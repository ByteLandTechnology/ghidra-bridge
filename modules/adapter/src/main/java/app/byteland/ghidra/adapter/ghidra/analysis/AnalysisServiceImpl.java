package app.byteland.ghidra.adapter.ghidra.analysis;

import app.byteland.ghidra.ExecutorShutdown;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import app.byteland.ghidra.service.analysis.AnalysisService;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.AutoAnalysisManagerListener;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class AnalysisServiceImpl implements AnalysisService {
  private final GhidraSession context;
  private final Program program;
  private final AutoAnalysisManager manager;
  private final ExecutorService executor;
  private final Object lock = new Object();
  private final Runnable commitListener = this::refreshAnalyzed;
  private final DomainObjectListener domainObjectListener = this::onDomainObjectChanged;
  private final AutoAnalysisManagerListener managerListener =
      (ignored, cancelled) -> refreshAnalyzed();
  private volatile AnalysisTask currentTask;
  private volatile boolean analyzed;
  private volatile boolean closed;

  public AnalysisServiceImpl(GhidraSession context) {
    this.context = Objects.requireNonNull(context, "context");
    this.program = context.currentProgram();
    this.manager = AutoAnalysisManager.getAnalysisManager(program);
    this.executor = Executors.newSingleThreadExecutor(new AnalysisThreadFactory(program.getName()));
    this.program.addListener(domainObjectListener);
    this.manager.addListener(managerListener);
    this.context.addCommitListener(commitListener);
    refreshAnalyzed();
  }

  @Override
  public AnalysisResource startAnalysis(List<String> analyzers) {
    synchronized (lock) {
      boolean bridgeRunning = currentTask != null && currentTask.isRunning();
      switch (AnalysisStatusPolicy.start(closed, bridgeRunning, manager.isAnalyzing())) {
        case REJECT_CLOSED -> throw new IllegalStateException("analysis service is closed");
        case RETURN_BRIDGE -> {
          return currentTask.snapshot();
        }
        case RETURN_GHIDRA -> {
          return globalStatus(AnalysisResource.Status.RUNNING);
        }
        case START_BRIDGE -> {
          AnalyzerSelection selection = AnalyzerSelection.from(analyzers);
          AnalysisTask task =
              new AnalysisTask(
                  context, manager, selection, this::isAnalyzed, this::refreshAnalyzed);
          currentTask = task;
          executor.execute(task::run);
          return task.snapshot();
        }
      }
      throw new AssertionError("unreachable analysis start decision");
    }
  }

  @Override
  public AnalysisResource getStatus() {
    AnalysisTask task = currentTask;
    boolean bridgeRunning = task != null && task.isRunning();
    boolean ghidraRunning = manager.isAnalyzing();
    return switch (AnalysisStatusPolicy.status(
        task != null, bridgeRunning, ghidraRunning)) {
      case BRIDGE -> task.snapshot();
      case GHIDRA ->
          globalStatus(
              ghidraRunning ? AnalysisResource.Status.RUNNING : AnalysisResource.Status.IDLE);
    };
  }

  /**
   * Cancels the active analysis and waits until it stops.
   *
   * <p>The session ends when its connection closes or the host process stops. An
   * analysis can run for hours, so close must not wait for it to complete. The program keeps the
   * analysis results that exist when the analysis stops.
   */
  @Override
  public void close() {
    AnalysisTask task;
    synchronized (lock) {
      if (closed) {
        return;
      }
      closed = true;
      task = currentTask;
    }
    try {
      if (task != null) {
        task.cancel();
      }
      manager.cancelQueuedTasks();
      ExecutorShutdown.shutdownAndAwait(executor);
      AnalysisManagerWait.awaitIdle(manager);
    } finally {
      context.removeCommitListener(commitListener);
      manager.removeListener(managerListener);
      program.removeListener(domainObjectListener);
    }
  }

  private AnalysisResource globalStatus(AnalysisResource.Status state) {
    return new AnalysisResource(
        AnalysisResource.Kind.GHIDRA,
        state,
        analyzed,
        null,
        null,
        null,
        null);
  }

  private boolean isAnalyzed() {
    return analyzed;
  }

  private void onDomainObjectChanged(DomainObjectChangedEvent event) {
    if (event != null && event.contains(DomainObjectEvent.CLOSED)) {
      return;
    }
    refreshAnalyzed();
  }

  private void refreshAnalyzed() {
    if (closed || program.isClosed()) {
      return;
    }
    try {
      analyzed = GhidraProgramUtilities.isAnalyzed(program);
    } catch (RuntimeException ignored) {
      // Keep the last cached value if the program closes during refresh.
    }
  }
}
