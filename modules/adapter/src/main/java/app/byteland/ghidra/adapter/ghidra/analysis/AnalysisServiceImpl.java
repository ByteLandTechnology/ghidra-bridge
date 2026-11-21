package app.byteland.ghidra.adapter.ghidra.analysis;

import app.byteland.ghidra.ExecutorShutdown;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import app.byteland.ghidra.service.analysis.AnalysisService;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class AnalysisServiceImpl implements AnalysisService {
  private final Backend backend;
  private final ExecutorService executor;
  private final Object lock = new Object();
  private AnalysisTask currentTask;
  private boolean closed;

  public AnalysisServiceImpl(GhidraSession context) {
    Objects.requireNonNull(context, "context");
    Program program = context.currentProgram();
    AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(program);
    this.backend = new GhidraBackend(context, program, manager);
    this.executor = Executors.newSingleThreadExecutor(new AnalysisThreadFactory(program.getName()));
  }

  AnalysisServiceImpl(Backend backend, ExecutorService executor) {
    this.backend = Objects.requireNonNull(backend, "backend");
    this.executor = Objects.requireNonNull(executor, "executor");
  }

  @Override
  public AnalysisResource startAnalysis(List<String> analyzers) {
    synchronized (lock) {
      boolean bridgeRunning = currentTask != null && currentTask.isRunning();
      switch (AnalysisStatusPolicy.start(closed, bridgeRunning, backend.isAnalyzing())) {
        case REJECT_CLOSED -> throw new IllegalStateException("analysis service is closed");
        case RETURN_BRIDGE -> {
          return currentTask.snapshot();
        }
        case RETURN_GHIDRA -> {
          return globalStatus(AnalysisResource.Status.RUNNING);
        }
        case START_BRIDGE -> {
          AnalysisTask task = backend.createTask(analyzers);
          executor.execute(task::run);
          currentTask = task;
          return currentTask.snapshot();
        }
      }
      throw new AssertionError("unreachable analysis start decision");
    }
  }

  @Override
  public AnalysisResource getStatus() {
    synchronized (lock) {
      boolean bridgeRunning = currentTask != null && currentTask.isRunning();
      boolean ghidraRunning = backend.isAnalyzing();
      return switch (AnalysisStatusPolicy.status(
          currentTask != null, bridgeRunning, ghidraRunning)) {
        case BRIDGE -> currentTask.snapshot();
        case GHIDRA ->
            globalStatus(
                ghidraRunning ? AnalysisResource.Status.RUNNING : AnalysisResource.Status.IDLE);
      };
    }
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
      closed = true;
      task = currentTask;
    }
    if (task != null) {
      task.cancel();
    }
    backend.cancelQueuedTasks();
    ExecutorShutdown.shutdownAndAwait(executor);
    backend.awaitIdle();
  }

  private AnalysisResource globalStatus(AnalysisResource.Status state) {
    return new AnalysisResource(
        AnalysisResource.Kind.GHIDRA,
        state,
        backend.isAnalyzed(),
        null,
        null,
        null,
        null,
        null,
        null);
  }

  interface Backend {
    boolean isAnalyzing();

    AnalysisTask createTask(List<String> analyzers);

    boolean isAnalyzed();

    void cancelQueuedTasks();

    void awaitIdle();
  }

  private record GhidraBackend(
      GhidraSession context, Program program, AutoAnalysisManager manager) implements Backend {
    @Override
    public boolean isAnalyzing() {
      return manager.isAnalyzing();
    }

    @Override
    public AnalysisTask createTask(List<String> analyzers) {
      AnalyzerSelection selection = AnalyzerSelection.from(analyzers);
      AnalysisTask.AnalysisOptionChange optionChange =
          AnalysisTask.prepareScriptAnalyzerSelection(context, manager, program, selection);
      return new AnalysisTask(context, manager, optionChange);
    }

    @Override
    public boolean isAnalyzed() {
      return GhidraProgramUtilities.isAnalyzed(program);
    }

    @Override
    public void cancelQueuedTasks() {
      manager.cancelQueuedTasks();
    }

    @Override
    public void awaitIdle() {
      AnalysisManagerWait.awaitIdle(manager);
    }
  }
}
