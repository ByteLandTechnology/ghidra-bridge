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
  private final GhidraSession context;
  private final Program program;
  private final AutoAnalysisManager manager;
  private final ExecutorService executor;
  private final Object lock = new Object();
  private AnalysisTask currentTask;
  private boolean closed;

  public AnalysisServiceImpl(GhidraSession context) {
    this.context = Objects.requireNonNull(context, "context");
    this.program = context.currentProgram();
    this.manager = AutoAnalysisManager.getAnalysisManager(program);
    this.executor = Executors.newSingleThreadExecutor(new AnalysisThreadFactory(program.getName()));
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
          AnalysisTask task = new AnalysisTask(context, manager, selection);
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
      boolean ghidraRunning = manager.isAnalyzing();
      return switch (AnalysisStatusPolicy.status(
          currentTask != null, bridgeRunning, ghidraRunning)) {
        case BRIDGE -> currentTask.snapshot();
        case GHIDRA ->
            globalStatus(
                ghidraRunning ? AnalysisResource.Status.RUNNING : AnalysisResource.Status.IDLE);
      };
    }
  }

  @Override
  public void close() {
    synchronized (lock) {
      closed = true;
    }
    ExecutorShutdown.shutdownAndAwait(executor);
    AnalysisManagerWait.awaitIdle(manager);
  }

  private AnalysisResource globalStatus(AnalysisResource.Status state) {
    return new AnalysisResource(
        AnalysisResource.Kind.GHIDRA,
        state,
        GhidraProgramUtilities.isAnalyzed(program),
        null,
        null,
        null,
        null);
  }
}
