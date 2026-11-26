package app.byteland.ghidra.adapter.ghidra.analysis;

import app.byteland.ghidra.ExecutorShutdown;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import app.byteland.ghidra.service.analysis.AnalysisService;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Ghidra-backed implementation of {@link AnalysisService}.
 */
public final class AnalysisServiceImpl implements AnalysisService {
  private final GhidraSession context;
  private final Object lock = new Object();
  private final Map<Program, ProgramAnalysisState> states = new IdentityHashMap<>();
  private boolean closed;

  /**
   * Creates an analysis service bound to a Ghidra session.
   *
   * @param context active Ghidra session
   */
  public AnalysisServiceImpl(GhidraSession context) {
    this.context = Objects.requireNonNull(context, "context");
  }

  @Override
  public AnalysisResource startAnalysis(List<String> analyzers) {
    Program program = context.currentProgram();
    synchronized (lock) {
      if (closed) {
        throw new IllegalStateException("analysis service is closed");
      }
      ProgramAnalysisState state = stateFor(program);
      boolean bridgeRunning = state.currentTask != null && state.currentTask.isRunning();
      switch (AnalysisStatusPolicy.start(false, bridgeRunning, state.manager.isAnalyzing())) {
        case REJECT_CLOSED -> throw new IllegalStateException("analysis service is closed");
        case RETURN_BRIDGE -> {
          return state.currentTask.snapshot();
        }
        case RETURN_GHIDRA -> {
          return globalStatus(program, AnalysisResource.Status.RUNNING);
        }
        case START_BRIDGE -> {
          AnalyzerSelection selection = AnalyzerSelection.from(analyzers);
          AnalysisTask task = new AnalysisTask(context, program, state.manager, selection);
          state.executor.execute(task::run);
          state.currentTask = task;
          return state.currentTask.snapshot();
        }
      }
      throw new AssertionError("unreachable analysis start decision");
    }
  }

  @Override
  public AnalysisResource getStatus() {
    Program program = context.currentProgram();
    synchronized (lock) {
      ProgramAnalysisState state = states.get(program);
      AutoAnalysisManager manager =
          state != null ? state.manager : AutoAnalysisManager.getAnalysisManager(program);
      AnalysisTask currentTask = state != null ? state.currentTask : null;
      boolean bridgeRunning = currentTask != null && currentTask.isRunning();
      boolean ghidraRunning = manager.isAnalyzing();
      return switch (AnalysisStatusPolicy.status(
          currentTask != null, bridgeRunning, ghidraRunning)) {
        case BRIDGE -> currentTask.snapshot();
        case GHIDRA ->
            globalStatus(
                program,
                ghidraRunning ? AnalysisResource.Status.RUNNING : AnalysisResource.Status.IDLE);
      };
    }
  }

  /**
   * Cancels and releases background analysis resources for a closed program.
   *
   * @param program closed Ghidra program, or {@code null}
   */
  public void releaseProgram(Program program) {
    if (program == null) {
      return;
    }
    ProgramAnalysisState state;
    synchronized (lock) {
      state = states.remove(program);
    }
    if (state != null) {
      stopState(state);
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
    List<ProgramAnalysisState> activeStates;
    synchronized (lock) {
      closed = true;
      activeStates = List.copyOf(states.values());
      states.clear();
    }
    for (ProgramAnalysisState state : activeStates) {
      stopState(state);
    }
  }

  private ProgramAnalysisState stateFor(Program program) {
    return states.computeIfAbsent(program, ProgramAnalysisState::new);
  }

  private static void stopState(ProgramAnalysisState state) {
    if (state.currentTask != null) {
      state.currentTask.cancel();
    }
    state.manager.cancelQueuedTasks();
    ExecutorShutdown.shutdownAndAwait(state.executor);
    AnalysisManagerWait.awaitIdle(state.manager);
  }

  private static AnalysisResource globalStatus(Program program, AnalysisResource.Status state) {
    return new AnalysisResource(
        AnalysisResource.Kind.GHIDRA,
        state,
        GhidraProgramUtilities.isAnalyzed(program),
        null,
        null,
        null,
        null);
  }

  private static final class ProgramAnalysisState {
    private final AutoAnalysisManager manager;
    private final ExecutorService executor;
    private AnalysisTask currentTask;

    private ProgramAnalysisState(Program program) {
      this.manager = AutoAnalysisManager.getAnalysisManager(program);
      this.executor =
          Executors.newSingleThreadExecutor(new AnalysisThreadFactory(program.getName()));
    }
  }
}
