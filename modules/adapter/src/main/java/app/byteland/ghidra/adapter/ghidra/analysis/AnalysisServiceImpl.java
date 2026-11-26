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
import java.util.function.Function;
import java.util.function.Supplier;

public final class AnalysisServiceImpl implements AnalysisService {
  private final Supplier<Object> currentTarget;
  private final Function<Object, Backend> backendFactory;
  private final Function<Object, ExecutorService> executorFactory;
  private final Object lock = new Object();
  private final Map<Object, ProgramAnalysisState> states = new IdentityHashMap<>();
  private boolean closed;

  public AnalysisServiceImpl(GhidraSession context) {
    Objects.requireNonNull(context, "context");
    this.currentTarget = context::currentProgram;
    this.backendFactory =
        target -> {
          Program program = (Program) target;
          return new GhidraBackend(
              context, program, AutoAnalysisManager.getAnalysisManager(program));
        };
    this.executorFactory =
        target -> {
          Program program = (Program) target;
          return Executors.newSingleThreadExecutor(new AnalysisThreadFactory(program.getName()));
        };
  }

  AnalysisServiceImpl(Backend backend, ExecutorService executor) {
    Objects.requireNonNull(backend, "backend");
    Objects.requireNonNull(executor, "executor");
    Object singleTarget = new Object();
    this.currentTarget = () -> singleTarget;
    this.backendFactory = ignored -> backend;
    this.executorFactory = ignored -> executor;
    this.states.put(singleTarget, new ProgramAnalysisState(backend, executor));
  }

  AnalysisServiceImpl(
      Supplier<Object> currentTarget,
      Function<Object, Backend> backendFactory,
      Function<Object, ExecutorService> executorFactory) {
    this.currentTarget = Objects.requireNonNull(currentTarget, "currentTarget");
    this.backendFactory = Objects.requireNonNull(backendFactory, "backendFactory");
    this.executorFactory = Objects.requireNonNull(executorFactory, "executorFactory");
  }

  @Override
  public AnalysisResource startAnalysis(List<String> analyzers) {
    Object target = Objects.requireNonNull(currentTarget.get(), "target");
    synchronized (lock) {
      if (closed) {
        throw new IllegalStateException("analysis service is closed");
      }
      ProgramAnalysisState state = states.get(target);
      Backend backend = state != null ? state.backend : backendFactory.apply(target);
      boolean bridgeRunning =
          state != null && state.currentTask != null && state.currentTask.isRunning();
      switch (AnalysisStatusPolicy.start(false, bridgeRunning, backend.isAnalyzing())) {
        case REJECT_CLOSED -> throw new IllegalStateException("analysis service is closed");
        case RETURN_BRIDGE -> {
          return state.currentTask.snapshot();
        }
        case RETURN_GHIDRA -> {
          return globalStatus(backend, AnalysisResource.Status.RUNNING);
        }
        case START_BRIDGE -> {
          AnalysisTask task = backend.createTask(analyzers);
          if (state == null) {
            state = new ProgramAnalysisState(backend, executorFactory.apply(target));
            states.put(target, state);
          }
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
    Object target = Objects.requireNonNull(currentTarget.get(), "target");
    synchronized (lock) {
      ProgramAnalysisState state = states.get(target);
      Backend backend = state != null ? state.backend : backendFactory.apply(target);
      AnalysisTask currentTask = state != null ? state.currentTask : null;
      boolean bridgeRunning = currentTask != null && currentTask.isRunning();
      boolean ghidraRunning = backend.isAnalyzing();
      return switch (AnalysisStatusPolicy.status(
          currentTask != null, bridgeRunning, ghidraRunning)) {
        case BRIDGE -> currentTask.snapshot();
        case GHIDRA ->
            globalStatus(
                backend,
                ghidraRunning ? AnalysisResource.Status.RUNNING : AnalysisResource.Status.IDLE);
      };
    }
  }

  /** Cancels and releases background analysis resources for a closed program. */
  public void releaseProgram(Program program) {
    releaseTarget(program);
  }

  void releaseTarget(Object target) {
    if (target == null) {
      return;
    }
    ProgramAnalysisState state;
    synchronized (lock) {
      state = states.remove(target);
    }
    if (state != null) {
      stopState(state);
    }
  }

  /**
   * Cancels the active analysis and waits until it stops.
   *
   * <p>The session ends when its connection closes or the host process stops. An analysis can run
   * for hours, so close must not wait for it to complete. The program keeps the analysis results
   * that exist when the analysis stops.
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

  private static void stopState(ProgramAnalysisState state) {
    if (state.currentTask != null) {
      state.currentTask.cancel();
    }
    state.backend.cancelQueuedTasks();
    ExecutorShutdown.shutdownAndAwait(state.executor);
    state.backend.awaitIdle();
  }

  private static AnalysisResource globalStatus(Backend backend, AnalysisResource.Status state) {
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
          AnalysisTask.prepareAnalyzerSelection(manager, program, selection);
      return new AnalysisTask(context, program, manager, optionChange);
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

  private static final class ProgramAnalysisState {
    private final Backend backend;
    private final ExecutorService executor;
    private AnalysisTask currentTask;

    private ProgramAnalysisState(Backend backend, ExecutorService executor) {
      this.backend = backend;
      this.executor = executor;
    }
  }
}
