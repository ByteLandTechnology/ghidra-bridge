package app.byteland.ghidra.adapter.ghidra.analysis;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.AutoAnalysisManagerListener;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObjectClosedListener;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Predicate;

final class AnalysisTask {
  private final String id = UUID.randomUUID().toString();
  private final BooleanSupplier analyzed;
  private final TaskBody body;
  private final AnalysisTaskMonitor monitor = new AnalysisTaskMonitor();
  private volatile AnalysisResource.Status status = AnalysisResource.Status.RUNNING;
  private final long startedAt = System.currentTimeMillis();
  private volatile Long completedAt;
  private volatile String error;

  AnalysisTask(
      GhidraSession context, AutoAnalysisManager manager, AnalysisOptionChange optionChange) {
    GhidraSession session = Objects.requireNonNull(context, "context");
    AutoAnalysisManager analysisManager = Objects.requireNonNull(manager, "manager");
    Program program = session.currentProgram();
    this.analyzed = () -> GhidraProgramUtilities.isAnalyzed(program);
    this.body = () -> performAnalysis(session, analysisManager, program, optionChange);
  }

  AnalysisTask(BooleanSupplier analyzed, Consumer<AnalysisTaskMonitor> operation) {
    this.analyzed = Objects.requireNonNull(analyzed, "analyzed");
    Objects.requireNonNull(operation, "operation");
    this.body =
        () -> {
          operation.accept(monitor);
          if (monitor.isCancelled()) {
            return new TaskOutcome(AnalysisResource.Status.CANCELLED, null);
          }
          return new TaskOutcome(AnalysisResource.Status.COMPLETED, null);
        };
  }

  void run() {
    TaskOutcome outcome;
    try {
      outcome = Objects.requireNonNull(body.run(), "analysis task outcome");
    } catch (RuntimeException failure) {
      outcome = new TaskOutcome(AnalysisResource.Status.FAILED, errorMessage(failure));
    } catch (Error fatal) {
      publish(new TaskOutcome(AnalysisResource.Status.FAILED, errorMessage(fatal)));
      throw fatal;
    }
    publish(outcome);
  }

  private TaskOutcome performAnalysis(
      GhidraSession context,
      AutoAnalysisManager manager,
      Program program,
      AnalysisOptionChange optionChange) {
    Map<String, String> previousAnalysisOptions = null;
    AnalysisResource.Status terminalStatus = AnalysisResource.Status.FAILED;
    String terminalError = null;
    AtomicBoolean managerCancelled = new AtomicBoolean(false);
    AutoAnalysisManagerListener listener =
        (ignored, cancelled) -> managerCancelled.compareAndSet(false, cancelled);
    boolean listenerRegistered = false;
    try {
      manager.addListener(listener);
      listenerRegistered = true;
      monitor.setMessage("Initializing analysis");
      if (monitor.isCancelled()) {
        terminalStatus = AnalysisResource.Status.CANCELLED;
        return new TaskOutcome(terminalStatus, null);
      }
      if (manager.isAnalyzing()) {
        throw new IllegalStateException(
            "Ghidra analysis started before the bridge task acquired the analysis manager");
      }
      if (optionChange != null) {
        previousAnalysisOptions = optionChange.previous();
        applyScriptAnalyzerSelection(context, program, optionChange.updates());
      }
      if (monitor.isCancelled()) {
        terminalStatus = AnalysisResource.Status.CANCELLED;
      } else {
        monitor.setIndeterminate(true);
        monitor.setMessage("Running analysis");
        manager.initializeOptions();
        runAnalysis(manager, program);
        AnalysisManagerWait.awaitIdle(manager);
        if (monitor.isCancelled() || managerCancelled.get()) {
          terminalStatus = AnalysisResource.Status.CANCELLED;
        } else {
          terminalStatus = AnalysisResource.Status.COMPLETED;
        }
      }
    } catch (RuntimeException failure) {
      terminalStatus = AnalysisResource.Status.FAILED;
      terminalError = errorMessage(failure);
    } finally {
      if (listenerRegistered) {
        try {
          manager.removeListener(listener);
        } catch (RuntimeException cleanupFailure) {
          terminalStatus = AnalysisResource.Status.FAILED;
          terminalError = appendError(terminalError, errorMessage(cleanupFailure));
        }
      }
      String restoreError =
          restoreScriptAnalyzerSelection(context, manager, program, previousAnalysisOptions);
      if (restoreError != null) {
        terminalStatus = AnalysisResource.Status.FAILED;
        terminalError = appendError(terminalError, restoreError);
      }
    }
    if (terminalStatus == AnalysisResource.Status.COMPLETED) {
      if (monitor.isCancelled()) {
        return new TaskOutcome(AnalysisResource.Status.CANCELLED, null);
      }
      try {
        context.withTransaction(
            () -> {
              GhidraProgramUtilities.markProgramAnalyzed(program);
              return null;
            });
      } catch (RuntimeException markFailure) {
        return new TaskOutcome(AnalysisResource.Status.FAILED, errorMessage(markFailure));
      }
    }
    return new TaskOutcome(terminalStatus, terminalError);
  }

  boolean isRunning() {
    return status == AnalysisResource.Status.RUNNING;
  }

  /** Asks the analysis to stop. An active task then ends with the cancelled status. */
  void cancel() {
    monitor.requestCancel();
  }

  AnalysisResource snapshot() {
    AnalysisResource.Status currentStatus = status;
    boolean terminal = currentStatus != AnalysisResource.Status.RUNNING;
    Long finished = terminal ? completedAt : null;
    String currentError = currentStatus == AnalysisResource.Status.FAILED ? error : null;
    return new AnalysisResource(
        AnalysisResource.Kind.BRIDGE,
        currentStatus,
        analyzed.getAsBoolean(),
        id,
        Instant.ofEpochMilli(startedAt),
        finished == null ? null : Instant.ofEpochMilli(finished),
        monitor.percent(),
        message(),
        currentError);
  }

  private String message() {
    return normalizeMessage(monitor.getMessage());
  }

  private void publish(TaskOutcome outcome) {
    if (outcome.status() == AnalysisResource.Status.COMPLETED) {
      monitor.setMessage("Analysis completed");
    } else if (outcome.status() == AnalysisResource.Status.CANCELLED) {
      monitor.setMessage("Analysis cancelled");
    }
    error =
        outcome.status() == AnalysisResource.Status.FAILED
            ? normalizeMessage(outcome.error())
            : null;
    completedAt = System.currentTimeMillis();
    status = outcome.status();
  }

  static AnalysisOptionChange prepareScriptAnalyzerSelection(
      GhidraSession context,
      AutoAnalysisManager manager,
      Program program,
      AnalyzerSelection selection) {
    Objects.requireNonNull(selection, "selection");
    if (!selection.hasSelection()) {
      return null;
    }
    return prepareScriptAnalyzerSelection(
        context.script().getCurrentAnalysisOptionsAndValues(program),
        analyzer -> manager.getAnalyzer(analyzer) != null,
        selection);
  }

  static AnalysisOptionChange prepareScriptAnalyzerSelection(
      Map<String, String> currentOptions,
      Predicate<String> analyzerExists,
      AnalyzerSelection selection) {
    Objects.requireNonNull(selection, "selection");
    if (!selection.hasSelection()) {
      return null;
    }
    Objects.requireNonNull(currentOptions, "currentOptions");
    Objects.requireNonNull(analyzerExists, "analyzerExists");

    Set<String> selected = new LinkedHashSet<>(selection.analyzers());
    for (String analyzer : selected) {
      if (!analyzerExists.test(analyzer)) {
        throw new IllegalArgumentException("unknown analyzer: " + analyzer);
      }
    }

    Map<String, String> previous = new LinkedHashMap<>();
    Map<String, String> updates = new LinkedHashMap<>();
    for (Map.Entry<String, String> entry : currentOptions.entrySet()) {
      String value = entry.getValue();
      if (!analyzerExists.test(entry.getKey()) || !isBooleanOption(value)) {
        continue;
      }
      previous.put(entry.getKey(), value);
      updates.put(entry.getKey(), Boolean.toString(selected.contains(entry.getKey())));
    }

    for (String analyzer : selected) {
      if (!updates.containsKey(analyzer)) {
        throw new IllegalArgumentException("analyzer option is unavailable: " + analyzer);
      }
    }

    return new AnalysisOptionChange(previous, updates);
  }

  private static void applyScriptAnalyzerSelection(
      GhidraSession context, Program program, Map<String, String> updates) {
    if (!updates.isEmpty()) {
      context.withTransaction(
          () -> {
            context.script().setAnalysisOptions(program, updates);
            return null;
          });
    }
  }

  private static String restoreScriptAnalyzerSelection(
      GhidraSession context,
      AutoAnalysisManager manager,
      Program program,
      Map<String, String> previousAnalysisOptions) {
    if (previousAnalysisOptions == null || previousAnalysisOptions.isEmpty()) {
      return null;
    }
    try {
      context.withTransaction(
          () -> {
            context.script().setAnalysisOptions(program, previousAnalysisOptions);
            return null;
          });
      manager.initializeOptions();
      return null;
    } catch (RuntimeException ex) {
      return "Unable to restore analysis options: " + errorMessage(ex);
    }
  }

  private void runAnalysis(AutoAnalysisManager manager, Program program) {
    runAnalysis(
        manager.getAnalysisTool(),
        program,
        activeMonitor -> {
          manager.reAnalyzeAll(null);
          manager.startAnalysis(activeMonitor, true);
        });
  }

  void runAnalysis(PluginTool tool, Program program, Consumer<TaskMonitor> execution) {
    Objects.requireNonNull(execution, "execution");
    if (monitor.isCancelled()) {
      return;
    }
    if (tool == null || tool.threadIsBackgroundTaskThread()) {
      execution.accept(monitor);
      return;
    }
    if (program != null && program.isClosed()) {
      monitor.requestCancel();
      return;
    }

    GuiAnalysisCommand command = new GuiAnalysisCommand(monitor, execution);
    CancelledListener monitorListener = command::onMonitorCancelled;
    DomainObjectClosedListener closeListener =
        program == null ? null : ignored -> command.onProgramClosed();
    monitor.addCancelledListener(monitorListener);
    if (closeListener != null) {
      program.addCloseListener(closeListener);
    }
    try {
      if (monitor.isCancelled()) {
        command.onMonitorCancelled();
        return;
      }
      if (program != null && program.isClosed()) {
        command.onProgramClosed();
        return;
      }
      tool.executeBackgroundCommand(command, program);
      command.awaitCompletion(tool, program);
    } catch (InterruptedException interrupted) {
      command.onCallerInterrupted();
      Thread.currentThread().interrupt();
      return;
    } finally {
      monitor.removeCancelledListener(monitorListener);
      if (closeListener != null) {
        program.removeCloseListener(closeListener);
      }
    }
    command.rethrowIfFailed();
  }

  private static Boolean toolExecutingCommandOrNull(PluginTool tool) {
    try {
      return tool.isExecutingCommand();
    } catch (NullPointerException uninitializedTool) {
      return null;
    }
  }

  private static String normalizeMessage(String value) {
    return value == null || value.isBlank() ? null : value;
  }

  private static boolean isBooleanOption(String value) {
    return "true".equalsIgnoreCase(value) || "false".equalsIgnoreCase(value);
  }

  private static String errorMessage(Throwable failure) {
    String message = failure.getMessage();
    return message == null || message.isBlank() ? failure.toString() : message;
  }

  private static String appendError(String current, String additional) {
    return current == null || current.isBlank() ? additional : current + "; " + additional;
  }

  private static final class GuiAnalysisCommand extends BackgroundCommand<Program> {
    private static final long QUEUE_POLL_MILLIS = 25L;

    private enum Phase {
      QUEUED,
      RUNNING,
      AWAITING_TASK_COMPLETED,
      ABORTED_BEFORE_START,
      DONE
    }

    private final AnalysisTaskMonitor monitor;
    private final Consumer<TaskMonitor> execution;
    private final CountDownLatch completed = new CountDownLatch(1);
    private final Object lock = new Object();
    private Phase phase = Phase.QUEUED;
    private boolean taskCompletedWhileRunning;
    private Throwable failure;

    private GuiAnalysisCommand(AnalysisTaskMonitor monitor, Consumer<TaskMonitor> execution) {
      super("Auto Analysis", true, true, false);
      this.monitor = monitor;
      this.execution = execution;
    }

    @Override
    public boolean applyTo(Program targetProgram, TaskMonitor toolMonitor) {
      boolean abortBeforeStart = false;
      synchronized (lock) {
        if (phase != Phase.QUEUED) {
          return false;
        }
        if (monitor.isCancelled() || (targetProgram != null && targetProgram.isClosed())) {
          phase = Phase.ABORTED_BEFORE_START;
          abortBeforeStart = true;
        } else {
          phase = Phase.RUNNING;
        }
      }
      if (abortBeforeStart) {
        monitor.requestCancel();
        completed.countDown();
        return false;
      }

      boolean handoffToTaskCompleted = false;
      try (AnalysisTaskMonitor.BridgedMonitor bridged = monitor.bridge(toolMonitor)) {
        if (!bridged.isCancelled()) {
          execution.accept(bridged);
        }
        handoffToTaskCompleted = true;
        return true;
      } catch (RuntimeException | Error ex) {
        synchronized (lock) {
          failure = ex;
        }
        handoffToTaskCompleted = true;
        return true;
      } finally {
        boolean releaseNow;
        synchronized (lock) {
          if (handoffToTaskCompleted && !taskCompletedWhileRunning) {
            phase = Phase.AWAITING_TASK_COMPLETED;
            releaseNow = false;
          } else {
            phase = Phase.DONE;
            releaseNow = true;
          }
        }
        if (releaseNow) {
          completed.countDown();
        }
      }
    }

    @Override
    public void taskCompleted() {
      boolean cancelMonitor = false;
      boolean releaseNow = false;
      synchronized (lock) {
        switch (phase) {
          case QUEUED -> {
            phase = Phase.ABORTED_BEFORE_START;
            cancelMonitor = true;
            releaseNow = true;
          }
          case RUNNING -> {
            taskCompletedWhileRunning = true;
            cancelMonitor = true;
          }
          case AWAITING_TASK_COMPLETED -> {
            phase = Phase.DONE;
            releaseNow = true;
          }
          case ABORTED_BEFORE_START, DONE -> releaseNow = true;
        }
      }
      if (cancelMonitor) {
        monitor.requestCancel();
      }
      if (releaseNow) {
        completed.countDown();
      }
    }

    @Override
    public void dispose() {
      boolean releaseNow = false;
      synchronized (lock) {
        switch (phase) {
          case QUEUED -> {
            phase = Phase.ABORTED_BEFORE_START;
            releaseNow = true;
          }
          case RUNNING -> {
            // Wait until applyTo finishes so cleanup does not run concurrently with analysis.
          }
          case AWAITING_TASK_COMPLETED -> {
            phase = Phase.DONE;
            releaseNow = true;
          }
          case ABORTED_BEFORE_START, DONE -> releaseNow = true;
        }
      }
      monitor.requestCancel();
      if (releaseNow) {
        completed.countDown();
      }
    }

    private void onMonitorCancelled() {
      boolean releaseNow = false;
      synchronized (lock) {
        if (phase == Phase.QUEUED) {
          phase = Phase.ABORTED_BEFORE_START;
          releaseNow = true;
        }
      }
      if (releaseNow) {
        completed.countDown();
      }
    }

    private void onProgramClosed() {
      boolean releaseNow = false;
      synchronized (lock) {
        if (phase == Phase.QUEUED) {
          phase = Phase.ABORTED_BEFORE_START;
          releaseNow = true;
        } else if (phase == Phase.AWAITING_TASK_COMPLETED) {
          phase = Phase.DONE;
          releaseNow = true;
        }
      }
      monitor.requestCancel();
      if (releaseNow) {
        completed.countDown();
      }
    }

    private void onToolIdle() {
      boolean cancelMonitor = false;
      boolean releaseNow = false;
      synchronized (lock) {
        if (phase == Phase.QUEUED) {
          phase = Phase.ABORTED_BEFORE_START;
          cancelMonitor = true;
          releaseNow = true;
        } else if (phase == Phase.AWAITING_TASK_COMPLETED) {
          phase = Phase.DONE;
          releaseNow = true;
        }
      }
      if (cancelMonitor) {
        monitor.requestCancel();
      }
      if (releaseNow) {
        completed.countDown();
      }
    }

    private void onCallerInterrupted() {
      monitor.requestCancel();
      onMonitorCancelled();
    }

    private void awaitCompletion(PluginTool tool, Program program) throws InterruptedException {
      while (!completed.await(QUEUE_POLL_MILLIS, TimeUnit.MILLISECONDS)) {
        if (program != null && program.isClosed()) {
          onProgramClosed();
          if (completed.getCount() == 0) {
            return;
          }
        }
        if (Boolean.FALSE.equals(toolExecutingCommandOrNull(tool))) {
          onToolIdle();
          if (completed.getCount() == 0) {
            return;
          }
        }
      }
    }

    private void rethrowIfFailed() {
      Throwable recordedFailure;
      synchronized (lock) {
        recordedFailure = failure;
      }
      if (recordedFailure instanceof RuntimeException runtimeException) {
        throw runtimeException;
      }
      if (recordedFailure instanceof Error fatalError) {
        throw fatalError;
      }
    }
  }

  record AnalysisOptionChange(Map<String, String> previous, Map<String, String> updates) {
    AnalysisOptionChange {
      previous = immutableCopy(previous);
      updates = immutableCopy(updates);
    }

    private static Map<String, String> immutableCopy(Map<String, String> values) {
      return Collections.unmodifiableMap(new LinkedHashMap<>(values));
    }
  }

  @FunctionalInterface
  private interface TaskBody {
    TaskOutcome run();
  }

  private record TaskOutcome(AnalysisResource.Status status, String error) {}
}
