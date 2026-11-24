package app.byteland.ghidra.adapter.ghidra.analysis;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.AutoAnalysisManagerListener;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
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
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
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

  AnalysisTask(BooleanSupplier analyzed, Runnable operation) {
    this(
        analyzed,
        ignored -> {
          Objects.requireNonNull(operation, "operation").run();
        });
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
    }
    publish(outcome);
  }

  private TaskOutcome performAnalysis(
      GhidraSession context,
      AutoAnalysisManager manager,
      Program program,
      AnalysisOptionChange optionChange) {
    Map<String, String> previousAnalysisOptions = null;
    AnalysisResource.Status terminalStatus;
    String terminalError = null;
    AtomicBoolean managerCancelled = new AtomicBoolean(false);
    AutoAnalysisManagerListener listener =
        (ignored, cancelled) -> managerCancelled.compareAndSet(false, cancelled);
    boolean listenerRegistered = false;
    try {
      manager.addListener(listener);
      listenerRegistered = true;
      monitor.setMessage("Initializing analysis");
      if (manager.isAnalyzing()) {
        throw new IllegalStateException(
            "Ghidra analysis started before the bridge task acquired the analysis manager");
      }
      if (optionChange != null) {
        previousAnalysisOptions = optionChange.previous();
        applyScriptAnalyzerSelection(context, program, optionChange.updates());
      }
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
    monitor.cancel();
  }

  AnalysisTaskMonitor monitor() {
    return monitor;
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

  String message() {
    return normalizeMessage(monitor.getMessage());
  }

  String error() {
    return error;
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
      context.script().setAnalysisOptions(program, updates);
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
      context.script().setAnalysisOptions(program, previousAnalysisOptions);
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

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  void runAnalysis(PluginTool tool, Program program, Consumer<TaskMonitor> execution) {
    Objects.requireNonNull(execution, "execution");
    if (tool == null || tool.threadIsBackgroundTaskThread()) {
      execution.accept(monitor);
      return;
    }
    CountDownLatch completed = new CountDownLatch(1);
    AtomicBoolean started = new AtomicBoolean();
    AtomicReference<RuntimeException> commandFailure = new AtomicReference<>();
    BackgroundCommand<Program> command =
        new BackgroundCommand<>("Auto Analysis", true, true, false) {
          @Override
          public boolean applyTo(Program targetProgram, TaskMonitor toolMonitor) {
            boolean finishedNormally = false;
            started.set(true);
            try (AnalysisTaskMonitor.BridgedMonitor bridged = monitor.bridge(toolMonitor)) {
              if (!bridged.isCancelled()) {
                execution.accept(bridged);
              }
              finishedNormally = true;
              return true;
            } catch (RuntimeException failure) {
              commandFailure.set(failure);
              finishedNormally = true;
              return true;
            } finally {
              if (!finishedNormally) {
                completed.countDown();
              }
            }
          }

          @Override
          public void taskCompleted() {
            if (!started.get()) {
              monitor.cancel();
            }
            completed.countDown();
          }

          @Override
          public void dispose() {
            if (!started.get()) {
              monitor.cancel();
            }
            completed.countDown();
          }
        };
    tool.executeBackgroundCommand(command, program);
    try {
      completed.await();
    } catch (InterruptedException interrupted) {
      monitor.cancel();
      Thread.currentThread().interrupt();
      return;
    }
    RuntimeException failure = commandFailure.get();
    if (failure != null) {
      throw failure;
    }
  }

  private static String normalizeMessage(String value) {
    return value == null || value.isBlank() ? null : value;
  }

  private static boolean isBooleanOption(String value) {
    return "true".equalsIgnoreCase(value) || "false".equalsIgnoreCase(value);
  }

  private static String errorMessage(RuntimeException failure) {
    String message = failure.getMessage();
    return message == null || message.isBlank() ? failure.toString() : message;
  }

  private static String appendError(String current, String additional) {
    return current == null || current.isBlank() ? additional : current + "; " + additional;
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
