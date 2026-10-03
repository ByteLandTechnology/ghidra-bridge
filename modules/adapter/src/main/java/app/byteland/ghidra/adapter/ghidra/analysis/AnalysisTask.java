package app.byteland.ghidra.adapter.ghidra.analysis;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.AutoAnalysisManagerListener;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;

final class AnalysisTask {
  private final String id = UUID.randomUUID().toString();
  private final BooleanSupplier analyzed;
  private final TaskBody body;
  private final AnalysisTaskMonitor monitor = new AnalysisTaskMonitor();
  private volatile AnalysisResource.Status status = AnalysisResource.Status.RUNNING;
  private final long startedAt = System.currentTimeMillis();
  private volatile Long completedAt;

  AnalysisTask(GhidraSession context, AutoAnalysisManager manager, AnalyzerSelection selection) {
    GhidraSession session = Objects.requireNonNull(context, "context");
    AutoAnalysisManager analysisManager = Objects.requireNonNull(manager, "manager");
    AnalyzerSelection analyzerSelection = Objects.requireNonNull(selection, "selection");
    Program program = session.currentProgram();
    this.analyzed = () -> GhidraProgramUtilities.isAnalyzed(program);
    this.body = () -> performAnalysis(session, analysisManager, program, analyzerSelection);
  }

  AnalysisTask(BooleanSupplier analyzed, Runnable operation) {
    this.analyzed = Objects.requireNonNull(analyzed, "analyzed");
    Objects.requireNonNull(operation, "operation");
    this.body =
        () -> {
          operation.run();
          return new TaskOutcome(AnalysisResource.Status.COMPLETED, null);
        };
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  void run() {
    TaskOutcome outcome;
    try {
      outcome = Objects.requireNonNull(body.run(), "analysis task outcome");
    } catch (RuntimeException failure) {
      outcome = new TaskOutcome(AnalysisResource.Status.FAILED, errorMessage(failure));
    }
    publish(outcome);
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private TaskOutcome performAnalysis(
      GhidraSession context,
      AutoAnalysisManager manager,
      Program program,
      AnalyzerSelection selection) {
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
      AnalysisOptionChange optionChange =
          prepareScriptAnalyzerSelection(context, manager, program, selection);
      if (optionChange != null) {
        previousAnalysisOptions = optionChange.previous();
        applyScriptAnalyzerSelection(context, program, optionChange.updates());
      }
      monitor.setIndeterminate(true);
      monitor.setMessage("Running analysis");
      manager.initializeOptions();
      manager.reAnalyzeAll(null);
      runAndWaitForAnalysis(manager);
      AnalysisManagerWait.awaitIdle(manager);
      if (monitor.isCancelled() || managerCancelled.get()) {
        terminalStatus = AnalysisResource.Status.CANCELLED;
        terminalError = "analysis cancelled";
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
    return new TaskOutcome(terminalStatus, terminalError);
  }

  boolean isRunning() {
    return status == AnalysisResource.Status.RUNNING;
  }

  /** Asks the analysis to stop. A running task then ends with the cancelled status. */
  void cancel() {
    monitor.cancel();
  }

  AnalysisResource snapshot() {
    return new AnalysisResource(
        AnalysisResource.Kind.BRIDGE,
        status,
        analyzed.getAsBoolean(),
        id,
        java.time.Instant.ofEpochMilli(startedAt),
        completedAt == null ? null : java.time.Instant.ofEpochMilli(completedAt),
        monitor.percent());
  }

  String message() {
    return monitor.getMessage();
  }

  private void publish(TaskOutcome outcome) {
    if (outcome.error() != null) {
      monitor.setMessage(outcome.error());
    } else if (outcome.status() == AnalysisResource.Status.COMPLETED) {
      monitor.setMessage("Analysis completed");
    }
    completedAt = System.currentTimeMillis();
    status = outcome.status();
  }

  private static AnalysisOptionChange prepareScriptAnalyzerSelection(
      GhidraSession context,
      AutoAnalysisManager manager,
      Program program,
      AnalyzerSelection selection) {
    if (!selection.hasSelection()) {
      return null;
    }

    Map<String, String> current = context.script().getCurrentAnalysisOptionsAndValues(program);
    Set<String> selected = new LinkedHashSet<>(selection.analyzers());
    for (String analyzer : selected) {
      if (manager.getAnalyzer(analyzer) == null) {
        throw new IllegalArgumentException("unknown analyzer: " + analyzer);
      }
    }

    Map<String, String> previous = new LinkedHashMap<>();
    Map<String, String> updates = new LinkedHashMap<>();
    for (Map.Entry<String, String> entry : current.entrySet()) {
      String value = entry.getValue();
      if (manager.getAnalyzer(entry.getKey()) == null || !isBooleanOption(value)) {
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

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
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

  private void runAndWaitForAnalysis(AutoAnalysisManager manager) {
    PluginTool tool = manager.getAnalysisTool();
    if (tool == null || tool.threadIsBackgroundTaskThread()) {
      manager.startAnalysis(monitor, true);
      return;
    }
    manager.waitForAnalysis(null, monitor);
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
