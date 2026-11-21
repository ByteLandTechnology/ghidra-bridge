package app.byteland.ghidra.adapter.ghidra.analysis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.api.ApiFailures;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiConsumer;
import org.junit.jupiter.api.Test;

class AnalysisTelemetryAndValidationTest {
  @Test
  void exposesPhaseMessagesNormalizesBlanksAndSeparatesTerminalErrors() throws Exception {
    CountDownLatch phaseReady = new CountDownLatch(1);
    CountDownLatch releaseBlankCheck = new CountDownLatch(1);
    CountDownLatch blankReady = new CountDownLatch(1);
    CountDownLatch releaseFinish = new CountDownLatch(1);

    AnalysisTask task =
        new AnalysisTask(
            () -> true,
            monitor -> {
              monitor.initialize(200);
              monitor.setProgress(50);
              monitor.setMessage("Decompiler Parameter ID");
              phaseReady.countDown();
              awaitLatch(releaseBlankCheck);
              monitor.setMessage("   \t\n  ");
              blankReady.countDown();
              awaitLatch(releaseFinish);
              monitor.setMessage("Finalizing");
            });

    AnalysisResource initial = task.snapshot();
    assertEquals(AnalysisResource.Status.RUNNING, initial.status());
    assertEquals("Analysis queued", initial.message());
    assertNull(initial.error());

    ExecutorService worker = Executors.newSingleThreadExecutor();
    try {
      Future<?> runFuture = worker.submit(task::run);

      assertTrue(phaseReady.await(5, TimeUnit.SECONDS));
      AnalysisResource midRun = task.snapshot();
      assertEquals(AnalysisResource.Status.RUNNING, midRun.status());
      assertEquals(25.0, midRun.progress());
      assertEquals("Decompiler Parameter ID", midRun.message());
      assertNull(midRun.error());

      releaseBlankCheck.countDown();
      assertTrue(blankReady.await(5, TimeUnit.SECONDS));
      AnalysisResource blankMessage = task.snapshot();
      assertNull(blankMessage.message());
      assertNull(blankMessage.error());

      releaseFinish.countDown();
      runFuture.get(5, TimeUnit.SECONDS);

      AnalysisResource completed = task.snapshot();
      assertEquals(AnalysisResource.Status.COMPLETED, completed.status());
      assertEquals("Analysis completed", completed.message());
      assertNull(completed.error());
      assertNotNull(completed.finishedAt());
    } finally {
      worker.shutdownNow();
    }

    AnalysisTask failingTask =
        new AnalysisTask(
            () -> false,
            monitor -> {
              monitor.setMessage("Decompiler Parameter ID");
              throw new IllegalStateException("decompiler crashed");
            });
    failingTask.run();

    AnalysisResource failed = failingTask.snapshot();
    assertEquals(AnalysisResource.Status.FAILED, failed.status());
    assertEquals("Decompiler Parameter ID", failed.message());
    assertEquals("decompiler crashed", failed.error());
  }

  @Test
  void keepsErrorNullWhenTaskIsCancelled() {
    AnalysisTask cancelledTask = new AnalysisTask(() -> false, AnalysisTaskMonitor::cancel);
    cancelledTask.run();

    AnalysisResource snapshot = cancelledTask.snapshot();
    assertEquals(AnalysisResource.Status.CANCELLED, snapshot.status());
    assertEquals("Analysis cancelled", snapshot.message());
    assertNull(snapshot.error());
  }

  @Test
  void validatesAnalyzersAndBuildsBooleanOptionChanges() {
    assertFalse(AnalyzerSelection.from(null).hasSelection());
    assertNull(
        AnalysisTask.prepareScriptAnalyzerSelection(
            Map.of(), ignored -> true, AnalyzerSelection.from(null)));

    assertThrows(IllegalArgumentException.class, () -> AnalyzerSelection.from(List.of()));
    assertThrows(IllegalArgumentException.class, () -> AnalyzerSelection.from(List.of("   ")));

    Map<String, String> options = new LinkedHashMap<>();
    options.put("ASCII Strings", "true");
    options.put("ASCII Strings.Minimum Length", "5");
    options.put("Stack", "true");
    options.put("NonBooleanAnalyzer", "custom-mode");
    Set<String> registeredAnalyzers = Set.of("ASCII Strings", "Stack", "NonBooleanAnalyzer");

    IllegalArgumentException unknown =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                AnalysisTask.prepareScriptAnalyzerSelection(
                    options,
                    registeredAnalyzers::contains,
                    AnalyzerSelection.from(List.of("NoSuchAnalyzer"))));
    assertEquals("unknown analyzer: NoSuchAnalyzer", unknown.getMessage());

    IllegalArgumentException unavailable =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                AnalysisTask.prepareScriptAnalyzerSelection(
                    options,
                    registeredAnalyzers::contains,
                    AnalyzerSelection.from(List.of("NonBooleanAnalyzer"))));
    assertEquals("analyzer option is unavailable: NonBooleanAnalyzer", unavailable.getMessage());

    AnalysisTask.AnalysisOptionChange change =
        AnalysisTask.prepareScriptAnalyzerSelection(
            options,
            registeredAnalyzers::contains,
            AnalyzerSelection.from(List.of("ASCII Strings")));
    assertNotNull(change);
    assertEquals(Map.of("ASCII Strings", "true", "Stack", "true"), change.previous());
    assertEquals(Map.of("ASCII Strings", "true", "Stack", "false"), change.updates());
  }

  @Test
  void rejectsInvalidAnalyzersBeforeMutatingCurrentTaskOrQueuingWork() {
    AtomicInteger queuedRuns = new AtomicInteger();
    AtomicBoolean ghidraAnalyzing = new AtomicBoolean(false);
    AtomicBoolean failNextRun = new AtomicBoolean(false);
    Set<String> validAnalyzers = Set.of("ASCII Strings", "Decompiler Parameter ID");
    Map<String, String> currentOptions =
        Map.of("ASCII Strings", "true", "Decompiler Parameter ID", "false");

    AnalysisServiceImpl.Backend backend =
        new AnalysisServiceImpl.Backend() {
          @Override
          public boolean isAnalyzing() {
            return ghidraAnalyzing.get();
          }

          @Override
          public AnalysisTask createTask(List<String> analyzers) {
            AnalyzerSelection selection = AnalyzerSelection.from(analyzers);
            AnalysisTask.prepareScriptAnalyzerSelection(
                currentOptions, validAnalyzers::contains, selection);
            return new AnalysisTask(
                () -> true,
                monitor -> {
                  monitor.setMessage("ASCII Strings");
                  if (failNextRun.get()) {
                    throw new IllegalStateException("corrupt block");
                  }
                });
          }

          @Override
          public boolean isAnalyzed() {
            return false;
          }

          @Override
          public void cancelQueuedTasks() {}

          @Override
          public void awaitIdle() {}
        };

    ExecutorService directExecutor =
        new DirectExecutorService(() -> queuedRuns.incrementAndGet());
    try (AnalysisServiceImpl service = new AnalysisServiceImpl(backend, directExecutor)) {
      IllegalArgumentException initialError =
          assertThrows(
              IllegalArgumentException.class,
              () -> service.startAnalysis(List.of("NoSuchAnalyzer")));
      ApiFailures.Failure failure = ApiFailures.normalize(initialError);
      assertEquals(400, failure.status());
      assertEquals("invalid_request", failure.error().code());
      assertEquals(0, queuedRuns.get());

      AnalysisResource idle = service.getStatus();
      assertEquals(AnalysisResource.Kind.GHIDRA, idle.kind());
      assertEquals(AnalysisResource.Status.IDLE, idle.status());
      assertNull(idle.message());
      assertNull(idle.error());

      AnalysisResource completed = service.startAnalysis(List.of("ASCII Strings"));
      assertEquals(1, queuedRuns.get());
      assertEquals(AnalysisResource.Kind.BRIDGE, completed.kind());
      assertEquals(AnalysisResource.Status.COMPLETED, completed.status());
      assertEquals("Analysis completed", completed.message());
      assertNull(completed.error());

      assertThrows(
          IllegalArgumentException.class,
          () -> service.startAnalysis(List.of("NoSuchAnalyzer")));
      assertEquals(1, queuedRuns.get());

      AnalysisResource preservedCompleted = service.getStatus();
      assertEquals(completed.taskId(), preservedCompleted.taskId());
      assertEquals(AnalysisResource.Status.COMPLETED, preservedCompleted.status());
      assertEquals("Analysis completed", preservedCompleted.message());
      assertNull(preservedCompleted.error());

      failNextRun.set(true);
      AnalysisResource failed = service.startAnalysis(List.of("Decompiler Parameter ID"));
      assertEquals(2, queuedRuns.get());
      assertEquals(AnalysisResource.Status.FAILED, failed.status());
      assertEquals("ASCII Strings", failed.message());
      assertEquals("corrupt block", failed.error());

      assertThrows(
          IllegalArgumentException.class, () -> service.startAnalysis(List.of()));
      assertEquals(2, queuedRuns.get());

      AnalysisResource preservedFailed = service.getStatus();
      assertEquals(failed.taskId(), preservedFailed.taskId());
      assertEquals(AnalysisResource.Status.FAILED, preservedFailed.status());
      assertEquals("ASCII Strings", preservedFailed.message());
      assertEquals("corrupt block", preservedFailed.error());

      ghidraAnalyzing.set(true);
      AnalysisResource externalRun = service.getStatus();
      assertEquals(AnalysisResource.Kind.GHIDRA, externalRun.kind());
      assertEquals(AnalysisResource.Status.RUNNING, externalRun.status());
      assertNull(externalRun.message());
      assertNull(externalRun.error());
    }
  }

  @Test
  void forwardsGuiProgressMessagesAndCancellationThroughPluginTool() throws Exception {
    RecordingTaskMonitor guiMonitor = new RecordingTaskMonitor();
    CountDownLatch midProgress = new CountDownLatch(1);
    CountDownLatch finishCommand = new CountDownLatch(1);
    ExecutorService guiExecutor = Executors.newSingleThreadExecutor();
    ExecutorService taskExecutor = Executors.newSingleThreadExecutor();
    try {
      FakePluginTool tool =
          new FakePluginTool(
              (command, target) ->
                  guiExecutor.execute(
                      () -> {
                        guiExecutorThread.set(true);
                        try {
                          command.applyTo(target, guiMonitor);
                          command.taskCompleted();
                        } finally {
                          guiExecutorThread.remove();
                        }
                      }));

      AtomicReference<AnalysisTask> taskRef = new AtomicReference<>();
      AnalysisTask task =
          new AnalysisTask(
              () -> true,
              ignored ->
                  taskRef
                      .get()
                      .runAnalysis(
                          tool,
                          null,
                          activeMonitor -> {
                            assertTrue(tool.threadIsBackgroundTaskThread());
                            activeMonitor.initialize(400, "ASCII Strings");
                            activeMonitor.setProgress(100);
                            activeMonitor.incrementProgress(60);
                            midProgress.countDown();
                            awaitLatch(finishCommand);
                          }));
      taskRef.set(task);

      Future<?> taskFuture = taskExecutor.submit(task::run);
      assertTrue(midProgress.await(5, TimeUnit.SECONDS));

      AnalysisResource liveSnapshot = task.snapshot();
      assertEquals(AnalysisResource.Status.RUNNING, liveSnapshot.status());
      assertEquals(40.0, liveSnapshot.progress());
      assertEquals("ASCII Strings", liveSnapshot.message());
      assertFalse(guiMonitor.isIndeterminate());
      assertEquals(400L, guiMonitor.getMaximum());
      assertEquals(160L, guiMonitor.getProgress());
      assertEquals("ASCII Strings", guiMonitor.getMessage());

      finishCommand.countDown();
      taskFuture.get(5, TimeUnit.SECONDS);

      AnalysisResource completed = task.snapshot();
      assertEquals(AnalysisResource.Status.COMPLETED, completed.status());
      assertEquals(40.0, completed.progress());
      assertEquals("Analysis completed", completed.message());
      assertNull(completed.error());
    } finally {
      guiExecutor.shutdownNow();
      taskExecutor.shutdownNow();
    }
  }

  @Test
  void propagatesBidirectionalCancellationAndEarlyQueueDisposalInPluginTool() throws Exception {
    RecordingTaskMonitor guiMonitor = new RecordingTaskMonitor();
    FakePluginTool guiCancelledTool =
        new FakePluginTool(
            (command, target) -> {
              command.applyTo(target, guiMonitor);
              command.taskCompleted();
            });
    AtomicReference<AnalysisTask> guiCancelledRef = new AtomicReference<>();
    AnalysisTask guiCancelledTask =
        new AnalysisTask(
            () -> false,
            ignored ->
                guiCancelledRef
                    .get()
                    .runAnalysis(
                        guiCancelledTool,
                        null,
                        activeMonitor -> {
                          activeMonitor.setMessage("Stack");
                          guiMonitor.cancel();
                          assertTrue(activeMonitor.isCancelled());
                        }));
    guiCancelledRef.set(guiCancelledTask);
    guiCancelledTask.run();
    assertEquals(AnalysisResource.Status.CANCELLED, guiCancelledTask.snapshot().status());
    assertEquals("Analysis cancelled", guiCancelledTask.snapshot().message());
    assertNull(guiCancelledTask.snapshot().error());

    RecordingTaskMonitor bridgeCancelledGuiMonitor = new RecordingTaskMonitor();
    FakePluginTool bridgeCancelledTool =
        new FakePluginTool(
            (command, target) -> {
              command.applyTo(target, bridgeCancelledGuiMonitor);
              command.taskCompleted();
            });
    AtomicReference<AnalysisTask> bridgeCancelledRef = new AtomicReference<>();
    AnalysisTask bridgeCancelledTask =
        new AnalysisTask(
            () -> false,
            ignored ->
                bridgeCancelledRef
                    .get()
                    .runAnalysis(
                        bridgeCancelledTool,
                        null,
                        activeMonitor -> {
                          bridgeCancelledRef.get().cancel();
                          assertTrue(bridgeCancelledGuiMonitor.isCancelled());
                        }));
    bridgeCancelledRef.set(bridgeCancelledTask);
    bridgeCancelledTask.run();
    assertEquals(AnalysisResource.Status.CANCELLED, bridgeCancelledTask.snapshot().status());
    assertNull(bridgeCancelledTask.snapshot().error());

    FakePluginTool cancelledBeforeRunTool =
        new FakePluginTool((command, target) -> command.taskCompleted());
    AtomicReference<AnalysisTask> queuedCancelRef = new AtomicReference<>();
    AnalysisTask queuedCancelTask =
        new AnalysisTask(
            () -> false,
            ignored -> queuedCancelRef.get().runAnalysis(cancelledBeforeRunTool, null, m -> {}));
    queuedCancelRef.set(queuedCancelTask);
    queuedCancelTask.run();
    assertEquals(AnalysisResource.Status.CANCELLED, queuedCancelTask.snapshot().status());
    assertEquals("Analysis cancelled", queuedCancelTask.snapshot().message());
    assertNull(queuedCancelTask.snapshot().error());

    FakePluginTool disposedBeforeRunTool =
        new FakePluginTool((command, target) -> command.dispose());
    AtomicReference<AnalysisTask> disposedRef = new AtomicReference<>();
    AnalysisTask disposedTask =
        new AnalysisTask(
            () -> false,
            ignored -> disposedRef.get().runAnalysis(disposedBeforeRunTool, null, m -> {}));
    disposedRef.set(disposedTask);
    disposedTask.run();
    assertEquals(AnalysisResource.Status.CANCELLED, disposedTask.snapshot().status());
    assertNull(disposedTask.snapshot().error());

    FakePluginTool failingTool =
        new FakePluginTool(
            (command, target) -> {
              command.applyTo(target, new RecordingTaskMonitor());
              command.taskCompleted();
            });
    AtomicReference<AnalysisTask> failingRef = new AtomicReference<>();
    AnalysisTask failingGuiTask =
        new AnalysisTask(
            () -> false,
            ignored ->
                failingRef
                    .get()
                    .runAnalysis(
                        failingTool,
                        null,
                        activeMonitor -> {
                          activeMonitor.setMessage("Decompiler Parameter ID");
                          throw new IllegalStateException("gui analyzer failure");
                        }));
    failingRef.set(failingGuiTask);
    failingGuiTask.run();
    assertEquals(AnalysisResource.Status.FAILED, failingGuiTask.snapshot().status());
    assertEquals("Decompiler Parameter ID", failingGuiTask.snapshot().message());
    assertEquals("gui analyzer failure", failingGuiTask.snapshot().error());
  }

  private static final ThreadLocal<Boolean> guiExecutorThread =
      ThreadLocal.withInitial(() -> false);

  private static void awaitLatch(CountDownLatch latch) {
    try {
      assertTrue(latch.await(5, TimeUnit.SECONDS));
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      throw new AssertionError(interrupted);
    }
  }

  private static final class RecordingTaskMonitor extends TaskMonitorAdapter {
    private volatile long maximum = TaskMonitor.NO_PROGRESS_VALUE;
    private volatile long progress;
    private volatile boolean indeterminate;
    private volatile String message;

    RecordingTaskMonitor() {
      super(true);
    }

    @Override
    public void initialize(long max) {
      this.maximum = max;
      this.progress = 0;
      this.indeterminate = max <= 0;
    }

    @Override
    public void setMaximum(long max) {
      this.maximum = max;
    }

    @Override
    public long getMaximum() {
      return maximum;
    }

    @Override
    public void setProgress(long value) {
      this.progress = value;
    }

    @Override
    public void incrementProgress(long incrementAmount) {
      this.progress += incrementAmount;
    }

    @Override
    public long getProgress() {
      return progress;
    }

    @Override
    public void setIndeterminate(boolean indeterminate) {
      this.indeterminate = indeterminate;
    }

    @Override
    public boolean isIndeterminate() {
      return indeterminate;
    }

    @Override
    public void setMessage(String message) {
      this.message = message;
    }

    @Override
    public String getMessage() {
      return message;
    }
  }

  private static final class FakePluginTool extends PluginTool {
    private final BiConsumer<BackgroundCommand<Program>, Program> dispatcher;

    FakePluginTool(BiConsumer<BackgroundCommand<Program>, Program> dispatcher) {
      super();
      this.dispatcher = dispatcher;
    }

    @Override
    public boolean threadIsBackgroundTaskThread() {
      return guiExecutorThread.get();
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T extends DomainObject> void executeBackgroundCommand(
        BackgroundCommand<T> cmd, T obj) {
      dispatcher.accept((BackgroundCommand<Program>) cmd, (Program) obj);
    }
  }

  private static final class DirectExecutorService extends java.util.concurrent.AbstractExecutorService {
    private final Runnable onExecute;
    private volatile boolean shutdown;

    DirectExecutorService(Runnable onExecute) {
      this.onExecute = onExecute;
    }

    @Override
    public void shutdown() {
      shutdown = true;
    }

    @Override
    public List<Runnable> shutdownNow() {
      shutdown = true;
      return List.of();
    }

    @Override
    public boolean isShutdown() {
      return shutdown;
    }

    @Override
    public boolean isTerminated() {
      return shutdown;
    }

    @Override
    public boolean awaitTermination(long timeout, TimeUnit unit) {
      return shutdown;
    }

    @Override
    public void execute(Runnable command) {
      onExecute.run();
      command.run();
    }
  }
}
