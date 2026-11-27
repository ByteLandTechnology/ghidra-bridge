package app.byteland.ghidra.adapter.ghidra.analysis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.analysis.AnalysisResource;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class AnalysisTaskTest {

  @Test
  void snapshotOmitsErrorDuringRunAndAfterCompletion() throws Exception {
    CountDownLatch entered = new CountDownLatch(1);
    CountDownLatch proceed = new CountDownLatch(1);
    AtomicReference<AnalysisResource> activeSnapshot = new AtomicReference<>();
    AnalysisTask task =
        new AnalysisTask(
            () -> true,
            () -> {
              entered.countDown();
              try {
                assertTrue(proceed.await(5, TimeUnit.SECONDS));
              } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(interrupted);
              }
            });

    ExecutorService executor = Executors.newSingleThreadExecutor();
    try {
      Future<?> future = executor.submit(task::run);
      assertTrue(entered.await(5, TimeUnit.SECONDS));
      activeSnapshot.set(task.snapshot());
      assertEquals(AnalysisResource.Status.RUNNING, activeSnapshot.get().status());
      assertNull(activeSnapshot.get().error());
      assertNull(activeSnapshot.get().finishedAt());

      proceed.countDown();
      future.get(5, TimeUnit.SECONDS);
    } finally {
      executor.shutdownNow();
    }

    AnalysisResource completed = task.snapshot();
    assertEquals(AnalysisResource.Status.COMPLETED, completed.status());
    assertTrue(completed.analyzed());
    assertNotNull(completed.finishedAt());
    assertNull(completed.error());
  }

  @Test
  void snapshotRecordsFailureReason() {
    AnalysisTask task =
        new AnalysisTask(
            () -> false,
            () -> {
              throw new IllegalArgumentException("unknown analyzer: Bogus Analyzer");
            });

    task.run();

    AnalysisResource failed = task.snapshot();
    assertEquals(AnalysisResource.Status.FAILED, failed.status());
    assertFalse(failed.analyzed());
    assertNotNull(failed.finishedAt());
    assertEquals("unknown analyzer: Bogus Analyzer", failed.error());
  }

  @Test
  void cancelStopsActiveTaskAndRecordsCancellationReason() throws Exception {
    CountDownLatch entered = new CountDownLatch(1);
    CountDownLatch cancelledLatch = new CountDownLatch(1);
    AnalysisTask task =
        new AnalysisTask(
            () -> false,
            () -> {
              entered.countDown();
              try {
                assertTrue(cancelledLatch.await(5, TimeUnit.SECONDS));
              } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(interrupted);
              }
            });

    ExecutorService executor = Executors.newSingleThreadExecutor();
    try {
      Future<?> future = executor.submit(task::run);
      assertTrue(entered.await(5, TimeUnit.SECONDS));
      assertTrue(task.isRunning());
      task.cancel();
      cancelledLatch.countDown();
      future.get(5, TimeUnit.SECONDS);
    } finally {
      executor.shutdownNow();
    }

    assertFalse(task.isRunning());
    AnalysisResource cancelled = task.snapshot();
    assertEquals(AnalysisResource.Status.CANCELLED, cancelled.status());
    assertNotNull(cancelled.finishedAt());
    assertEquals("analysis cancelled", cancelled.error());
  }
}
