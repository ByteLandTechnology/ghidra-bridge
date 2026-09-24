package app.byteland.ghidra.adapter.ghidra.analysis;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.AutoAnalysisManagerListener;
import java.util.Objects;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

final class AnalysisManagerWait {
  private static final long POLL_INTERVAL_MILLIS = 50;

  private AnalysisManagerWait() {}

  static void awaitIdle(AutoAnalysisManager manager) {
    Objects.requireNonNull(manager, "manager");
    Semaphore ended = new Semaphore(0);
    AutoAnalysisManagerListener listener = (ignored, cancelled) -> ended.release();
    awaitIdle(
        manager::isAnalyzing,
        () -> manager.addListener(listener),
        () -> manager.removeListener(listener),
        () -> ended.tryAcquire(POLL_INTERVAL_MILLIS, TimeUnit.MILLISECONDS));
  }

  static void awaitIdle(
      BooleanSupplier analyzing,
      Runnable registerListener,
      Runnable removeListener,
      InterruptibleSignal endSignal) {
    Objects.requireNonNull(analyzing, "analyzing");
    Objects.requireNonNull(registerListener, "registerListener");
    Objects.requireNonNull(removeListener, "removeListener");
    Objects.requireNonNull(endSignal, "endSignal");
    boolean interrupted = Thread.interrupted();
    boolean listenerRegistered = false;
    try {
      registerListener.run();
      listenerRegistered = true;
      while (analyzing.getAsBoolean()) {
        try {
          boolean signaled = endSignal.await();
          if (signaled && !analyzing.getAsBoolean()) {
            break;
          }
        } catch (InterruptedException ignored) {
          interrupted = true;
        }
      }
    } finally {
      try {
        if (listenerRegistered) {
          removeListener.run();
        }
      } finally {
        if (interrupted) {
          Thread.currentThread().interrupt();
        }
      }
    }
  }

  @FunctionalInterface
  interface InterruptibleSignal {
    boolean await() throws InterruptedException;
  }
}
