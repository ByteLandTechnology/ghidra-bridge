package app.byteland.ghidra;

import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Provides graceful shutdown procedures for executor services.
 */
public final class ExecutorShutdown {
  private ExecutorShutdown() {}

  /**
   * Stops an executor service and waits for tasks to finish.
   *
   * @param executor executor service to stop
   */
  public static void shutdownAndAwait(ExecutorService executor) {
    Objects.requireNonNull(executor, "executor").shutdown();
    awaitTermination(executor);
  }

  private static void awaitTermination(ExecutorService executor) {
    boolean interrupted = Thread.interrupted();
    try {
      while (!executor.isTerminated()) {
        try {
          executor.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
        } catch (InterruptedException ignored) {
          interrupted = true;
        }
      }
    } finally {
      if (interrupted) {
        Thread.currentThread().interrupt();
      }
    }
  }
}
