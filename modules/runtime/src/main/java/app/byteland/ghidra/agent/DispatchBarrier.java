package app.byteland.ghidra.agent;

import java.util.Objects;

/**
 * Counts in-flight dispatches, rejects new ones after close, and waits for in-flight ones to finish.
 */
final class DispatchBarrier {
  @FunctionalInterface
  interface CheckedOperation<T> {
    T run() throws Exception;
  }

  private int activeDispatches;
  private boolean closing;

  <T> T run(CheckedOperation<T> operation) throws Exception {
    Objects.requireNonNull(operation, "operation");
    synchronized (this) {
      if (closing) {
        throw new IllegalStateException("Agent dispatcher is shutting down");
      }
      activeDispatches++;
    }

    try {
      return operation.run();
    } finally {
      synchronized (this) {
        activeDispatches--;
        if (activeDispatches == 0) {
          notifyAll();
        }
      }
    }
  }

  boolean closeAndAwait() {
    boolean interrupted = Thread.interrupted();
    boolean ownsResourceClose;
    synchronized (this) {
      ownsResourceClose = !closing;
      closing = true;
      while (activeDispatches != 0) {
        try {
          wait();
        } catch (InterruptedException ignored) {
          interrupted = true;
        }
      }
    }
    if (interrupted) {
      Thread.currentThread().interrupt();
    }
    return ownsResourceClose;
  }
}
