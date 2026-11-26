package app.byteland.ghidra.agent;

import java.util.Objects;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Coordinates fair shared-read and exclusive-write execution, counts in-flight dispatches, and
 * rejects new dispatches after close while waiting for active dispatches to finish.
 */
final class DispatchBarrier {
  @FunctionalInterface
  interface CheckedOperation<T> {
    T run() throws Exception;
  }

  private final ReentrantReadWriteLock readWriteLock = new ReentrantReadWriteLock(true);
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

  <T> T runRead(CheckedOperation<T> operation) throws Exception {
    Objects.requireNonNull(operation, "operation");
    ReentrantReadWriteLock.ReadLock readLock = readWriteLock.readLock();
    readLock.lock();
    try {
      return operation.run();
    } finally {
      readLock.unlock();
    }
  }

  <T> T runWrite(CheckedOperation<T> operation) throws Exception {
    Objects.requireNonNull(operation, "operation");
    ReentrantReadWriteLock.WriteLock writeLock = readWriteLock.writeLock();
    writeLock.lock();
    try {
      return operation.run();
    } finally {
      writeLock.unlock();
    }
  }

  boolean isFair() {
    return readWriteLock.isFair();
  }

  int readHoldCount() {
    return readWriteLock.getReadHoldCount();
  }

  int readLockCount() {
    return readWriteLock.getReadLockCount();
  }

  boolean isWriteLockedByCurrentThread() {
    return readWriteLock.isWriteLockedByCurrentThread();
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
