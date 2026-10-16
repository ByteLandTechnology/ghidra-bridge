package app.byteland.ghidra;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

@SuppressWarnings("try")
final class GracefulExit implements AutoCloseable {
  @FunctionalInterface
  interface CheckedAction {
    void run() throws Exception;
  }

  /** The time that the JVM gets to exit after a save that ran at the deadline. */
  private static final Duration AFTER_SAVE_GRACE = Duration.ofSeconds(30);

  private final CheckedAction saveAction;
  private final Runnable saveSucceeded;
  private final java.util.function.Consumer<Exception> saveFailed;
  private final AtomicBoolean closeStarted = new AtomicBoolean(false);
  private final CountDownLatch saveCompleted = new CountDownLatch(1);

  private Optional<Thread> shutdownHook = Optional.empty();

  GracefulExit(
      CheckedAction saveAction,
      Runnable saveSucceeded,
      java.util.function.Consumer<Exception> saveFailed) {
    this.saveAction = Objects.requireNonNull(saveAction, "saveAction");
    this.saveSucceeded = Objects.requireNonNull(saveSucceeded, "saveSucceeded");
    this.saveFailed = Objects.requireNonNull(saveFailed, "saveFailed");
  }

  synchronized void installShutdownHook(Runnable stopAction, Runnable onShutdown) {
    Objects.requireNonNull(stopAction, "stopAction");
    Objects.requireNonNull(onShutdown, "onShutdown");
    if (shutdownHook.isPresent()) {
      throw new IllegalStateException("shutdown hook already installed");
    }

    Thread hook =
        new Thread(
            () -> {
              try {
                try {
                  stopAction.run();
                } finally {
                  onShutdown.run();
                }
              } finally {
                awaitSaveCompletion();
              }
            },
            "ghidra-bridge-shutdown");
    Runtime.getRuntime().addShutdownHook(hook);
    shutdownHook = Optional.of(hook);
  }

  /**
   * Halts the JVM if it does not exit within {@code delay}. The host that started this Ghidra
   * asks for the deadline. Thus, no orphan process stays when a close step blocks.
   *
   * <p>The deadline never stops a save. If a save runs at the deadline, the JVM gets {@link
   * #AFTER_SAVE_GRACE} after the save to exit. A normal exit stops the daemon thread.
   */
  void startExitDeadline(Duration delay, java.util.function.Consumer<String> log) {
    Thread.ofPlatform()
        .daemon()
        .name("ghidra-bridge-exit-deadline")
        .start(
            () -> {
              try {
                Thread.sleep(delay.toMillis());
                if (closeStarted.get() && saveCompleted.getCount() > 0) {
                  saveCompleted.await();
                  Thread.sleep(AFTER_SAVE_GRACE.toMillis());
                }
              } catch (InterruptedException interrupted) {
                return;
              }
              log.accept("[ghidra-bridge] Ghidra did not exit after the session ended; halting.");
              Runtime.getRuntime().halt(1);
            });
  }

  @Override
  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  public void close() throws Exception {
    if (!closeStarted.compareAndSet(false, true)) {
      return;
    }

    try {
      saveAction.run();
      saveSucceeded.run();
    } catch (Exception failure) {
      saveFailed.accept(failure);
      throw failure;
    } finally {
      saveCompleted.countDown();
      unregisterShutdownHook();
    }
  }

  private void awaitSaveCompletion() {
    boolean interrupted = false;
    while (true) {
      try {
        saveCompleted.await();
        break;
      } catch (InterruptedException ignored) {
        interrupted = true;
      }
    }
    if (interrupted) {
      Thread.currentThread().interrupt();
    }
  }

  private synchronized void unregisterShutdownHook() {
    if (shutdownHook.isEmpty()) {
      return;
    }
    try {
      Runtime.getRuntime().removeShutdownHook(shutdownHook.orElseThrow());
    } catch (IllegalStateException ignored) {
    } finally {
      shutdownHook = Optional.empty();
    }
  }

}
