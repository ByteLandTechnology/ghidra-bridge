package app.byteland.ghidra;

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

  interface HookRegistrar {
    void add(Thread hook);

    boolean remove(Thread hook);
  }

  private static final HookRegistrar RUNTIME_HOOKS =
      new HookRegistrar() {
        @Override
        public void add(Thread hook) {
          Runtime.getRuntime().addShutdownHook(hook);
        }

        @Override
        public boolean remove(Thread hook) {
          return Runtime.getRuntime().removeShutdownHook(hook);
        }
      };

  private final CheckedAction saveAction;
  private final Runnable saveSucceeded;
  private final java.util.function.Consumer<Exception> saveFailed;
  private final AtomicBoolean closeStarted = new AtomicBoolean(false);
  private final CountDownLatch saveCompleted = new CountDownLatch(1);

  private Optional<HookRegistration> hookRegistration = Optional.empty();

  GracefulExit(
      CheckedAction saveAction,
      Runnable saveSucceeded,
      java.util.function.Consumer<Exception> saveFailed) {
    this.saveAction = Objects.requireNonNull(saveAction, "saveAction");
    this.saveSucceeded = Objects.requireNonNull(saveSucceeded, "saveSucceeded");
    this.saveFailed = Objects.requireNonNull(saveFailed, "saveFailed");
  }

  void installShutdownHook(Runnable stopAction, Runnable onShutdown) {
    installShutdownHook(stopAction, onShutdown, RUNTIME_HOOKS);
  }

  synchronized void installShutdownHook(
      Runnable stopAction, Runnable onShutdown, HookRegistrar registrar) {
    Objects.requireNonNull(stopAction, "stopAction");
    Objects.requireNonNull(onShutdown, "onShutdown");
    Objects.requireNonNull(registrar, "registrar");
    if (hookRegistration.isPresent()) {
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
    registrar.add(hook);
    hookRegistration = Optional.of(new HookRegistration(registrar, hook));
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
    if (hookRegistration.isEmpty()) {
      return;
    }
    HookRegistration registration = hookRegistration.orElseThrow();
    try {
      registration.registrar().remove(registration.hook());
    } catch (IllegalStateException ignored) {
    } finally {
      hookRegistration = Optional.empty();
    }
  }

  private record HookRegistration(HookRegistrar registrar, Thread hook) {
    private HookRegistration {
      Objects.requireNonNull(registrar, "registrar");
      Objects.requireNonNull(hook, "hook");
    }
  }
}
