package app.byteland.ghidra.adapter.ghidra;

import app.byteland.ghidra.service.TransactionExecutionException;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import ghidra.app.script.GhidraScript;
import ghidra.framework.cmd.Command;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Coordinates Ghidra program access, commands, and transaction lifecycles.
 */
public final class GhidraSession {
  private final ProgramHost host;
  private final Object executionLock = new Object();
  private final List<Consumer<Program>> programCloseListeners = new CopyOnWriteArrayList<>();
  private int transactionDepth;
  private Program pinnedProgram;

  public GhidraSession(GhidraScript script) {
    this(ProgramHost.forScript(Objects.requireNonNull(script, "script")));
  }

  public GhidraSession(Supplier<Program> programSupplier) {
    this(ProgramHost.forProgramSupplier(Objects.requireNonNull(programSupplier, "programSupplier")));
  }

  public GhidraSession(ProgramHost host) {
    this.host = Objects.requireNonNull(host, "host");
  }

  @SuppressFBWarnings(
      value = "EI_EXPOSE_REP",
      justification = "Adapter collaborators require the live GhidraScript execution context")
  public GhidraScript script() {
    GhidraScript script = host.scriptOrNull();
    if (script == null) {
      throw new IllegalStateException("Session does not run inside a GhidraScript");
    }
    return script;
  }

  @SuppressFBWarnings(
      value = "EI_EXPOSE_REP",
      justification = "Adapter collaborators use FlatProgramAPI for the active program")
  public FlatProgramAPI flatApi() {
    synchronized (executionLock) {
      if (pinnedProgram != null && host.scriptOrNull() == null) {
        return new FlatProgramAPI(pinnedProgram, ghidra.util.task.TaskMonitor.DUMMY);
      }
      return host.flatApi();
    }
  }

  public Program currentProgram() {
    Program program = currentProgramOrNull();
    if (program == null) {
      throw new IllegalStateException("No current program is open in Ghidra");
    }
    return program;
  }

  public Program currentProgramOrNull() {
    synchronized (executionLock) {
      return pinnedProgram != null ? pinnedProgram : host.currentProgramOrNull();
    }
  }

  public void onProgramClosed(Consumer<Program> listener) {
    programCloseListeners.add(Objects.requireNonNull(listener, "listener"));
  }

  public void notifyProgramClosed(Program program) {
    if (program == null) {
      return;
    }
    for (Consumer<Program> listener : programCloseListeners) {
      listener.accept(program);
    }
  }

  public void withExclusiveAccess(Runnable action) {
    Objects.requireNonNull(action, "action");
    synchronized (executionLock) {
      action.run();
    }
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  public void saveCurrentProgram() {
    synchronized (executionLock) {
      try {
        host.saveProgram(currentProgram());
      } catch (Exception error) {
        String detail = error.getMessage();
        if (detail == null || detail.isBlank()) {
          detail = error.getClass().getSimpleName();
        }
        throw new IllegalStateException("Unable to save current program: " + detail, error);
      }
    }
  }

  public Address parseAddress(String rawAddress) {
    return AddressUtil.parseAddress(flatApi(), rawAddress);
  }

  public java.util.List<ghidra.program.model.symbol.Reference> references(
      Address address, boolean to) {
    FlatProgramAPI api = flatApi();
    return java.util.Arrays.asList(
        to ? api.getReferencesTo(address) : api.getReferencesFrom(address));
  }

  public <T> T withTransaction(TransactionalOperation<T> operation) {
    return withTransaction(null, operation, true);
  }

  public <T> T withProgramTransaction(Program program, TransactionalOperation<T> operation) {
    return withTransaction(Objects.requireNonNull(program, "program"), operation, true);
  }

  public <T> T withTemporaryChanges(TransactionalOperation<T> operation) {
    return withTransaction(null, operation, false);
  }

  private <T> T withTransaction(
      Program explicitProgram, TransactionalOperation<T> operation, boolean commitChanges) {
    Objects.requireNonNull(operation, "operation");
    synchronized (executionLock) {
      if (transactionDepth > 0) {
        if (!commitChanges) {
          throw new IllegalStateException("Temporary changes require an independent transaction");
        }
        return runOperation(operation);
      }

      Program targetProgram =
          explicitProgram != null
              ? explicitProgram
              : (host.scriptOrNull() == null ? currentProgram() : host.currentProgramOrNull());
      int transactionId = host.beginTransaction(targetProgram);
      pinnedProgram = targetProgram;
      transactionDepth++;
      boolean commit = false;
      try {
        T result = runOperation(operation);
        commit = commitChanges;
        return result;
      } finally {
        transactionDepth--;
        pinnedProgram = null;
        host.finishTransaction(targetProgram, transactionId, commit);
      }
    }
  }

  public void runCommand(Command<Program> command, String failurePrefix) {
    Objects.requireNonNull(command, "command");
    synchronized (executionLock) {
      if (transactionDepth == 0 && host.scriptOrNull() == null) {
        boolean applied = withTransaction(() -> host.runCommand(currentProgram(), command));
        if (applied) {
          return;
        }
      } else if (host.runCommand(
          host.scriptOrNull() == null ? currentProgram() : host.currentProgramOrNull(), command)) {
        return;
      }
    }
    String status = command.getStatusMsg();
    if (status == null || status.isBlank()) {
      status = "command failed";
    }
    throw new TransactionExecutionException(failurePrefix + ": " + status);
  }

  @FunctionalInterface
  public interface TransactionalOperation<T> {
    T run() throws Exception;
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private static <T> T runOperation(TransactionalOperation<T> operation) {
    try {
      return operation.run();
    } catch (RuntimeException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new TransactionExecutionException(ex.getMessage(), ex);
    }
  }
}
