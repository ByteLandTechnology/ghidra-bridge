package app.byteland.ghidra.adapter.ghidra;

import app.byteland.ghidra.service.TransactionExecutionException;
import ghidra.app.script.GhidraScript;
import ghidra.framework.cmd.Command;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import java.util.Arrays;
import java.util.Collections;
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

  /**
   * Creates a session wrapper around an active Ghidra script.
   *
   * @param script active Ghidra script instance
   */
  public GhidraSession(GhidraScript script) {
    this(ProgramHost.forScript(Objects.requireNonNull(script, "script")));
  }

  /**
   * Creates a session wrapper around a dynamic program supplier.
   *
   * @param programSupplier supplier for the active Ghidra program
   */
  public GhidraSession(Supplier<Program> programSupplier) {
    this(ProgramHost.forProgramSupplier(Objects.requireNonNull(programSupplier, "programSupplier")));
  }

  /**
   * Creates a session wrapper around a program host.
   *
   * @param host host for Ghidra program access and transactions
   */
  public GhidraSession(ProgramHost host) {
    this.host = Objects.requireNonNull(host, "host");
  }

  /**
   * Returns the flat program API for the pinned or active program.
   *
   * @return flat program API instance
   */
  public FlatProgramAPI flatApi() {
    synchronized (executionLock) {
      return host.flatApi(pinnedProgram);
    }
  }

  /**
   * Returns the active Ghidra program or fails when none is open.
   *
   * @return active Ghidra program
   */
  public Program currentProgram() {
    Program program = currentProgramOrNull();
    if (program == null) {
      throw new IllegalStateException("No current program is open in Ghidra");
    }
    return program;
  }

  /**
   * Returns the active Ghidra program, or null when no program is open.
   *
   * @return active Ghidra program or null
   */
  public Program currentProgramOrNull() {
    if (Thread.holdsLock(executionLock) && pinnedProgram != null) {
      return pinnedProgram;
    }
    return host.currentProgramOrNull();
  }

  /**
   * Registers a listener that runs when a program closes.
   *
   * @param listener callback that receives the closed program
   */
  public void onProgramClosed(Consumer<Program> listener) {
    programCloseListeners.add(Objects.requireNonNull(listener, "listener"));
  }

  /**
   * Releases cached state for a closed program and notifies registered listeners.
   *
   * @param program closed Ghidra program, or {@code null}
   */
  public void notifyProgramClosed(Program program) {
    if (program == null) {
      return;
    }
    synchronized (executionLock) {
      host.releaseProgram(program);
    }
    for (Consumer<Program> listener : programCloseListeners) {
      listener.accept(program);
    }
  }

  /**
   * Commits any ambient script transaction and saves the active program.
   */
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

  /**
   * Parses a raw address text value against the active program.
   *
   * @param rawAddress canonical or hex address text
   * @return resolved Ghidra address
   */
  public Address parseAddress(String rawAddress) {
    Program program = currentProgramOrNull();
    if (program != null) {
      return AddressUtil.parseAddress(program, rawAddress);
    }
    return AddressUtil.parseAddress(flatApi(), rawAddress);
  }

  /**
   * Returns references to or from the given program address.
   *
   * @param address target or source address
   * @param to true for inbound references, false for outbound references
   * @return iterable of Ghidra references
   */
  public Iterable<Reference> references(Address address, boolean to) {
    Objects.requireNonNull(address, "address");
    ReferenceManager manager = currentProgram().getReferenceManager();
    if (to) {
      return () -> {
        ReferenceIterator incoming = manager.getReferencesTo(address);
        return incoming == null ? Collections.emptyIterator() : incoming;
      };
    }
    Reference[] outgoing = manager.getReferencesFrom(address);
    return outgoing == null ? List.of() : Arrays.asList(outgoing);
  }

  /**
   * Reads a byte range from the active program memory.
   *
   * @param start start address to read from
   * @param length number of bytes to read
   * @return copied program memory bytes
   * @throws MemoryAccessException if the requested range cannot be read
   */
  public byte[] readBytes(Address start, int length) throws MemoryAccessException {
    Objects.requireNonNull(start, "start");
    byte[] bytes = new byte[length];
    currentProgram().getMemory().getBytes(start, bytes);
    return bytes;
  }

  /**
   * Returns the next function after the entry point of the given function.
   *
   * @param function current Ghidra function, or {@code null}
   * @return next function in address order, or {@code null} when none exists
   */
  public Function functionAfter(Function function) {
    return function == null ? null : functionAfter(function.getEntryPoint());
  }

  /**
   * Returns the first function strictly after the given address.
   *
   * @param address reference address
   * @return next function in address order, or {@code null} when none exists
   */
  public Function functionAfter(Address address) {
    Objects.requireNonNull(address, "address");
    FunctionIterator iterator = currentProgram().getListing().getFunctions(address, true);
    if (!iterator.hasNext()) {
      return null;
    }
    Function candidate = iterator.next();
    if (address.equals(candidate.getEntryPoint())) {
      return iterator.hasNext() ? iterator.next() : null;
    }
    return candidate;
  }

  /**
   * Runs an operation inside a committed program transaction.
   *
   * @param operation transactional operation to run
   * @param <T> operation result type
   * @return operation result
   */
  public <T> T withTransaction(TransactionalOperation<T> operation) {
    return withTransaction(null, operation, true);
  }

  /**
   * Runs an operation inside a committed transaction on the given program.
   *
   * @param program target Ghidra program
   * @param operation transactional operation to run
   * @param <T> operation result type
   * @return operation result
   */
  public <T> T withProgramTransaction(Program program, TransactionalOperation<T> operation) {
    return withTransaction(Objects.requireNonNull(program, "program"), operation, true);
  }

  /**
   * Runs an operation inside a temporary transaction that reverts on completion.
   *
   * @param operation transactional operation to run
   * @param <T> operation result type
   * @return operation result
   */
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
        if (explicitProgram != null && pinnedProgram != null && explicitProgram != pinnedProgram) {
          throw new IllegalStateException("Nested transaction targets a different program");
        }
        return runOperation(operation);
      }

      Program targetProgram = host.resolveTransactionProgram(explicitProgram);
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

  /**
   * Executes a Ghidra command against the active program or fails on command error.
   *
   * @param command Ghidra program command
   * @param failurePrefix message prefix used when the command fails
   */
  public void runCommand(Command<Program> command, String failurePrefix) {
    Objects.requireNonNull(command, "command");
    synchronized (executionLock) {
      if (transactionDepth == 0 && host.requiresCommandTransaction()) {
        if (withTransaction(() -> host.runCommand(currentProgram(), command))) {
          return;
        }
      } else if (host.runCommand(currentProgramOrNull(), command)) {
        return;
      }
    }
    String status = command.getStatusMsg();
    if (status == null || status.isBlank()) {
      status = "command failed";
    }
    throw new TransactionExecutionException(failurePrefix + ": " + status);
  }

  /**
   * Represents a checked operation executed inside a Ghidra transaction.
   *
   * @param <T> operation result type
   */
  @FunctionalInterface
  public interface TransactionalOperation<T> {
    /**
     * Runs the transactional work.
     *
     * @return operation result
     * @throws Exception if the operation fails
     */
    T run() throws Exception;
  }

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
