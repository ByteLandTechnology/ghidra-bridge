package app.byteland.ghidra.adapter.ghidra;

import app.byteland.ghidra.service.TransactionExecutionException;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
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
import java.lang.ref.WeakReference;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Coordinates Ghidra program access, commands, and transaction lifecycles.
 */
public final class GhidraSession implements AutoCloseable {
  private final ProgramHost host;
  private final QuerySnapshotCache querySnapshots;
  private final BooleanSupplier analyzingSupplier;
  private final boolean allowProxySnapshots;
  private final Object executionLock = new Object();
  private final List<Consumer<Program>> programCloseListeners = new CopyOnWriteArrayList<>();
  private volatile WeakReference<Program> snapshotProgram = new WeakReference<>(null);
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
    this(host, new QuerySnapshotCache(), null, false);
  }

  /**
   * Creates a session wrapper around an active Ghidra script with custom snapshot state.
   *
   * @param script active Ghidra script instance
   * @param querySnapshots snapshot cache for paginated queries
   * @param analyzingSupplier supplier that reports if automatic analysis is active
   */
  public GhidraSession(
      GhidraScript script,
      QuerySnapshotCache querySnapshots,
      BooleanSupplier analyzingSupplier) {
    this(
        ProgramHost.forScript(Objects.requireNonNull(script, "script")),
        querySnapshots,
        Objects.requireNonNull(analyzingSupplier, "analyzingSupplier"),
        true);
  }

  /**
   * Creates a session wrapper around a program host with custom snapshot state.
   *
   * @param host host for Ghidra program access and transactions
   * @param querySnapshots snapshot cache for paginated queries
   * @param analyzingSupplier supplier that reports if automatic analysis is active
   */
  public GhidraSession(
      ProgramHost host,
      QuerySnapshotCache querySnapshots,
      BooleanSupplier analyzingSupplier) {
    this(
        host,
        querySnapshots,
        Objects.requireNonNull(analyzingSupplier, "analyzingSupplier"),
        true);
  }

  private GhidraSession(
      ProgramHost host,
      QuerySnapshotCache querySnapshots,
      BooleanSupplier analyzingSupplier,
      boolean allowProxySnapshots) {
    this.host = Objects.requireNonNull(host, "host");
    this.querySnapshots = Objects.requireNonNull(querySnapshots, "querySnapshots");
    this.analyzingSupplier = analyzingSupplier;
    this.allowProxySnapshots = allowProxySnapshots;
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
   * Returns the query snapshot cache for the active program and clears stale program state.
   *
   * @return query snapshot cache
   */
  public QuerySnapshotCache querySnapshots() {
    Program program = currentProgramOrNull();
    if (!snapshotProgram.refersTo(program)) {
      synchronized (querySnapshots) {
        if (!snapshotProgram.refersTo(program)) {
          querySnapshots.clear();
          snapshotProgram = new WeakReference<>(program);
        }
      }
    }
    return querySnapshots;
  }

  /**
   * Returns the modification number of the active program, or {@code 0L} when none is open.
   *
   * @return program modification number
   */
  public long modificationNumber() {
    Program program = currentProgramOrNull();
    return program == null ? 0L : program.getModificationNumber();
  }

  /**
   * Reports if automatic analysis is active on the current program.
   *
   * @return {@code true} if automatic analysis is active
   */
  public boolean isAnalyzing() {
    if (analyzingSupplier != null) {
      return analyzingSupplier.getAsBoolean();
    }
    Program program = currentProgramOrNull();
    return program != null
        && !Proxy.isProxyClass(program.getClass())
        && AutoAnalysisManager.hasAutoAnalysisManager(program)
        && AutoAnalysisManager.getAnalysisManager(program).isAnalyzing();
  }

  /**
   * Reports if sorted query snapshots can be cached for the current program.
   *
   * @return {@code true} if the session can cache snapshots
   */
  public boolean canCacheSnapshots() {
    Program program = currentProgramOrNull();
    if (program == null) {
      return false;
    }
    if (!allowProxySnapshots && Proxy.isProxyClass(program.getClass())) {
      return false;
    }
    return !isAnalyzing();
  }

  @Override
  public void close() {
    synchronized (querySnapshots) {
      querySnapshots.clear();
      snapshotProgram = new WeakReference<>(null);
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
    if (snapshotProgram.refersTo(program)) {
      synchronized (querySnapshots) {
        if (snapshotProgram.refersTo(program)) {
          querySnapshots.clear();
          snapshotProgram = new WeakReference<>(null);
        }
      }
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
   * Returns the specific reference between two addresses at an operand index, or {@code null}.
   *
   * @param fromAddress source address
   * @param toAddress destination address
   * @param operandIndex source operand index
   * @return found Ghidra reference, or {@code null} when absent
   */
  public Reference reference(Address fromAddress, Address toAddress, int operandIndex) {
    Objects.requireNonNull(fromAddress, "fromAddress");
    Objects.requireNonNull(toAddress, "toAddress");
    return currentProgram().getReferenceManager().getReference(fromAddress, toAddress, operandIndex);
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
        try {
          host.finishTransaction(targetProgram, transactionId, commit);
        } finally {
          querySnapshots.clear();
        }
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
      try {
        if (transactionDepth == 0 && host.requiresCommandTransaction()) {
          if (withTransaction(() -> host.runCommand(currentProgram(), command))) {
            return;
          }
        } else if (host.runCommand(currentProgramOrNull(), command)) {
          return;
        }
      } finally {
        querySnapshots.clear();
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
