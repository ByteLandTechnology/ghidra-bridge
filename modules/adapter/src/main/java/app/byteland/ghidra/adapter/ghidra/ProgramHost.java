package app.byteland.ghidra.adapter.ghidra;

import ghidra.app.script.GhidraScript;
import ghidra.framework.cmd.Command;
import ghidra.framework.model.DomainFile;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * Provides active Ghidra program access and transaction control for script or GUI hosts.
 */
public interface ProgramHost {
  /**
   * Returns the active Ghidra program, or {@code null} when no program is open.
   *
   * @return active Ghidra program, or {@code null}
   */
  Program currentProgramOrNull();

  /**
   * Returns a flat program API bound to the pinned or active program.
   *
   * @param pinnedProgram pinned transaction program, or {@code null}
   * @return flat program API instance
   */
  FlatProgramAPI flatApi(Program pinnedProgram);

  /**
   * Resolves the target program for a new transaction.
   *
   * @param explicitProgram explicit target program, or {@code null} for the active program
   * @return resolved target program
   */
  Program resolveTransactionProgram(Program explicitProgram);

  /**
   * Starts a transaction on the target program.
   *
   * @param program target Ghidra program
   * @return transaction identifier
   */
  int beginTransaction(Program program);

  /**
   * Ends an active transaction on the target program.
   *
   * @param program target Ghidra program
   * @param transactionId transaction identifier from {@link #beginTransaction(Program)}
   * @param commit {@code true} to keep changes, or {@code false} to revert changes
   */
  void finishTransaction(Program program, int transactionId, boolean commit);

  /**
   * Reports whether commands need an explicit outer transaction.
   *
   * @return {@code true} when commands need an explicit transaction
   */
  boolean requiresCommandTransaction();

  /**
   * Runs a Ghidra command against the target program.
   *
   * @param program target Ghidra program, or {@code null}
   * @param command Ghidra command to apply
   * @return {@code true} if the command succeeded
   */
  boolean runCommand(Program program, Command<Program> command);

  /**
   * Saves uncommitted changes for the target program.
   *
   * @param program target Ghidra program, or {@code null}
   * @throws Exception if the save operation fails
   */
  void saveProgram(Program program) throws Exception;

  /**
   * Releases cached host state when a program closes.
   *
   * @param program closed Ghidra program, or {@code null}
   */
  default void releaseProgram(Program program) {}

  /**
   * Creates a host backed by an active Ghidra script.
   *
   * @param script active Ghidra script
   * @return script-backed program host
   */
  static ProgramHost forScript(GhidraScript script) {
    return new ScriptProgramHost(script);
  }

  /**
   * Creates a host backed by a dynamic program supplier.
   *
   * @param programSupplier supplier for the active Ghidra program
   * @return supplier-backed program host
   */
  static ProgramHost forProgramSupplier(Supplier<Program> programSupplier) {
    return new DynamicProgramHost(programSupplier);
  }
}

final class ScriptProgramHost implements ProgramHost {
  private final GhidraScript script;

  ScriptProgramHost(GhidraScript script) {
    this.script = Objects.requireNonNull(script, "script");
  }

  @Override
  public Program currentProgramOrNull() {
    return script.getCurrentProgram();
  }

  @Override
  public FlatProgramAPI flatApi(Program pinnedProgram) {
    if (pinnedProgram != null && pinnedProgram != script.getCurrentProgram()) {
      return new FlatProgramAPI(pinnedProgram, TaskMonitor.DUMMY);
    }
    return script;
  }

  @Override
  public Program resolveTransactionProgram(Program explicitProgram) {
    return explicitProgram != null ? explicitProgram : script.getCurrentProgram();
  }

  @Override
  public int beginTransaction(Program program) {
    if (program != null && program != script.getCurrentProgram()) {
      return program.startTransaction("Ghidra Bridge");
    }
    script.end(true);
    script.start();
    return 0;
  }

  @Override
  public void finishTransaction(Program program, int transactionId, boolean commit) {
    if (program != null && program != script.getCurrentProgram()) {
      program.endTransaction(transactionId, commit);
      return;
    }
    try {
      script.end(commit);
    } finally {
      script.start();
    }
  }

  @Override
  public boolean requiresCommandTransaction() {
    return false;
  }

  @Override
  public boolean runCommand(Program program, Command<Program> command) {
    if (program != null && program != script.getCurrentProgram()) {
      return command.applyTo(program);
    }
    return script.runCommand(command);
  }

  @Override
  public void saveProgram(Program program) throws Exception {
    var monitor = script.getMonitor();
    boolean restoreCancellation = monitor != null && monitor.isCancelled();
    if (restoreCancellation) {
      monitor.clearCancelled();
    }
    try {
      try {
        script.end(true);
      } catch (Exception ignored) {
        // No ambient transaction exists, or the transaction ended.
      }
      script.saveProgram(program);
    } finally {
      if (restoreCancellation) {
        monitor.cancel();
      }
    }
  }
}

final class DynamicProgramHost implements ProgramHost {
  private final Supplier<Program> programSupplier;
  private Program cachedProgram;
  private FlatProgramAPI cachedApi;

  DynamicProgramHost(Supplier<Program> programSupplier) {
    this.programSupplier = Objects.requireNonNull(programSupplier, "programSupplier");
  }

  @Override
  public Program currentProgramOrNull() {
    return programSupplier.get();
  }

  @Override
  public synchronized FlatProgramAPI flatApi(Program pinnedProgram) {
    Program program = resolveTransactionProgram(pinnedProgram);
    if (program != cachedProgram || cachedApi == null) {
      cachedProgram = program;
      cachedApi = new FlatProgramAPI(program, TaskMonitor.DUMMY);
    }
    return cachedApi;
  }

  @Override
  public Program resolveTransactionProgram(Program explicitProgram) {
    if (explicitProgram != null) {
      return explicitProgram;
    }
    Program program = programSupplier.get();
    if (program == null) {
      throw new IllegalStateException("No current program is open in Ghidra");
    }
    return program;
  }

  @Override
  public int beginTransaction(Program program) {
    Program target = Objects.requireNonNull(program, "program");
    return target.startTransaction("Ghidra Bridge");
  }

  @Override
  public void finishTransaction(Program program, int transactionId, boolean commit) {
    Objects.requireNonNull(program, "program").endTransaction(transactionId, commit);
  }

  @Override
  public boolean requiresCommandTransaction() {
    return true;
  }

  @Override
  public boolean runCommand(Program program, Command<Program> command) {
    Program target = resolveTransactionProgram(program);
    return command.applyTo(target);
  }

  @Override
  public void saveProgram(Program program) throws Exception {
    if (program == null) {
      return;
    }
    DomainFile domainFile = program.getDomainFile();
    if (domainFile != null && domainFile.isInWritableProject() && program.canSave()) {
      program.save("Ghidra Bridge", TaskMonitor.DUMMY);
    }
  }

  @Override
  public synchronized void releaseProgram(Program program) {
    if (program != null && cachedProgram == program) {
      cachedProgram = null;
      cachedApi = null;
    }
  }
}
