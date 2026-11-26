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
  Program currentProgramOrNull();

  FlatProgramAPI flatApi(Program pinnedProgram);

  Program resolveTransactionProgram(Program explicitProgram);

  default int beginTransaction(Program program) {
    return beginTransaction(program, "bridge.write");
  }

  int beginTransaction(Program program, String description);

  void finishTransaction(Program program, int transactionId, boolean commit);

  boolean requiresCommandTransaction();

  boolean runCommand(Program program, Command<Program> command);

  void saveProgram(Program program) throws Exception;

  default void ensureIdle() {}

  default void releaseProgram(Program program) {}

  static ProgramHost forScript(GhidraScript script) {
    return new ScriptProgramHost(script);
  }

  static ProgramHost forProgramSupplier(Supplier<Program> programSupplier) {
    return new DynamicProgramHost(programSupplier);
  }

  static String normalizeTransactionName(String description) {
    return description == null || description.isBlank() ? "bridge.write" : description;
  }
}

final class ScriptProgramHost implements ProgramHost {
  private final GhidraScript script;

  ScriptProgramHost(GhidraScript script) {
    this.script = Objects.requireNonNull(script, "script");
    endAmbientScriptTransaction();
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
  public int beginTransaction(Program program, String description) {
    endAmbientScriptTransaction();
    if (program == null) {
      return -1;
    }
    return program.startTransaction(ProgramHost.normalizeTransactionName(description));
  }

  @Override
  public void finishTransaction(Program program, int transactionId, boolean commit) {
    if (program != null) {
      program.endTransaction(transactionId, commit);
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
      endAmbientScriptTransaction();
      script.saveProgram(program);
    } finally {
      endAmbientScriptTransaction();
      if (restoreCancellation) {
        monitor.cancel();
      }
    }
  }

  @Override
  public void ensureIdle() {
    endAmbientScriptTransaction();
  }

  private void endAmbientScriptTransaction() {
    try {
      script.end(true);
    } catch (Exception ignored) {
      // No ambient script transaction is active.
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
  public int beginTransaction(Program program, String description) {
    Program target = Objects.requireNonNull(program, "program");
    return target.startTransaction(ProgramHost.normalizeTransactionName(description));
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
