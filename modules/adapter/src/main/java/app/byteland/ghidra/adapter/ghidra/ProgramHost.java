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
 * Supplies the active Ghidra program and manages transactions for script or GUI hosts.
 */
public interface ProgramHost {
  Program currentProgramOrNull();

  FlatProgramAPI flatApi();

  GhidraScript scriptOrNull();

  int beginTransaction(Program program);

  void finishTransaction(Program program, int transactionId, boolean commit);

  boolean runCommand(Program program, Command<Program> command);

  void saveProgram(Program program) throws Exception;

  static ProgramHost forScript(GhidraScript script) {
    return new ScriptProgramHost(script);
  }

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
  public FlatProgramAPI flatApi() {
    return script;
  }

  @Override
  public GhidraScript scriptOrNull() {
    return script;
  }

  @Override
  public int beginTransaction(Program program) {
    script.end(true);
    script.start();
    return 0;
  }

  @Override
  public void finishTransaction(Program program, int transactionId, boolean commit) {
    try {
      script.end(commit);
    } finally {
      script.start();
    }
  }

  @Override
  public boolean runCommand(Program program, Command<Program> command) {
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
  public synchronized FlatProgramAPI flatApi() {
    Program program = programSupplier.get();
    if (program == null) {
      throw new IllegalStateException("No current program is open in Ghidra");
    }
    if (program != cachedProgram || cachedApi == null) {
      cachedProgram = program;
      cachedApi = new FlatProgramAPI(program, TaskMonitor.DUMMY);
    }
    return cachedApi;
  }

  @Override
  public GhidraScript scriptOrNull() {
    return null;
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
  public boolean runCommand(Program program, Command<Program> command) {
    Program target = program != null ? program : currentProgramOrNull();
    if (target == null) {
      throw new IllegalStateException("No current program is open in Ghidra");
    }
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
}
