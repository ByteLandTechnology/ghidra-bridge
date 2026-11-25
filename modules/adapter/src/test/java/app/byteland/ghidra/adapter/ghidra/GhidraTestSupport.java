package app.byteland.ghidra.adapter.ghidra;

import ghidra.GhidraApplicationLayout;
import ghidra.app.plugin.processors.sleigh.SleighLanguageProvider;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.net.URISyntaxException;
import java.util.concurrent.atomic.AtomicInteger;

public final class GhidraTestSupport {
  private static final Object LANGUAGE_LOCK = new Object();
  private static Language cachedX64Language;

  private GhidraTestSupport() {}

  public static Language x64Language() {
    synchronized (LANGUAGE_LOCK) {
      if (cachedX64Language != null) {
        return cachedX64Language;
      }
      if (!Application.isInitialized()) {
        File installDir = locateGhidraInstallDir();
        ApplicationConfiguration config = new ApplicationConfiguration();
        config.setInitializeLogging(false);
        try {
          Application.initializeApplication(new GhidraApplicationLayout(installDir), config);
        } catch (IOException error) {
          throw new IllegalStateException("Failed to initialize Ghidra application", error);
        }
      }
      cachedX64Language =
          SleighLanguageProvider.getSleighLanguageProvider()
              .getLanguage(new LanguageID("x86:LE:64:default"));
      if (cachedX64Language == null) {
        throw new IllegalStateException("x86:LE:64:default language not found");
      }
      return cachedX64Language;
    }
  }

  public static ProgramHolder createX64Program(String name) {
    try {
      Language language = x64Language();
      CompilerSpec compilerSpec = language.getDefaultCompilerSpec();
      Object consumer = new Object();
      ProgramDB program = new ProgramDB(name, language, compilerSpec, consumer);
      return new ProgramHolder(program, consumer);
    } catch (IOException error) {
      throw new IllegalStateException("Failed to create test ProgramDB", error);
    }
  }

  public static GhidraSession sessionFor(Program program) {
    return new GhidraSession(new HeadlessTestScript(program));
  }

  private static File locateGhidraInstallDir() {
    String envDir = System.getenv("GHIDRA_INSTALL_DIR");
    if (envDir != null && !envDir.isBlank()) {
      File candidate = new File(envDir);
      if (new File(candidate, "Ghidra/application.properties").isFile()) {
        return candidate;
      }
    }
    try {
      File current =
          new File(ProgramDB.class.getProtectionDomain().getCodeSource().getLocation().toURI());
      while (current != null) {
        if (new File(current, "Ghidra/application.properties").isFile()) {
          return current;
        }
        current = current.getParentFile();
      }
    } catch (URISyntaxException error) {
      throw new IllegalStateException("Unable to inspect ProgramDB code source", error);
    }
    throw new IllegalStateException("Unable to locate Ghidra installation directory");
  }

  private static final class HeadlessTestScript extends GhidraScript {
    private HeadlessTestScript(Program program) {
      set(program, TaskMonitor.DUMMY);
    }

    @Override
    protected void run() {}
  }

  public record ProgramHolder(ProgramDB program, Object consumer) implements AutoCloseable {
    public void inTransaction(TransactionalSetup setup) {
      int tx = program.startTransaction("test-setup");
      boolean commit = false;
      try {
        setup.run(program);
        commit = true;
      } catch (Exception error) {
        throw new IllegalStateException("Test program setup failed", error);
      } finally {
        program.endTransaction(tx, commit);
      }
    }

    @Override
    public void close() {
      program.release(consumer);
    }
  }

  @FunctionalInterface
  public interface TransactionalSetup {
    void run(ProgramDB program) throws Exception;
  }

  public static final class SeekSpy {
    public final AtomicInteger instructionIterators = new AtomicInteger();
    public final AtomicInteger definedDataIterators = new AtomicInteger();
    public final AtomicInteger codeUnitIterators = new AtomicInteger();
    public final AtomicInteger functionIterators = new AtomicInteger();
    public final AtomicInteger boundaryLookups = new AtomicInteger();
    public final AtomicInteger statelessAfterBeforeCalls = new AtomicInteger();

    public void reset() {
      instructionIterators.set(0);
      definedDataIterators.set(0);
      codeUnitIterators.set(0);
      functionIterators.set(0);
      boundaryLookups.set(0);
      statelessAfterBeforeCalls.set(0);
    }

    public Program wrap(Program delegate) {
      Listing realListing = delegate.getListing();
      FunctionManager realFunctionManager = delegate.getFunctionManager();

      Listing listingProxy =
          (Listing)
              Proxy.newProxyInstance(
                  Listing.class.getClassLoader(),
                  new Class<?>[] {Listing.class},
                  (proxy, method, args) -> {
                    switch (method.getName()) {
                      case "getInstructions" -> instructionIterators.incrementAndGet();
                      case "getDefinedData" -> definedDataIterators.incrementAndGet();
                      case "getCodeUnits" -> codeUnitIterators.incrementAndGet();
                      case "getInstructionAfter",
                          "getInstructionBefore",
                          "getDefinedDataAfter",
                          "getDefinedDataBefore",
                          "getDataAfter",
                          "getDataBefore",
                          "getUndefinedDataAfter",
                          "getUndefinedDataBefore",
                          "getFunctions" ->
                          statelessAfterBeforeCalls.incrementAndGet();
                      case "getCodeUnitAt",
                          "getCodeUnitContaining",
                          "getCodeUnitAfter",
                          "getCodeUnitBefore" ->
                          boundaryLookups.incrementAndGet();
                      default -> {}
                    }
                    try {
                      return method.invoke(realListing, args);
                    } catch (InvocationTargetException error) {
                      throw error.getTargetException();
                    }
                  });

      FunctionManager functionManagerProxy =
          (FunctionManager)
              Proxy.newProxyInstance(
                  FunctionManager.class.getClassLoader(),
                  new Class<?>[] {FunctionManager.class},
                  (proxy, method, args) -> {
                    switch (method.getName()) {
                      case "getFunctions" -> functionIterators.incrementAndGet();
                      case "getFunctionAt" -> boundaryLookups.incrementAndGet();
                      default -> {}
                    }
                    try {
                      return method.invoke(realFunctionManager, args);
                    } catch (InvocationTargetException error) {
                      throw error.getTargetException();
                    }
                  });

      return (Program)
          Proxy.newProxyInstance(
              Program.class.getClassLoader(),
              new Class<?>[] {Program.class},
              (proxy, method, args) -> {
                if ("getListing".equals(method.getName())) return listingProxy;
                if ("getFunctionManager".equals(method.getName())) return functionManagerProxy;
                try {
                  return method.invoke(delegate, args);
                } catch (InvocationTargetException error) {
                  throw error.getTargetException();
                }
              });
    }
  }
}
