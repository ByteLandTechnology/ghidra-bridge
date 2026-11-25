package app.byteland.ghidra.adapter.ghidra.analysis;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.GhidraTestSupport;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import ghidra.framework.cmd.Command;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class AnalysisServiceImplTest {

  @Test
  @DisplayName("Reads initial analyzed state at startup and avoids Program.getOptions on getStatus")
  void cachesInitialAnalyzedStateWithoutProgramReadsOnGetStatus() {
    try (GhidraTestSupport.ProgramHolder unanalyzedHolder =
        GhidraTestSupport.createX64Program("analysis-startup-false")) {
      AtomicInteger getOptionsCalls = new AtomicInteger();
      Program spiedUnanalyzed = spyGetOptions(unanalyzedHolder.program(), getOptionsCalls);
      GhidraSession unanalyzedSession = GhidraTestSupport.sessionFor(spiedUnanalyzed);

      try (AnalysisServiceImpl service = new AnalysisServiceImpl(unanalyzedSession)) {
        assertTrue(getOptionsCalls.get() >= 1);
        getOptionsCalls.set(0);

        for (int i = 0; i < 10; i++) {
          AnalysisResource status = service.getStatus();
          assertEquals(AnalysisResource.Kind.GHIDRA, status.kind());
          assertEquals(AnalysisResource.Status.IDLE, status.status());
          assertFalse(status.analyzed());
        }
        assertEquals(0, getOptionsCalls.get());
      }
    }

    try (GhidraTestSupport.ProgramHolder analyzedHolder =
        GhidraTestSupport.createX64Program("analysis-startup-true")) {
      analyzedHolder.inTransaction(GhidraProgramUtilities::markProgramAnalyzed);
      AtomicInteger getOptionsCalls = new AtomicInteger();
      Program spiedAnalyzed = spyGetOptions(analyzedHolder.program(), getOptionsCalls);
      GhidraSession analyzedSession = GhidraTestSupport.sessionFor(spiedAnalyzed);

      try (AnalysisServiceImpl service = new AnalysisServiceImpl(analyzedSession)) {
        getOptionsCalls.set(0);
        AnalysisResource status = service.getStatus();
        assertEquals(AnalysisResource.Kind.GHIDRA, status.kind());
        assertEquals(AnalysisResource.Status.IDLE, status.status());
        assertTrue(status.analyzed());
        assertEquals(0, getOptionsCalls.get());
      }
    }
  }

  @Test
  @DisplayName("Refreshes cached analyzed flag on GhidraSession commits and Program domain events")
  void refreshesAnalyzedFlagOnSessionCommitsAndDomainEvents() {
    try (GhidraTestSupport.ProgramHolder holder =
        GhidraTestSupport.createX64Program("analysis-refresh-events")) {
      GhidraSession session = GhidraTestSupport.sessionFor(holder.program());

      try (AnalysisServiceImpl service = new AnalysisServiceImpl(session)) {
        assertFalse(service.getStatus().analyzed());

        // Temporary changes roll back and keep analyzed false.
        session.withTemporaryChanges(
            () -> {
              GhidraProgramUtilities.markProgramAnalyzed(holder.program());
              return null;
            });
        assertFalse(service.getStatus().analyzed());

        // Committed session transaction refreshes analyzed to true immediately.
        session.withTransaction(
            () -> {
              GhidraProgramUtilities.markProgramAnalyzed(holder.program());
              return null;
            });
        assertTrue(service.getStatus().analyzed());

        // Standalone runCommand refreshes analyzed when it resets analysis flags.
        Command<Program> resetCommand =
            new Command<>() {
              @Override
              public boolean applyTo(Program program) {
                GhidraProgramUtilities.resetAnalysisFlags(program);
                return true;
              }

              @Override
              public String getStatusMsg() {
                return null;
              }

              @Override
              public String getName() {
                return "ResetAnalyzed";
              }
            };
        session.runCommand(resetCommand, "unable to reset analysis flags");
        assertFalse(service.getStatus().analyzed());

        // Direct ProgramDB change outside GhidraSession refreshes analyzed on flushEvents.
        holder.inTransaction(GhidraProgramUtilities::markProgramAnalyzed);
        holder.program().flushEvents();
        assertTrue(service.getStatus().analyzed());

        holder.inTransaction(GhidraProgramUtilities::resetAnalysisFlags);
        holder.program().flushEvents();
        assertFalse(service.getStatus().analyzed());
      }
    }
  }

  @Test
  @DisplayName("Updates status and cached analyzed flag across background AnalysisTask execution")
  void updatesStatusAndAnalyzedFlagAcrossAnalysisTaskCompletion() throws Exception {
    try (GhidraTestSupport.ProgramHolder holder =
        GhidraTestSupport.createX64Program("analysis-task-lifecycle")) {
      GhidraSession session = GhidraTestSupport.sessionFor(holder.program());

      try (AnalysisServiceImpl service = new AnalysisServiceImpl(session)) {
        assertFalse(service.getStatus().analyzed());

        AnalysisResource initial = service.startAnalysis(null);
        assertEquals(AnalysisResource.Kind.BRIDGE, initial.kind());
        assertNotNull(initial.taskId());
        assertNotNull(initial.startedAt());

        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
        AnalysisResource terminal = service.getStatus();
        while (terminal.status() == AnalysisResource.Status.RUNNING
            && System.nanoTime() - deadline < 0) {
          Thread.sleep(20);
          terminal = service.getStatus();
        }

        assertEquals(AnalysisResource.Kind.BRIDGE, terminal.kind());
        assertEquals(AnalysisResource.Status.COMPLETED, terminal.status());
        assertTrue(terminal.analyzed());
        assertEquals(initial.taskId(), terminal.taskId());
        assertNotNull(terminal.finishedAt());
      }
    }
  }

  private static Program spyGetOptions(Program delegate, AtomicInteger getOptionsCalls) {
    return (Program)
        Proxy.newProxyInstance(
            Program.class.getClassLoader(),
            new Class<?>[] {Program.class},
            (proxy, method, args) -> {
              if ("getOptions".equals(method.getName())) {
                getOptionsCalls.incrementAndGet();
              }
              try {
                return method.invoke(delegate, args);
              } catch (InvocationTargetException error) {
                throw error.getTargetException();
              }
            });
  }
}
