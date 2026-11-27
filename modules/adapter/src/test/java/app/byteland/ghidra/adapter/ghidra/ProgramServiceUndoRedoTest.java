package app.byteland.ghidra.adapter.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.program.ProgramServiceImpl;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.comment.CommentResource;
import app.byteland.ghidra.service.program.ProgramHistoryConflictException;
import app.byteland.ghidra.service.program.ProgramHistoryResource;
import app.byteland.ghidra.service.program.ProgramUndoRedoResult;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import java.util.List;
import org.junit.jupiter.api.Test;

class ProgramServiceUndoRedoTest {
  @Test
  void closesInitialScriptTransactionAndSupportsNamedTransactionsUndoAndRedo() throws Exception {
    try (GhidraTestSupport.ProgramHolder holder = GhidraTestSupport.createX64Program("undo-test")) {
      ProgramDB program = holder.program();
      Address base = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x00100000L);
      holder.inTransaction(
          db ->
              db.getMemory()
                  .createInitializedBlock(
                      "ram_block", base, 0x100, (byte) 0x90, TaskMonitor.DUMMY, false));
      program.clearUndo();

      ScriptWithOpenInitialTransaction script = new ScriptWithOpenInitialTransaction(program);
      assertNotNull(program.getCurrentTransactionInfo());

      BridgeServices services = GhidraServiceFactory.create(script);
      assertNull(program.getCurrentTransactionInfo());

      ProgramHistoryResource initial = services.programService().getHistory();
      assertFalse(initial.canUndo());
      assertFalse(initial.canRedo());
      assertNull(initial.undoName());
      assertNull(initial.redoName());
      assertEquals(List.of(), initial.undoList());
      assertEquals(List.of(), initial.redoList());

      ProgramHistoryConflictException emptyUndo =
          assertThrows(
              ProgramHistoryConflictException.class, () -> services.programService().undo());
      assertEquals("nothing_to_undo", emptyUndo.code());

      ProgramHistoryConflictException emptyRedo =
          assertThrows(
              ProgramHistoryConflictException.class, () -> services.programService().redo());
      assertEquals("nothing_to_redo", emptyRedo.code());

      services
          .transactionRunner()
          .run(
              "comment.create",
              () -> {
                services
                    .commentService()
                    .setComment("ram:00100000", CommentResource.Type.PRE, "first comment");
                return null;
              });
      assertNull(program.getCurrentTransactionInfo());

      ProgramHistoryResource afterComment = services.programService().getHistory();
      assertTrue(afterComment.canUndo());
      assertFalse(afterComment.canRedo());
      assertEquals("comment.create", afterComment.undoName());
      assertEquals(List.of("comment.create"), afterComment.undoList());

      services
          .transactionRunner()
          .run(
              "batch.execute",
              () -> {
                services
                    .commentService()
                    .setComment("ram:00100004", CommentResource.Type.EOL, "batch comment");
                program
                    .getSymbolTable()
                    .createLabel(base, "entry_label", SourceType.USER_DEFINED);
                return null;
              });

      ProgramHistoryResource afterBatch = services.programService().getHistory();
      assertTrue(afterBatch.canUndo());
      assertEquals("batch.execute", afterBatch.undoName());
      assertEquals(List.of("batch.execute", "comment.create"), afterBatch.undoList());

      ProgramUndoRedoResult undoneBatch = services.programService().undo();
      assertEquals("undo", undoneBatch.action());
      assertEquals("batch.execute", undoneBatch.transactionName());
      assertTrue(undoneBatch.canUndo());
      assertTrue(undoneBatch.canRedo());
      assertEquals("comment.create", undoneBatch.undoName());
      assertEquals("batch.execute", undoneBatch.redoName());
      assertNull(program.getSymbolTable().getPrimarySymbol(base));
      assertEquals("first comment", program.getListing().getComment(CommentType.PRE, base));

      ProgramUndoRedoResult redoneBatch = services.programService().redo();
      assertEquals("redo", redoneBatch.action());
      assertEquals("batch.execute", redoneBatch.transactionName());
      assertTrue(redoneBatch.canUndo());
      assertFalse(redoneBatch.canRedo());
      assertEquals("entry_label", program.getSymbolTable().getPrimarySymbol(base).getName());

      GhidraSession session = new GhidraSession(script);
      ProgramServiceImpl directService = new ProgramServiceImpl(session);
      ProgramHistoryConflictException inTx =
          session.withTransaction(
              "outer.tx",
              () -> assertThrows(ProgramHistoryConflictException.class, directService::undo));
      assertEquals("transaction_in_progress", inTx.code());
    }
  }

  @Test
  void supportsNamedTransactionsUndoAndRedoForDynamicProgramHost() throws Exception {
    try (GhidraTestSupport.ProgramHolder holder =
        GhidraTestSupport.createX64Program("dynamic-undo-test")) {
      ProgramDB program = holder.program();
      Address base = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x00100000L);
      holder.inTransaction(
          db ->
              db.getMemory()
                  .createInitializedBlock(
                      "ram_block", base, 0x100, (byte) 0x90, TaskMonitor.DUMMY, false));
      program.clearUndo();

      GhidraSession session = new GhidraSession(() -> program);
      try (BridgeServices services = GhidraServiceFactory.create(session, "gui-fallback")) {
        services
            .transactionRunner()
            .run(
                "comment.create",
                () -> {
                  services
                      .commentService()
                      .setComment("ram:00100000", CommentResource.Type.PRE, "dynamic comment");
                  return null;
                });
        assertNull(program.getCurrentTransactionInfo());
        assertEquals(List.of("comment.create"), services.programService().getHistory().undoList());

        session
            .querySnapshots()
            .put(
                QuerySnapshotCache.Key.of("symbol", session.modificationNumber(), ""),
                new String[] {"1"});
        assertEquals(1, session.querySnapshots().entryCount());

        ProgramUndoRedoResult undone = services.programService().undo();
        assertEquals("comment.create", undone.transactionName());
        assertNull(program.getListing().getComment(CommentType.PRE, base));
        assertEquals(0, session.querySnapshots().entryCount());

        session
            .querySnapshots()
            .put(
                QuerySnapshotCache.Key.of("symbol", session.modificationNumber(), ""),
                new String[] {"1"});
        assertEquals(1, session.querySnapshots().entryCount());

        ProgramUndoRedoResult redone = services.programService().redo();
        assertEquals("comment.create", redone.transactionName());
        assertEquals("dynamic comment", program.getListing().getComment(CommentType.PRE, base));
        assertEquals(0, session.querySnapshots().entryCount());
      }
    }
  }

  private static final class ScriptWithOpenInitialTransaction extends GhidraScript {
    private ScriptWithOpenInitialTransaction(Program program) {
      set(program, TaskMonitor.DUMMY);
      start();
    }

    @Override
    protected void run() {}
  }
}
