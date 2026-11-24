package app.byteland.ghidra.adapter.ghidra.program;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.GhidraTestSupport;
import app.byteland.ghidra.adapter.ghidra.GhidraTestSupport.ProgramHolder;
import app.byteland.ghidra.adapter.ghidra.function.FunctionServiceImpl;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.FunctionService.FunctionQuery;
import app.byteland.ghidra.service.program.ExportResource;
import app.byteland.ghidra.service.program.ImportResource;
import app.byteland.ghidra.service.program.ProgramService.ExportQuery;
import app.byteland.ghidra.service.program.ProgramService.ImportQuery;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;
import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ProgramEntryQueriesTest {

  @Test
  void listsImportsExportsEntryPointsAndExternalFunctionsDeterministically() {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("program_entries_test")) {
      holder.inTransaction(
          program -> {
            AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
            Address base = space.getAddress(0x10000L);
            byte[] bytes = new byte[0x100];
            bytes[0x00] = (byte) 0xc3;
            bytes[0x10] = (byte) 0xc3;
            bytes[0x20] = (byte) 0xe9;
            bytes[0x30] = (byte) 0xe9;
            bytes[0x40] = (byte) 0xc3;
            program
                .getMemory()
                .createInitializedBlock(
                    ".text",
                    base,
                    new ByteArrayInputStream(bytes),
                    bytes.length,
                    TaskMonitor.DUMMY,
                    false);

            FunctionManager fm = program.getFunctionManager();
            ExternalManager em = program.getExternalManager();
            SymbolTable st = program.getSymbolTable();

            ExternalLocation putsLoc =
                em.addExtFunction("libc.so.6", "puts", null, SourceType.IMPORTED);
            fm.createThunkFunction(
                "puts_thunk_hi",
                program.getGlobalNamespace(),
                base.add(0x30),
                new AddressSet(base.add(0x30), base.add(0x34)),
                putsLoc.getFunction(),
                SourceType.IMPORTED);
            fm.createThunkFunction(
                "puts_thunk_lo",
                program.getGlobalNamespace(),
                base.add(0x20),
                new AddressSet(base.add(0x20), base.add(0x24)),
                putsLoc.getFunction(),
                SourceType.IMPORTED);

            ExternalLocation ordLoc =
                em.addExtFunction("KERNEL32.DLL", "Ordinal_42", null, SourceType.IMPORTED);
            ordLoc.setName(ordLoc.getParentNameSpace(), "Sleep", SourceType.USER_DEFINED);

            em.addExtLocation("libdata.so", "global_errno", null, SourceType.IMPORTED);

            Function exportedFn =
                fm.createFunction(
                    "ExportedInit",
                    base,
                    new AddressSet(base, base),
                    SourceType.USER_DEFINED);
            st.addExternalEntryPoint(exportedFn.getEntryPoint());
            st.createLabel(base, "ExportedInitAlias", SourceType.USER_DEFINED);
            st.createLabel(base, "Ordinal_7", SourceType.IMPORTED);

            Namespace apiNs =
                st.createNameSpace(program.getGlobalNamespace(), "api", SourceType.USER_DEFINED);
            Address dataExport = base.add(0x10);
            st.createLabel(dataExport, "ApiTable", apiNs, SourceType.USER_DEFINED);
            st.addExternalEntryPoint(dataExport);

            fm.createFunction(
                "InternalOnly",
                base.add(0x40),
                new AddressSet(base.add(0x40), base.add(0x40)),
                SourceType.USER_DEFINED);
          });

      ProgramServiceImpl programService =
          new ProgramServiceImpl(GhidraTestSupport.sessionFor(holder.program()));
      FunctionServiceImpl functionService =
          new FunctionServiceImpl(GhidraTestSupport.sessionFor(holder.program()));

      List<ImportResource> pagedImports = new ArrayList<>();
      String importCursor = null;
      while (true) {
        Page<ImportResource> page =
            programService.listImports(
                new ImportQuery(null, null, false, null, null, 1, importCursor));
        pagedImports.addAll(page.items());
        importCursor = page.nextCursor();
        if (importCursor == null) break;
      }
      assertEquals(3, pagedImports.size());

      ImportResource puts = pagedImports.get(0);
      assertEquals("puts", puts.name());
      assertEquals("libc.so.6", puts.library());
      assertTrue(puts.isFunction());
      assertNotNull(puts.signature());
      assertEquals(List.of("ram:00010020", "ram:00010030"), puts.thunkAddresses());

      ImportResource sleep = pagedImports.get(1);
      assertEquals("Sleep", sleep.name());
      assertEquals("KERNEL32.DLL", sleep.library());
      assertEquals("Ordinal_42", sleep.originalName());
      assertEquals(42, sleep.ordinal());
      assertTrue(sleep.isFunction());

      ImportResource dataImport = pagedImports.get(2);
      assertEquals("global_errno", dataImport.name());
      assertEquals("libdata.so", dataImport.library());
      assertFalse(dataImport.isFunction());
      assertNull(dataImport.signature());

      Page<ImportResource> filteredImports =
          programService.listImports(
              new ImportQuery(null, "kernel32", false, "^sl.*p$", null, 10, null));
      assertEquals(List.of("Sleep"), filteredImports.items().stream().map(ImportResource::name).toList());

      assertThrows(
          IllegalArgumentException.class,
          () ->
              programService.listImports(
                  new ImportQuery(null, null, false, null, null, 10, "bad-cursor")));

      Page<ExportResource> exportsPage1 =
          programService.listExports(new ExportQuery(null, null, false, null, null, 2, null));
      assertEquals(
          List.of("ExportedInit", "ExportedInitAlias"),
          exportsPage1.items().stream().map(ExportResource::name).toList());
      assertEquals(7, exportsPage1.items().get(0).ordinal());
      assertEquals(7, exportsPage1.items().get(1).ordinal());
      assertTrue(exportsPage1.items().get(0).isFunction());
      assertNotNull(exportsPage1.nextCursor());

      Page<ExportResource> exportsPage2 =
          programService.listExports(
              new ExportQuery(null, null, false, null, null, 2, exportsPage1.nextCursor()));
      assertEquals(
          List.of("ApiTable"), exportsPage2.items().stream().map(ExportResource::name).toList());
      assertEquals("api", exportsPage2.items().get(0).namespace());
      assertFalse(exportsPage2.items().get(0).isFunction());
      assertNull(exportsPage2.nextCursor());

      Page<ExportResource> entryPoints =
          programService.listEntryPoints(new ExportQuery(null, null, false, null, null, 10, null));
      assertEquals(
          List.of("ExportedInit", "ApiTable"),
          entryPoints.items().stream().map(ExportResource::name).toList());

      Page<FunctionResource> extFnPage1 =
          functionService.listFunctions(
              new FunctionQuery(
                  AddressScanOptions.of(null, null, 1000),
                  1,
                  null,
                  null,
                  null,
                  null,
                  true,
                  null,
                  Set.of()));
      assertEquals(1, extFnPage1.items().size());
      assertEquals("puts", extFnPage1.items().getFirst().name());
      assertNotNull(extFnPage1.nextCursor());

      Page<FunctionResource> extFnPage2 =
          functionService.listFunctions(
              new FunctionQuery(
                  AddressScanOptions.of(null, null, 1000),
                  5,
                  extFnPage1.nextCursor(),
                  null,
                  null,
                  null,
                  true,
                  null,
                  Set.of()));
      assertEquals(
          List.of("Sleep"), extFnPage2.items().stream().map(FunctionResource::name).toList());
      assertNull(extFnPage2.nextCursor());

      FunctionResource resolvedPuts = functionService.getFunction(puts.address(), Set.of());
      assertEquals("puts", resolvedPuts.name());
      assertTrue(resolvedPuts.external());
    }
  }
}
