package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressResource.FunctionSummary;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ExportResource;
import app.byteland.ghidra.service.program.ImportResource;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.program.ProgramService.ExportQuery;
import app.byteland.ghidra.service.program.ProgramService.ImportQuery;
import app.byteland.ghidra.service.program.ProgramTextMatcher;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class ProgramEntryMethodsTest {
  @Test
  void importExportAndEntryPointMethodsAreReadOnlyAndPaginated() throws Exception {
    AtomicInteger transactions = new AtomicInteger();
    List<ImportResource> sampleImports =
        List.of(
            new ImportResource(
                "EXTERNAL:00000001",
                "libc.so.6",
                "puts",
                null,
                null,
                null,
                List.of("ram:00101030"),
                "int puts(char * s)",
                true),
            new ImportResource(
                "EXTERNAL:00000002",
                "libstdc++.so.6",
                "_ZN3foo3barEv",
                "_ZN3foo3barEv",
                "foo::bar()",
                12,
                List.of("ram:00101040"),
                "void bar(void)",
                true));
    List<ExportResource> sampleExports =
        List.of(
            new ExportResource(
                "ram:80000000",
                "export_low",
                null,
                "Global",
                true,
                new FunctionSummary("ram:80000000", "export_low"),
                1),
            new ExportResource(
                "ram:100000000",
                "export_high",
                "ns::export_high()",
                "ns",
                false,
                null,
                null));

    ProgramService program =
        proxy(
            ProgramService.class,
            (method, args) -> {
              if ("listImports".equals(method)) {
                ImportQuery query = (ImportQuery) args[0];
                ProgramTextMatcher nameMatcher =
                    ProgramTextMatcher.compile(
                        query.name(), query.regex(), query.nameRegex(), "name");
                ProgramTextMatcher libMatcher =
                    ProgramTextMatcher.compile(
                        query.library(), query.regex(), query.libraryRegex(), "library");
                List<ImportResource> filtered =
                    sampleImports.stream()
                        .filter(i -> nameMatcher == null || nameMatcher.matches(i.name()))
                        .filter(i -> libMatcher == null || libMatcher.matches(i.library()))
                        .toList();
                return Page.paginate(
                    filtered,
                    query.limit(),
                    query.cursor(),
                    i -> i.address() + '\0' + i.library() + '\0' + i.name());
              }
              if ("listExports".equals(method) || "listEntryPoints".equals(method)) {
                ExportQuery query = (ExportQuery) args[0];
                return Page.paginate(
                    sampleExports,
                    query.limit(),
                    query.cursor(),
                    e -> e.address() + '\0' + e.name());
              }
              throw new AssertionError(method);
            });

    ApiRegistry registry = buildRegistry(program, transactions);

    for (String methodName : List.of("import.list", "export.list", "entry_point.list")) {
      ApiMethod<?, ?> method = registry.method(methodName);
      assertNotNull(method);
      assertTrue(method.effects().readOnly());
      assertFalse(method.effects().mutatesProgram());
      assertFalse(method.effects().requiresTransaction());
      assertTrue(method.effects().allowedDuringAnalysis());
    }

    Map<?, ?> page1 =
        (Map<?, ?>) registry.dispatch("import.list", Map.of("page", Map.of("limit", 1)));
    List<?> items1 = (List<?>) page1.get("items");
    assertEquals(1, items1.size());
    assertEquals("puts", ((Map<?, ?>) items1.get(0)).get("name"));
    String cursor = (String) page1.get("next_cursor");
    assertNotNull(cursor);

    Map<?, ?> page2 =
        (Map<?, ?>)
            registry.dispatch(
                "import.list", Map.of("page", Map.of("limit", 1, "cursor", cursor)));
    List<?> items2 = (List<?>) page2.get("items");
    assertEquals(1, items2.size());
    assertEquals("_ZN3foo3barEv", ((Map<?, ?>) items2.get(0)).get("name"));
    assertEquals("foo::bar()", ((Map<?, ?>) items2.get(0)).get("demangled_name"));
    assertFalse(page2.containsKey("next_cursor"));

    Map<?, ?> filtered =
        (Map<?, ?>)
            registry.dispatch(
                "import.list",
                Map.of("filter", Map.of("library", "LIBSTDC", "name_regex", "^_ZN3foo.*$")));
    assertEquals(1, ((List<?>) filtered.get("items")).size());

    Map<?, ?> exports = (Map<?, ?>) registry.dispatch("export.list", Map.of());
    List<?> exportItems = (List<?>) exports.get("items");
    assertEquals(2, exportItems.size());
    assertEquals("ram:80000000", ((Map<?, ?>) exportItems.get(0)).get("address"));
    assertEquals("ram:100000000", ((Map<?, ?>) exportItems.get(1)).get("address"));

    Map<?, ?> entries = (Map<?, ?>) registry.dispatch("entry_point.list", Map.of());
    assertEquals(2, ((List<?>) entries.get("items")).size());
    assertEquals(0, transactions.get());
  }

  @Test
  void invalidAndOverlongRegexesReturnClient400Errors() {
    ProgramService program =
        proxy(
            ProgramService.class,
            (method, args) -> Page.of(List.of(), 100, null));
    ApiRegistry registry = buildRegistry(program, new AtomicInteger());

    Throwable syntaxFailure =
        assertThrows(
            Throwable.class,
            () ->
                registry.dispatch(
                    "import.list", Map.of("filter", Map.of("name", "[unclosed", "regex", true))));
    ApiFailures.Failure normalizedSyntax = ApiFailures.normalize(syntaxFailure);
    assertEquals(400, normalizedSyntax.status());
    assertEquals("invalid_regex", normalizedSyntax.error().code());
    assertEquals("/filter/name", normalizedSyntax.error().target());

    String overlong = "a".repeat(ProgramTextMatcher.MAX_REGEX_LENGTH + 1);
    Throwable lengthFailure =
        assertThrows(
            Throwable.class,
            () ->
                registry.dispatch(
                    "import.list", Map.of("filter", Map.of("library_regex", overlong))));
    ApiFailures.Failure normalizedLength = ApiFailures.normalize(lengthFailure);
    assertEquals(400, normalizedLength.status());
    assertEquals("invalid_regex", normalizedLength.error().code());
    assertEquals("/filter/library_regex", normalizedLength.error().target());

    ProgramTextMatcher backtracking =
        ProgramTextMatcher.compile(null, false, "^.*a.*a.*a.*a.*z$", "name");
    Throwable stepFailure =
        assertThrows(
            Throwable.class, () -> backtracking.matches("a".repeat(30)));
    ApiFailures.Failure normalizedStep = ApiFailures.normalize(stepFailure);
    assertEquals(400, normalizedStep.status());
    assertEquals("invalid_regex", normalizedStep.error().code());
  }

  private static ApiRegistry buildRegistry(ProgramService program, AtomicInteger transactions) {
    AnalysisService analysis =
        proxy(
            AnalysisService.class,
            (method, args) ->
                new AnalysisResource(
                    AnalysisResource.Kind.GHIDRA,
                    AnalysisResource.Status.IDLE,
                    false,
                    null,
                    null,
                    null,
                    null));
    TransactionRunner transaction =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            transactions.incrementAndGet();
            try {
              return operation.execute();
            } catch (Exception ex) {
              throw new RuntimeException(ex);
            }
          }
        };
    BridgeServices services =
        new BridgeServices(
            program,
            unused(AddressService.class),
            unused(CommentService.class),
            unused(ReferenceService.class),
            unused(MemoryService.class),
            unused(ListingService.class),
            unused(FunctionService.class),
            unused(GlobalVariableService.class),
            analysis,
            unused(DecompilationService.class),
            unused(SymbolService.class),
            unused(DataTypeService.class),
            transaction,
            "test");
    return new ApiRegistry(services, "test", Map::of, () -> {});
  }

  private interface Handler {
    Object invoke(String method, Object[] args);
  }

  private static <T> T unused(Class<T> type) {
    return proxy(
        type,
        (method, args) -> {
          throw new AssertionError(method);
        });
  }

  private static <T> T proxy(Class<T> type, Handler handler) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> handler.invoke(method.getName(), args)));
  }
}
