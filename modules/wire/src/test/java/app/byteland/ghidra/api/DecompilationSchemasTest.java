package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.decompilation.DecompilationResource;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.function.VariableStorageReference;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class DecompilationSchemasTest {
  @Test
  void acceptsNativeLayoutAndCommentResults() {
    Map<String, Object> line = Map.of(
        "number", 0, "indent", 2, "tokens", List.of(Map.of(
            "kind", "keyword", "text", "return", "start", 2, "end", 8,
            "location_address", "ram:1008", "code_unit_address", "ram:1008")));
    assertDoesNotThrow(() -> WireSchema.validate(
        List.of(line), ApiSchemaCatalog.outputFieldSchema("lines"), "/lines"));
    assertDoesNotThrow(() -> WireSchema.validate(
        List.of(Map.of("address", "ram:1008", "type", "repeatable", "text", "note")),
        ApiSchemaCatalog.outputFieldSchema("comments"), "/comments"));
    assertDoesNotThrow(() -> WireSchema.validate(
        true, ApiSchemaCatalog.outputFieldSchema("comments_complete"), "/comments_complete"));
    assertThrows(ApiException.class, () -> WireSchema.validate(
        List.of(Map.of("number", 0, "indent", 0, "tokens", List.of(Map.of("text", "bad")))),
        ApiSchemaCatalog.outputFieldSchema("lines"), "/lines"));
  }

  @Test
  void dispatchesIncludeLocalsAndOmitsLocalVariablesByDefault() throws Exception {
    DecompilationService decompilation =
        new DecompilationService() {
          @Override
          public DecompilationResource decompileFunction(
              String rawAddress,
              DecompilationResource.Format format,
              Integer timeoutMs,
              boolean includeComments,
              boolean includeLocals) {
            return new DecompilationResource(
                "ram:00101000",
                "demo",
                format,
                true,
                3L,
                "int demo(void) { return 0; }\n",
                null,
                null,
                null,
                null,
                includeLocals
                    ? List.of(
                        new FunctionResource.LocalVariableResource(
                            "local_10",
                            DataTypeReference.named("/int"),
                            VariableStorageReference.serialization("stack:-0x10:4")))
                    : null,
                List.of());
          }

          @Override
          public void close() {}
        };
    BridgeServices services =
        new BridgeServices(
            unused(ProgramService.class),
            unused(AddressService.class),
            unused(CommentService.class),
            unused(ReferenceService.class),
            unused(MemoryService.class),
            unused(ListingService.class),
            unused(FunctionService.class),
            unused(GlobalVariableService.class),
            unused(AnalysisService.class),
            decompilation,
            unused(SymbolService.class),
            unused(DataTypeService.class),
            new TransactionRunner() {
              @Override
              public <T> T run(Operation<T> operation) {
                try {
                  return operation.execute();
                } catch (Exception ex) {
                  throw new RuntimeException(ex);
                }
              }
            },
            "test");
    ApiRegistry registry = new ApiRegistry(services, "test", Map::of, () -> {});

    Map<?, ?> defaultResult =
        (Map<?, ?>)
            registry.dispatch("decompilation.get", Map.of("selector", Map.of("entry", "0x101000")));
    assertFalse(defaultResult.containsKey("local_variables"));

    Map<?, ?> withLocalsResult =
        (Map<?, ?>)
            registry.dispatch(
                "decompilation.get",
                Map.of("selector", Map.of("entry", "0x101000"), "include_locals", true));
    assertEquals(
        List.of(
            Map.of(
                "name", "local_10",
                "data_type", Map.of("kind", "named", "name", "/int"),
                "storage", Map.of("kind", "serialization", "serialization", "stack:-0x10:4"))),
        withLocalsResult.get("local_variables"));
  }

  private static <T> T unused(Class<T> type) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> {
              throw new AssertionError(method.getName());
            }));
  }
}
