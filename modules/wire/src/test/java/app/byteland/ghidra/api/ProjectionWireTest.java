package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.ScanProgress;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressResource;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeCategoryResource;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeResource;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.datatype.FunctionSignature;
import app.byteland.ghidra.service.decompilation.DecompilationResource;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionCallResource;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.function.VariableStorageReference;
import app.byteland.ghidra.service.globalvariable.GlobalVariableResource;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.CodeUnitResource;
import app.byteland.ghidra.service.listing.DataUnitResource;
import app.byteland.ghidra.service.listing.FlowOverrideValue;
import app.byteland.ghidra.service.listing.InstructionResource;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.AddressSpaceResource;
import app.byteland.ghidra.service.program.ProgramLanguageResource;
import app.byteland.ghidra.service.program.ProgramResource;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolResource;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class ProjectionWireTest {

  private record RecordedCall(
      String service,
      String method,
      int argCount,
      Set<String> fields,
      Set<String> queryFields,
      Set<String> includes) {}

  @Test
  @SuppressWarnings("unchecked")
  void forwardsSelectedFieldsToDomainOverloadsAndCallsBaseMethodsWhenUnprojected()
      throws Exception {
    AtomicReference<RecordedCall> lastCall = new AtomicReference<>();
    ApiRegistry registry = buildRecordingRegistry(lastCall);

    record Case(
        String wireMethod,
        Map<String, Object> baseParams,
        String projectionField,
        String serviceName,
        String domainMethod,
        int baseArity,
        List<String> expectedSelectedFields,
        boolean hasQueryFields) {}

    List<Case> cases =
        List.of(
            new Case(
                "program.get",
                Map.of(),
                "executable_format",
                "ProgramService",
                "getProgram",
                0,
                List.of("name", "executable_format"),
                false),
            new Case(
                "program_language.get",
                Map.of(),
                "processor",
                "ProgramService",
                "getLanguageInfo",
                0,
                List.of("language_id", "processor"),
                false),
            new Case(
                "address_space.list",
                Map.of(),
                "kind",
                "ProgramService",
                "getAddressSpaces",
                2,
                List.of("name", "kind"),
                false),
            new Case(
                "address.resolve",
                Map.of("selector", Map.of("address", "0x00101000")),
                "in_memory",
                "AddressService",
                "resolveAddress",
                1,
                List.of("address", "in_memory"),
                false),
            new Case(
                "code_unit.list",
                Map.of(),
                "kind",
                "ListingService",
                "listCodeUnits",
                4,
                List.of("address", "kind"),
                false),
            new Case(
                "data_unit.list",
                Map.of(),
                "length",
                "ListingService",
                "listDataUnits",
                3,
                List.of("address", "length"),
                false),
            new Case(
                "instruction.get",
                Map.of("selector", Map.of("address", "0x00101000")),
                "mnemonic",
                "ListingService",
                "getInstruction",
                1,
                List.of("address", "mnemonic"),
                false),
            new Case(
                "instruction.list",
                Map.of(),
                "mnemonic",
                "ListingService",
                "listInstructions",
                3,
                List.of("address", "mnemonic"),
                false),
            new Case(
                "flow_override.list",
                Map.of(
                    "filter",
                    Map.of("selector", Map.of("kind", "address", "address", "0x00101000"))),
                "flow_override",
                "ListingService",
                "getFlowOverrides",
                5,
                List.of("address", "flow_override"),
                false),
            new Case(
                "global_variable.get",
                Map.of("selector", Map.of("address", "0x00200000")),
                "name",
                "GlobalVariableService",
                "getGlobalVariable",
                1,
                List.of("address", "name"),
                false),
            new Case(
                "global_variable.list",
                Map.of(),
                "name",
                "GlobalVariableService",
                "listGlobalVariables",
                1,
                List.of("address", "name"),
                true),
            new Case(
                "function.get",
                Map.of("selector", Map.of("entry", "0x00101000")),
                "name",
                "FunctionService",
                "getFunction",
                2,
                List.of("entry", "name"),
                false),
            new Case(
                "function.list",
                Map.of(),
                "name",
                "FunctionService",
                "listFunctions",
                1,
                List.of("entry", "name"),
                true),
            new Case(
                "function_call.list",
                Map.of("filter", Map.of("entry", "0x00101000", "direction", "callers")),
                "name",
                "FunctionService",
                "getCallers",
                3,
                List.of("entry", "name"),
                false),
            new Case(
                "function_call.list",
                Map.of("filter", Map.of("entry", "0x00101000", "direction", "callees")),
                "name",
                "FunctionService",
                "getCallees",
                3,
                List.of("entry", "name"),
                false),
            new Case(
                "decompilation.get",
                Map.of("selector", Map.of("entry", "0x00101000")),
                "completed",
                "DecompilationService",
                "decompileFunction",
                4,
                List.of("entry", "completed"),
                false),
            new Case(
                "symbol.get",
                Map.of("selector", Map.of("id", "1")),
                "name",
                "SymbolService",
                "getSymbol",
                1,
                List.of("id", "name"),
                false),
            new Case(
                "symbol.list",
                Map.of(),
                "name",
                "SymbolService",
                "listSymbols",
                1,
                List.of("address", "id", "name"),
                true),
            new Case(
                "data_type_category.list",
                Map.of(),
                "name",
                "DataTypeService",
                "listCategories",
                3,
                List.of("path", "name"),
                false),
            new Case(
                "data_type.get",
                Map.of("selector", Map.of("path", "/Callback")),
                "kind",
                "DataTypeService",
                "getDataType",
                1,
                List.of("path", "kind"),
                false),
            new Case(
                "data_type.list",
                Map.of(),
                "kind",
                "DataTypeService",
                "searchDataTypes",
                5,
                List.of("path", "kind"),
                false));

    for (Case testCase : cases) {
      lastCall.set(null);
      registry.dispatch(testCase.wireMethod(), testCase.baseParams());
      RecordedCall unprojected = lastCall.get();
      assertEquals(testCase.serviceName(), unprojected.service(), testCase.wireMethod());
      assertEquals(testCase.domainMethod(), unprojected.method(), testCase.wireMethod());
      assertEquals(testCase.baseArity(), unprojected.argCount(), testCase.wireMethod());
      assertNull(unprojected.fields(), testCase.wireMethod());
      assertNull(unprojected.queryFields(), testCase.wireMethod());

      lastCall.set(null);
      Map<String, Object> projectedParams = new LinkedHashMap<>(testCase.baseParams());
      projectedParams.put("projection", Map.of("fields", List.of(testCase.projectionField())));
      registry.dispatch(testCase.wireMethod(), projectedParams);
      RecordedCall projected = lastCall.get();
      assertEquals(testCase.serviceName(), projected.service(), testCase.wireMethod());
      assertEquals(testCase.domainMethod(), projected.method(), testCase.wireMethod());
      assertEquals(testCase.baseArity() + 1, projected.argCount(), testCase.wireMethod());
      assertEquals(testCase.expectedSelectedFields(), List.copyOf(projected.fields()));
      if (testCase.hasQueryFields()) {
        assertEquals(Set.copyOf(testCase.expectedSelectedFields()), projected.queryFields());
      }
    }

    // Check derived includes on function.get and function.list across dot-path projections.
    lastCall.set(null);
    Map<String, Object> fnDot =
        (Map<String, Object>)
            registry.dispatch(
                "function.get",
                Map.of(
                    "selector",
                    Map.of("entry", "0x00101000"),
                    "projection",
                    Map.of(
                        "fields",
                        List.of("body.start", "parameters.name", "local_variables.storage"))));
    assertEquals(Set.of("parameters", "locals"), lastCall.get().includes());
    assertEquals(
        Map.of(
            "entry",
            "0x00101000",
            "body",
            Map.of("start", "0x00101000"),
            "parameters",
            List.of(Map.of("name", "argc")),
            "local_variables",
            List.of(Map.of("storage", Map.of("kind", "register", "register", "RAX")))),
        fnDot);

    lastCall.set(null);
    registry.dispatch(
        "function.list",
        Map.of("projection", Map.of("fields", List.of("body.start"))));
    assertEquals(Set.of(), lastCall.get().includes());
    assertEquals(List.of("entry", "body.start"), List.copyOf(lastCall.get().fields()));

    // Check split-phase prepareDispatch and batch.execute field projections.
    lastCall.set(null);
    ApiRegistry.PreparedDispatch prepared =
        registry.prepareDispatch(
            "data_type.get",
            Map.of(
                "selector",
                Map.of("path", "/Callback"),
                "projection",
                Map.of("fields", List.of("signature.return_type"))));
    assertEquals(
        Map.of(
            "path",
            "/Callback",
            "signature",
            Map.of("return_type", Map.of("kind", "named", "name", "int"))),
        prepared.encodeResponse(prepared.execute()));
    assertEquals(List.of("path", "signature.return_type"), List.copyOf(lastCall.get().fields()));

    lastCall.set(null);
    ApiRegistry.PreparedDispatch batch =
        registry.prepareDispatch(
            "batch.execute",
            Map.of(
                "items",
                List.of(
                    Map.of(
                        "id",
                        "item-1",
                        "method",
                        "symbol.get",
                        "arguments",
                        Map.of(
                            "selector",
                            Map.of("id", "1"),
                            "projection",
                            Map.of("fields", List.of("name")))))));
    assertEquals(
        Map.of(
            "items",
            List.of(Map.of("id", "item-1", "result", Map.of("id", "1", "name", "main")))),
        batch.encodeResponse(batch.execute()));
    assertEquals(List.of("id", "name"), List.copyOf(lastCall.get().fields()));
  }

  @SuppressWarnings("unchecked")
  private static ApiRegistry buildRecordingRegistry(AtomicReference<RecordedCall> lastCall) {
    ScanProgress scan =
        new ScanProgress(
            ScanProgress.Kind.ADDRESS,
            "0x00101000",
            "0x00102000",
            "0x00101000",
            "0x00101020",
            true,
            ScanProgress.StopReason.COMPLETED,
            1L);

    ProgramService programService =
        proxy(
            ProgramService.class,
            (proxy, method, args) -> {
              int count = args == null ? 0 : args.length;
              Set<String> fields = trailingFields(method, args);
              lastCall.set(
                  new RecordedCall("ProgramService", method.getName(), count, fields, null, null));
              return switch (method.getName()) {
                case "getProgram" ->
                    new ProgramResource(
                        "sample.bin",
                        "/bin/sample",
                        "ELF",
                        null,
                        null,
                        null,
                        null,
                        null,
                        Instant.parse("2026-01-01T00:00:00Z"),
                        null,
                        0L,
                        0L);
                case "getLanguageInfo" ->
                    new ProgramLanguageResource(
                        "x86:LE:64:default",
                        "gcc",
                        "x86",
                        ProgramLanguageResource.Endian.LITTLE,
                        64);
                case "getAddressSpaces" ->
                    Page.of(
                        List.of(
                            new AddressSpaceResource(
                                "ram", AddressSpaceResource.Kind.RAM, 64, null, null, true)),
                        100,
                        null);
                default -> invokeDefaultOrFail(proxy, method, args);
              };
            });

    AddressService addressService =
        proxy(
            AddressService.class,
            (proxy, method, args) -> {
              int count = args == null ? 0 : args.length;
              Set<String> fields = trailingFields(method, args);
              lastCall.set(
                  new RecordedCall("AddressService", method.getName(), count, fields, null, null));
              return new AddressResource("0x00101000", true, true, null, null, null, null);
            });

    ListingService listingService =
        proxy(
            ListingService.class,
            (proxy, method, args) -> {
              int count = args == null ? 0 : args.length;
              Set<String> fields = trailingFields(method, args);
              lastCall.set(
                  new RecordedCall("ListingService", method.getName(), count, fields, null, null));
              return switch (method.getName()) {
                case "listCodeUnits" ->
                    Page.scanned(
                        List.of(
                            new CodeUnitResource(
                                "0x00101000",
                                CodeUnitResource.Kind.DATA,
                                4,
                                new ByteSequence(ByteSequence.Encoding.HEX, "01000000", 4),
                                "dd 1h",
                                "dd",
                                List.of("1h"),
                                DataTypeReference.named("int"))),
                        100,
                        null,
                        scan);
                case "listDataUnits" ->
                    Page.scanned(
                        List.of(
                            new DataUnitResource(
                                "0x00200000",
                                4,
                                DataTypeReference.named("int"),
                                "0x1",
                                "1h",
                                new ByteSequence(ByteSequence.Encoding.HEX, "01000000", 4))),
                        100,
                        null,
                        scan);
                case "getInstruction" ->
                    new InstructionResource(
                        "0x00101000",
                        1,
                        new ByteSequence(ByteSequence.Encoding.HEX, "90", 1),
                        "NOP",
                        List.of(),
                        FlowOverrideValue.NONE,
                        "fall_through",
                        "fall_through",
                        "0x00101001");
                case "listInstructions", "getFlowOverrides" ->
                    Page.scanned(
                        List.of(
                            new InstructionResource(
                                "0x00101000",
                                1,
                                new ByteSequence(ByteSequence.Encoding.HEX, "90", 1),
                                "NOP",
                                List.of(),
                                FlowOverrideValue.BRANCH,
                                "fall_through",
                                "unconditional_jump",
                                null)),
                        100,
                        null,
                        scan);
                default -> invokeDefaultOrFail(proxy, method, args);
              };
            });

    GlobalVariableResource sampleGlobal =
        new GlobalVariableResource(
            "0x00200000",
            "g_count",
            "Global",
            DataTypeReference.named("int"),
            4,
            "0x2a",
            "42",
            "user_defined");

    GlobalVariableService globalVariableService =
        proxy(
            GlobalVariableService.class,
            (proxy, method, args) -> {
              int count = args == null ? 0 : args.length;
              Set<String> fields = trailingFields(method, args);
              Set<String> queryFields =
                  args != null
                          && args.length > 0
                          && args[0] instanceof GlobalVariableService.Query q
                      ? q.fields()
                      : null;
              lastCall.set(
                  new RecordedCall(
                      "GlobalVariableService", method.getName(), count, fields, queryFields, null));
              return switch (method.getName()) {
                case "getGlobalVariable" -> sampleGlobal;
                case "listGlobalVariables" -> Page.scanned(List.of(sampleGlobal), 100, null, scan);
                default -> invokeDefaultOrFail(proxy, method, args);
              };
            });

    FunctionResource sampleFunction =
        new FunctionResource(
            "0x00101000",
            "main",
            "Global",
            new FunctionResource.Body("0x00101000", null, 0L),
            null,
            null,
            null,
            0,
            null,
            List.of(new FunctionResource.ParameterResource(0, "argc", null, null)),
            List.of(
                new FunctionResource.LocalVariableResource(
                    null, null, new VariableStorageReference.Register("RAX"))),
            null,
            false,
            false,
            false,
            false,
            0,
            false,
            false,
            null,
            List.of(),
            null);

    FunctionService functionService =
        proxy(
            FunctionService.class,
            (proxy, method, args) -> {
              int count = args == null ? 0 : args.length;
              Set<String> fields = null;
              Set<String> queryFields = null;
              Set<String> includes = null;
              if ("getFunction".equals(method.getName())) {
                includes = (Set<String>) args[1];
                if (count == 3) {
                  fields = (Set<String>) args[2];
                }
              } else if ("listFunctions".equals(method.getName())) {
                FunctionService.FunctionQuery query = (FunctionService.FunctionQuery) args[0];
                queryFields = query.fields();
                includes = query.includes();
                if (count == 2) {
                  fields = (Set<String>) args[1];
                }
              } else {
                fields = trailingFields(method, args);
              }
              lastCall.set(
                  new RecordedCall(
                      "FunctionService", method.getName(), count, fields, queryFields, includes));
              return switch (method.getName()) {
                case "getFunction" -> sampleFunction;
                case "listFunctions" -> Page.scanned(List.of(sampleFunction), 100, null, scan);
                case "getCallers", "getCallees" ->
                    Page.of(
                        List.of(
                            new FunctionCallResource(
                                "0x00101040",
                                "helper",
                                null,
                                FunctionCallResource.Direction.CALLEES,
                                "Global",
                                null)),
                        100,
                        null);
                default -> invokeDefaultOrFail(proxy, method, args);
              };
            });

    DecompilationService decompilationService =
        proxy(
            DecompilationService.class,
            (proxy, method, args) -> {
              if ("close".equals(method.getName())) {
                return null;
              }
              int count = args == null ? 0 : args.length;
              Set<String> fields = trailingFields(method, args);
              lastCall.set(
                  new RecordedCall(
                      "DecompilationService", method.getName(), count, fields, null, null));
              return new DecompilationResource(
                  "0x00101000",
                  "",
                  DecompilationResource.Format.TEXT,
                  true,
                  0L,
                  "",
                  null,
                  null,
                  null,
                  null,
                  List.of());
            });

    SymbolResource sampleSymbol =
        new SymbolResource(
            "1", "main", "0x00101000", "Global", "function", "user_defined", true, null);

    SymbolService symbolService =
        proxy(
            SymbolService.class,
            (proxy, method, args) -> {
              int count = args == null ? 0 : args.length;
              Set<String> fields = trailingFields(method, args);
              Set<String> queryFields =
                  args != null && args.length > 0 && args[0] instanceof SymbolService.SymbolQuery q
                      ? q.fields()
                      : null;
              lastCall.set(
                  new RecordedCall(
                      "SymbolService", method.getName(), count, fields, queryFields, null));
              return switch (method.getName()) {
                case "getSymbol" -> sampleSymbol;
                case "listSymbols" -> Page.scanned(List.of(sampleSymbol), 100, null, scan);
                default -> invokeDefaultOrFail(proxy, method, args);
              };
            });

    DataTypeResource sampleDataType =
        new DataTypeResource(
            "/Callback",
            "Callback",
            "/",
            DataTypeResource.Kind.FUNCTION,
            null,
            null,
            null,
            null,
            null,
            new FunctionSignature(
                DataTypeReference.named("int"), List.of(), "default", false, false),
            null);

    DataTypeService dataTypeService =
        proxy(
            DataTypeService.class,
            (proxy, method, args) -> {
              int count = args == null ? 0 : args.length;
              Set<String> fields = trailingFields(method, args);
              lastCall.set(
                  new RecordedCall(
                      "DataTypeService", method.getName(), count, fields, null, null));
              return switch (method.getName()) {
                case "listCategories" ->
                    Page.of(
                        List.of(new DataTypeCategoryResource("/types", "types", 0, 0)), 100, null);
                case "getDataType" -> sampleDataType;
                case "searchDataTypes" -> Page.of(List.of(sampleDataType), 100, null);
                default -> invokeDefaultOrFail(proxy, method, args);
              };
            });

    CommentService commentService =
        proxy(CommentService.class, ProjectionWireTest::invokeDefaultOrFail);
    ReferenceService referenceService =
        (from, to, type, dir, limit, cursor) -> Page.of(List.of(), limit, null);
    MemoryService memoryService =
        proxy(MemoryService.class, ProjectionWireTest::invokeDefaultOrFail);
    AnalysisService analysisService =
        proxy(
            AnalysisService.class,
            (proxy, method, args) ->
                "getStatus".equals(method.getName())
                    ? new AnalysisResource(
                        AnalysisResource.Kind.GHIDRA,
                        AnalysisResource.Status.IDLE,
                        true,
                        null,
                        null,
                        null,
                        100.0)
                    : invokeDefaultOrFail(proxy, method, args));

    TransactionRunner txRunner =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            try {
              return operation.execute();
            } catch (RuntimeException runtime) {
              throw runtime;
            } catch (Exception checked) {
              throw new IllegalStateException(checked);
            }
          }
        };

    BridgeServices services =
        new BridgeServices(
            programService,
            addressService,
            commentService,
            referenceService,
            memoryService,
            listingService,
            functionService,
            globalVariableService,
            analysisService,
            decompilationService,
            symbolService,
            dataTypeService,
            txRunner,
            "sample.bin");

    return new ApiRegistry(
        services,
        "session-1",
        () -> Map.of("id", "session-1", "status", "ready", "program_name", "sample.bin"),
        () -> {});
  }

  @SuppressWarnings("unchecked")
  private static Set<String> trailingFields(java.lang.reflect.Method method, Object[] args) {
    if (args == null || args.length == 0) {
      return null;
    }
    Class<?>[] types = method.getParameterTypes();
    if (types[types.length - 1] == Set.class) {
      return (Set<String>) args[args.length - 1];
    }
    return null;
  }

  @SuppressWarnings("unchecked")
  private static <T> T proxy(Class<T> iface, InvocationHandler handler) {
    return (T)
        Proxy.newProxyInstance(
            iface.getClassLoader(),
            new Class<?>[] {iface},
            (proxy, method, args) -> {
              if (method.getDeclaringClass() == Object.class) {
                return switch (method.getName()) {
                  case "toString" -> iface.getSimpleName() + "Proxy";
                  case "hashCode" -> System.identityHashCode(proxy);
                  case "equals" -> proxy == args[0];
                  default -> null;
                };
              }
              return handler.invoke(proxy, method, args);
            });
  }

  private static Object invokeDefaultOrFail(
      Object proxy, java.lang.reflect.Method method, Object[] args) throws Throwable {
    if (method.isDefault()) {
      return InvocationHandler.invokeDefault(proxy, method, args);
    }
    throw new UnsupportedOperationException("unexpected service call: " + method);
  }
}
