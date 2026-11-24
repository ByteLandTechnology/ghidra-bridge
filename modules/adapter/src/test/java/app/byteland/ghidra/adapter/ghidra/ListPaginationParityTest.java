package app.byteland.ghidra.adapter.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;

import app.byteland.ghidra.JsonUtil;
import app.byteland.ghidra.adapter.ghidra.datatype.DataTypeServiceImpl;
import app.byteland.ghidra.adapter.ghidra.function.FunctionServiceImpl;
import app.byteland.ghidra.adapter.ghidra.reference.ReferenceServiceImpl;
import app.byteland.ghidra.api.ApiRegistry;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeCategoryResource;
import app.byteland.ghidra.service.datatype.DataTypePatch;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeResource;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.datatype.FunctionSignature;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionCallResource;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.function.VariableStorageReference;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceResource;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.DefaultAddressFactory;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class ListPaginationParityTest {
  private static final GenericAddressSpace RAM =
      new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);

  private static final class FixtureScript extends GhidraScript {
    private FixtureScript(Program program) {
      set(program, TaskMonitor.DUMMY);
    }

    @Override
    protected void run() {}
  }

  @Test
  void wireResponsesAndCursorTokensMatchBaselineAcrossAllFourListMethods() throws Exception {
    Fixture fixture = buildFixture();
    ApiRegistry actualRegistry = new ApiRegistry(fixture.actualServices(), "sess-1", Map::of, () -> {});
    ApiRegistry baselineRegistry =
        new ApiRegistry(fixture.baselineServices(), "sess-1", Map::of, () -> {});

    assertMethodParity(
        baselineRegistry,
        actualRegistry,
        "data_type_category.list",
        Map.of("filter", Map.of("path", "/")),
        2);

    for (Map<String, Object> filter :
        List.<Map<String, Object>>of(
            Map.of(),
            Map.of("query", "pkt"),
            Map.of("category_path", "/net"),
            Map.of("category_path", "/net", "kind", "struct"),
            Map.of("category_path", "/missing"),
            Map.of("category_path", "invalid_relative"),
            Map.of("kind", "union"))) {
      assertMethodParity(
          baselineRegistry, actualRegistry, "data_type.list", Map.of("filter", filter), 2);
    }

    for (String direction : List.of("callers", "callees")) {
      assertMethodParity(
          baselineRegistry,
          actualRegistry,
          "function_call.list",
          Map.of("filter", Map.of("entry", "ram:00400000", "direction", direction)),
          2);
    }

    assertMethodParity(
        baselineRegistry,
        actualRegistry,
        "reference.list",
        Map.of("filter", Map.of("to", "ram:00400000", "direction", "to")),
        2);
    assertMethodParity(
        baselineRegistry,
        actualRegistry,
        "reference.list",
        Map.of("filter", Map.of("to", "ram:00400000", "direction", "to", "type", "UNCONDITIONAL_CALL")),
        2);
    assertMethodParity(
        baselineRegistry,
        actualRegistry,
        "reference.list",
        Map.of("filter", Map.of("from", "ram:00400000", "direction", "from")),
        2);
  }

  @SuppressWarnings("unchecked")
  private static void assertMethodParity(
      ApiRegistry baseline,
      ApiRegistry actual,
      String method,
      Map<String, Object> baseRequest,
      int limit)
      throws Exception {
    for (int pageSize : List.of(limit, 100)) {
      String cursor = null;
      while (true) {
        Map<String, Object> request = new LinkedHashMap<>(baseRequest);
        Map<String, Object> page = new LinkedHashMap<>();
        page.put("limit", pageSize);
        if (cursor != null) {
          page.put("cursor", cursor);
        }
        request.put("page", page);
        Map<String, Object> expectedPage = (Map<String, Object>) baseline.dispatch(method, request);
        Map<String, Object> actualPage = (Map<String, Object>) actual.dispatch(method, request);
        assertEquals(expectedPage, actualPage, () -> method + " mismatch for " + request);
        cursor = (String) actualPage.get("next_cursor");
        if (cursor == null) break;
      }
    }
  }

  private record Fixture(BridgeServices actualServices, BridgeServices baselineServices) {}

  private static Fixture buildFixture() {
    List<DataTypeCategoryResource> rootCategories =
        List.of(
            new DataTypeCategoryResource("/zeta", "zeta", 0, 1),
            new DataTypeCategoryResource("/net", "net", 1, 3),
            new DataTypeCategoryResource("/core", "core", 0, 1));

    DataType dtNetB = mockDataType(Structure.class, "/net/PktB", "PktB", 16, "pkt b");
    DataType dtNetA = mockDataType(Structure.class, "/net/PktA", "PktA", 8, "pkt a");
    DataType dtNetU = mockDataType(Union.class, "/net/PktUnion", "PktUnion", 12, "union");
    DataType dtCore = mockDataType(Structure.class, "/core/Header", "Header", 24, "hdr");
    DataType dtZeta =
        mockDataType(ghidra.program.model.data.Enum.class, "/zeta/Mode", "Mode", 4, "mode");
    List<DataType> allTypes = List.of(dtNetB, dtCore, dtZeta, dtNetA, dtNetU);

    Category netCat = mockCategory("/net", "net", 1, new DataType[] {dtNetB, dtNetA, dtNetU});
    Category coreCat = mockCategory("/core", "core", 0, new DataType[] {dtCore});
    Category zetaCat = mockCategory("/zeta", "zeta", 0, new DataType[] {dtZeta});
    Category rootCat =
        (Category)
            Proxy.newProxyInstance(
                Category.class.getClassLoader(),
                new Class<?>[] {Category.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "getCategoryPath" -> CategoryPath.ROOT;
                      case "getName" -> "";
                      case "getCategories" -> new Category[] {zetaCat, netCat, coreCat};
                      case "getDataTypes" -> new DataType[0];
                      default -> throw new AssertionError(method.getName());
                    });

    Map<CategoryPath, Category> categoryMap = new HashMap<>();
    categoryMap.put(CategoryPath.ROOT, rootCat);
    categoryMap.put(new CategoryPath("/net"), netCat);
    categoryMap.put(new CategoryPath("/core"), coreCat);
    categoryMap.put(new CategoryPath("/zeta"), zetaCat);

    ProgramBasedDataTypeManager dtm =
        (ProgramBasedDataTypeManager)
            Proxy.newProxyInstance(
                ProgramBasedDataTypeManager.class.getClassLoader(),
                new Class<?>[] {ProgramBasedDataTypeManager.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "getCategory" -> categoryMap.get((CategoryPath) args[0]);
                      case "getAllDataTypes" -> allTypes.iterator();
                      default -> throw new AssertionError(method.getName());
                    });

    Function f3 = mockFunction(0x00403000L, "fn_three", "App");
    Function f1 = mockFunction(0x00401000L, "fn_one", "App");
    Function f2 = mockFunction(0x00402000L, "fn_two", "Global");
    Set<Function> callers = new LinkedHashSet<>(List.of(f3, f1, f2));
    Set<Function> callees = new LinkedHashSet<>(List.of(f2, f3));
    Address rootEntry = RAM.getAddress(0x00400000L);
    Function rootFn =
        (Function)
            Proxy.newProxyInstance(
                Function.class.getClassLoader(),
                new Class<?>[] {Function.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "getEntryPoint" -> rootEntry;
                      case "getCallingFunctions" -> callers;
                      case "getCalledFunctions" -> callees;
                      default -> throw new AssertionError(method.getName());
                    });

    List<Reference> incomingRefs =
        List.of(
            mockReference(RAM.getAddress(0x00403000L), rootEntry, RefType.UNCONDITIONAL_CALL, 0),
            mockReference(RAM.getAddress(0x00401000L), rootEntry, RefType.UNCONDITIONAL_CALL, 2),
            mockReference(RAM.getAddress(0x00401000L), rootEntry, RefType.UNCONDITIONAL_CALL, 10),
            mockReference(RAM.getAddress(0x00401000L), rootEntry, RefType.UNCONDITIONAL_CALL, -1),
            mockReference(RAM.getAddress(0x00402000L), rootEntry, RefType.DATA, 0));
    Reference[] outgoingRefs = {
      mockReference(rootEntry, RAM.getAddress(0x00409000L), RefType.READ, 1),
      mockReference(rootEntry, RAM.getAddress(0x00408000L), RefType.WRITE, 0)
    };

    AddressFactory factory = new DefaultAddressFactory(new AddressSpace[] {RAM});
    FunctionManager fnManager =
        (FunctionManager)
            Proxy.newProxyInstance(
                FunctionManager.class.getClassLoader(),
                new Class<?>[] {FunctionManager.class},
                (proxy, method, args) -> {
                  if ("getFunctionAt".equals(method.getName())) {
                    return rootEntry.equals(args[0]) ? rootFn : null;
                  }
                  throw new AssertionError(method.getName());
                });
    Listing listing =
        (Listing)
            Proxy.newProxyInstance(
                Listing.class.getClassLoader(),
                new Class<?>[] {Listing.class},
                (proxy, method, args) -> {
                  if ("getFunctionAt".equals(method.getName())) {
                    return rootEntry.equals(args[0]) ? rootFn : null;
                  }
                  throw new AssertionError(method.getName());
                });
    ReferenceManager refManager =
        (ReferenceManager)
            Proxy.newProxyInstance(
                ReferenceManager.class.getClassLoader(),
                new Class<?>[] {ReferenceManager.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "getReferencesTo" -> iteratorProxy(incomingRefs.iterator());
                      case "getReferencesFrom" -> outgoingRefs;
                      default -> throw new AssertionError(method.getName());
                    });
    AnalysisService analysis = unused(AnalysisService.class);
    Program program =
        (Program)
            Proxy.newProxyInstance(
                Program.class.getClassLoader(),
                new Class<?>[] {Program.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "getAddressFactory" -> factory;
                      case "getDataTypeManager" -> dtm;
                      case "getFunctionManager" -> fnManager;
                      case "getListing" -> listing;
                      case "getReferenceManager" -> refManager;
                      default -> throw new AssertionError(method.getName());
                    });

    GhidraSession session = new GhidraSession(new FixtureScript(program));
    BridgeServices actualServices =
        services(
            new DataTypeServiceImpl(session),
            new FunctionServiceImpl(session),
            new ReferenceServiceImpl(session),
            analysis);
    BridgeServices baselineServices =
        services(
            baselineDataTypeService(rootCategories, allTypes),
            baselineFunctionService(callers, callees),
            baselineReferenceService(incomingRefs, List.of(outgoingRefs)),
            analysis);
    return new Fixture(actualServices, baselineServices);
  }

  private static BridgeServices services(
      DataTypeService dt, FunctionService fn, ReferenceService ref, AnalysisService analysis) {
    TransactionRunner tx = unused(TransactionRunner.class);
    return new BridgeServices(
        unused(ProgramService.class),
        unused(AddressService.class),
        unused(CommentService.class),
        ref,
        unused(MemoryService.class),
        unused(ListingService.class),
        fn,
        unused(GlobalVariableService.class),
        analysis,
        unused(DecompilationService.class),
        unused(SymbolService.class),
        dt,
        tx,
        "test");
  }

  private static DataTypeService baselineDataTypeService(
      List<DataTypeCategoryResource> rootCategories, List<DataType> allTypes) {
    return new DataTypeService() {
      @Override
      public Page<DataTypeCategoryResource> listCategories(
          String categoryPath, int limit, String cursor) {
        List<DataTypeCategoryResource> copy = new ArrayList<>(rootCategories);
        copy.sort(Comparator.comparing(DataTypeCategoryResource::path));
        return Page.paginate(copy, limit, cursor, DataTypeCategoryResource::path);
      }

      @Override
      public DataTypeResource getDataType(String path) {
        throw new UnsupportedOperationException();
      }

      @Override
      public Page<DataTypeResource> searchDataTypes(
          String query, String categoryPath, String kind, int limit, String cursor) {
        String lower = query == null ? "" : query.toLowerCase(Locale.ROOT);
        List<DataTypeResource> matched = new ArrayList<>();
        for (DataType dt : allTypes) {
          if (!dt.getName().toLowerCase(Locale.ROOT).contains(lower)) continue;
          DataTypeResource res = baselineSummarize(dt);
          if (categoryPath != null && !categoryPath.equals(res.categoryPath())) continue;
          if (kind != null && !kind.equalsIgnoreCase(res.kind().name())) continue;
          matched.add(res);
        }
        matched.sort(Comparator.comparing(DataTypeResource::path));
        return Page.paginate(matched, limit, cursor, DataTypeResource::path);
      }

      @Override
      public void createDataType(
          String categoryPath,
          DataTypeResource.Kind kind,
          String name,
          DataTypeReference baseType,
          int size,
          FunctionSignature signature) {
        throw new UnsupportedOperationException();
      }

      @Override
      public List<DataTypeResource> parseC(String source, String categoryPath) {
        throw new UnsupportedOperationException();
      }

      @Override
      public void patchDataType(String path, DataTypePatch patch) {
        throw new UnsupportedOperationException();
      }

      @Override
      public boolean deleteDataType(String path) {
        throw new UnsupportedOperationException();
      }
    };
  }

  private static DataTypeResource baselineSummarize(DataType dt) {
    DataTypeResource.Kind kind =
        dt instanceof Structure
            ? DataTypeResource.Kind.STRUCT
            : dt instanceof Union ? DataTypeResource.Kind.UNION : DataTypeResource.Kind.ENUM;
    String path = dt.getPathName();
    String category = path.substring(0, path.lastIndexOf('/'));
    return new DataTypeResource(
        path,
        dt.getName(),
        category.isEmpty() ? "/" : category,
        kind,
        dt.getLength(),
        dt.getDescription(),
        null,
        null,
        null,
        null,
        null);
  }

  private static FunctionService baselineFunctionService(
      Set<Function> callers, Set<Function> callees) {
    return new FunctionService() {
      @Override
      public Page<FunctionCallResource> getCallers(String rawAddress, int limit, String cursor) {
        return baselineRelations(callers, FunctionCallResource.Direction.CALLERS, limit, cursor);
      }

      @Override
      public Page<FunctionCallResource> getCallees(String rawAddress, int limit, String cursor) {
        return baselineRelations(callees, FunctionCallResource.Direction.CALLEES, limit, cursor);
      }

      private Page<FunctionCallResource> baselineRelations(
          Set<Function> fns, FunctionCallResource.Direction dir, int limit, String cursor) {
        List<FunctionCallResource> rows = new ArrayList<>();
        for (Function fn : fns) {
          rows.add(
              new FunctionCallResource(
                  AddressUtil.canonicalAddress(fn.getEntryPoint()),
                  fn.getName(),
                  null,
                  dir,
                  fn.getParentNamespace().getName(true),
                  null));
        }
        rows.sort(Comparator.comparing(FunctionCallResource::entry));
        return Page.paginate(rows, limit, cursor, FunctionCallResource::entry);
      }

      @Override
      public Page<FunctionResource> listFunctions(FunctionQuery query) {
        throw new UnsupportedOperationException();
      }

      @Override
      public FunctionResource getFunction(String rawAddress, Set<String> includes) {
        throw new UnsupportedOperationException();
      }

      @Override
      public FunctionResource createFunction(
          String rawAddress, String name, boolean disassembleFirst) {
        throw new UnsupportedOperationException();
      }

      @Override
      public void deleteFunction(String rawAddress) {
        throw new UnsupportedOperationException();
      }

      @Override
      public void patchFunction(
          String rawAddress,
          String name,
          String comment,
          boolean updateComment,
          DataTypeReference returnType,
          VariableStorageReference returnStorage,
          String callingConvention,
          FunctionAttributePatch attributes,
          List<ParameterPatch> parameters,
          String signature) {
        throw new UnsupportedOperationException();
      }

      @Override
      public void addParameter(
          String rawAddress,
          int ordinal,
          String name,
          DataTypeReference dataType,
          VariableStorageReference storage) {
        throw new UnsupportedOperationException();
      }

      @Override
      public void removeParameter(String rawAddress, int ordinal) {
        throw new UnsupportedOperationException();
      }

      @Override
      public void patchParameter(
          String rawAddress,
          int ordinal,
          String newName,
          DataTypeReference dataType,
          VariableStorageReference storage) {
        throw new UnsupportedOperationException();
      }

      @Override
      public void patchLocalVariable(
          String rawAddress, String currentName, String newName, DataTypeReference dataType) {
        throw new UnsupportedOperationException();
      }
    };
  }

  private static ReferenceService baselineReferenceService(
      List<Reference> incoming, List<Reference> outgoing) {
    return (fromRaw, toRaw, type, direction, limit, cursor) -> {
      List<Reference> source = "to".equals(direction) ? incoming : outgoing;
      record Keyed(Reference ref, String key) {}
      List<Keyed> matched = new ArrayList<>();
      for (Reference ref : source) {
        if (type != null && !type.equalsIgnoreCase(ref.getReferenceType().getName())) continue;
        String key =
            JsonUtil.toJson(
                List.of(
                    AddressUtil.canonicalAddress(ref.getFromAddress()),
                    AddressUtil.canonicalAddress(ref.getToAddress()),
                    ref.getReferenceType().getName(),
                    ref.getOperandIndex()));
        matched.add(new Keyed(ref, key));
      }
      matched.sort(Comparator.comparing(Keyed::key));
      Page<Keyed> page = Page.paginate(matched, limit, cursor, Keyed::key);
      List<ReferenceResource> items =
          page.items().stream()
              .map(
                  k ->
                      new ReferenceResource(
                          AddressUtil.canonicalAddress(k.ref().getFromAddress()),
                          AddressUtil.canonicalAddress(k.ref().getToAddress()),
                          k.ref().getReferenceType().getName(),
                          k.ref().getOperandIndex(),
                          k.ref().isPrimary(),
                          String.valueOf(k.ref().getSource())))
              .toList();
      return Page.of(items, page.limit(), page.nextCursor());
    };
  }

  @SuppressWarnings("unchecked")
  private static <T> T unused(Class<T> type) {
    return (T)
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> {
              throw new UnsupportedOperationException(method.getName());
            });
  }

  private static Category mockCategory(
      String path, String name, int subCategories, DataType[] types) {
    CategoryPath cp = new CategoryPath(path);
    return (Category)
        Proxy.newProxyInstance(
            Category.class.getClassLoader(),
            new Class<?>[] {Category.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getCategoryPath" -> cp;
                  case "getName" -> name;
                  case "getCategories" -> new Category[subCategories];
                  case "getDataTypes" -> types;
                  default -> throw new AssertionError(method.getName());
                });
  }

  private static DataType mockDataType(
      Class<? extends DataType> iface, String path, String name, int length, String description) {
    return (DataType)
        Proxy.newProxyInstance(
            DataType.class.getClassLoader(),
            new Class<?>[] {iface},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getPathName" -> path;
                  case "getName" -> name;
                  case "getLength" -> length;
                  case "getDescription" -> description;
                  default -> throw new AssertionError(method.getName());
                });
  }

  private static Function mockFunction(long offset, String name, String ns) {
    Address entry = RAM.getAddress(offset);
    Namespace namespace =
        (Namespace)
            Proxy.newProxyInstance(
                Namespace.class.getClassLoader(),
                new Class<?>[] {Namespace.class},
                (proxy, method, args) -> ns);
    return (Function)
        Proxy.newProxyInstance(
            Function.class.getClassLoader(),
            new Class<?>[] {Function.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getEntryPoint" -> entry;
                  case "getName" -> name;
                  case "getParentNamespace" -> namespace;
                  case "getProgram" -> null;
                  case "hashCode" -> System.identityHashCode(proxy);
                  case "equals" -> proxy == args[0];
                  default -> throw new AssertionError(method.getName());
                });
  }

  private static Reference mockReference(
      Address from, Address to, RefType refType, int operandIndex) {
    return (Reference)
        Proxy.newProxyInstance(
            Reference.class.getClassLoader(),
            new Class<?>[] {Reference.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getFromAddress" -> from;
                  case "getToAddress" -> to;
                  case "getReferenceType" -> refType;
                  case "getOperandIndex" -> operandIndex;
                  case "isPrimary" -> true;
                  case "getSource" -> SourceType.ANALYSIS;
                  default -> throw new AssertionError(method.getName());
                });
  }

  private static ReferenceIterator iteratorProxy(Iterator<Reference> iterator) {
    return (ReferenceIterator)
        Proxy.newProxyInstance(
            ReferenceIterator.class.getClassLoader(),
            new Class<?>[] {ReferenceIterator.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "hasNext" -> iterator.hasNext();
                  case "next" -> iterator.next();
                  case "iterator" -> (ReferenceIterator) proxy;
                  default -> throw new AssertionError(method.getName());
                });
  }
}
