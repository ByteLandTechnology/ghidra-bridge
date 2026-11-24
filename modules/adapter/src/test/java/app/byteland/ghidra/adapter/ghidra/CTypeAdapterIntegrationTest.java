package app.byteland.ghidra.adapter.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.datatype.DataTypeServiceImpl;
import app.byteland.ghidra.adapter.ghidra.function.FunctionServiceImpl;
import app.byteland.ghidra.api.ApiFailures;
import app.byteland.ghidra.service.datatype.DataTypeAlreadyExistsException;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeResource;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.FunctionService.FunctionAttributePatch;
import app.byteland.ghidra.service.function.FunctionService.ParameterPatch;
import app.byteland.ghidra.service.function.VariableStorageReference;
import ghidra.GhidraApplicationLayout;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefaultLanguageService;
import ghidra.util.task.TaskMonitor;
import java.io.File;
import java.io.PrintWriter;
import java.io.Writer;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class CTypeAdapterIntegrationTest {

  private static final Object CONSUMER = new Object();

  @BeforeAll
  static void initGhidra() throws Exception {
    if (!Application.isInitialized()) {
      String installDir = System.getenv("GHIDRA_INSTALL_DIR");
      if (installDir == null || installDir.isBlank()) {
        installDir = System.getProperty("ghidraInstallDir");
      }
      ApplicationConfiguration config = new ApplicationConfiguration();
      config.setInitializeLogging(false);
      Application.initializeApplication(
          new GhidraApplicationLayout(new File(installDir)), config);
    }
  }

  private static Program newX64Program(String name) throws Exception {
    Language language =
        DefaultLanguageService.getLanguageService().getLanguage(new LanguageID("x86:LE:64:default"));
    return new ProgramDB(name, language, language.getDefaultCompilerSpec(), CONSUMER);
  }

  @Test
  void resolvesAllEightStandardCTypeFormsAndRejectsInvalidExpressions() throws Exception {
    Program program = newX64Program("ctype_test");
    int tx = program.startTransaction("test");
    try {
      DataTypeManager dtm = program.getDataTypeManager();
      StructureDataType pkgType = new StructureDataType(new CategoryPath("/pkg"), "Type", 8, dtm);
      dtm.addDataType(pkgType, DataTypeConflictHandler.DEFAULT_HANDLER);
      StructureDataType fooStruct = new StructureDataType(CategoryPath.ROOT, "Foo", 16, dtm);
      dtm.addDataType(fooStruct, DataTypeConflictHandler.DEFAULT_HANDLER);

      // 1. int
      DataType intType = GhidraDataTypeReferences.resolve(dtm, DataTypeReference.expression("int"));
      assertEquals(4, intType.getLength());
      assertEquals(DataTypeReference.named("/int"), GhidraDataTypeReferences.toReference(intType));

      // 2. /pkg/Type *
      DataType pkgPtr =
          GhidraDataTypeReferences.resolve(dtm, DataTypeReference.expression("/pkg/Type *"));
      assertInstanceOf(Pointer.class, pkgPtr);
      assertEquals(8, pkgPtr.getLength());
      assertEquals(
          DataTypeReference.pointerTo(DataTypeReference.named("/pkg/Type")),
          GhidraDataTypeReferences.toReference(pkgPtr));

      // 3. unsigned int
      DataType uintType =
          GhidraDataTypeReferences.resolve(dtm, DataTypeReference.expression("unsigned int"));
      assertEquals(4, uintType.getLength());
      assertEquals(
          DataTypeReference.named("/uint"), GhidraDataTypeReferences.toReference(uintType));

      // 4. const char *
      DataType constCharPtr =
          GhidraDataTypeReferences.resolve(dtm, DataTypeReference.expression("const char *"));
      assertEquals(
          DataTypeReference.pointerTo(DataTypeReference.named("/char")),
          GhidraDataTypeReferences.toReference(constCharPtr));

      // 5. struct Foo *
      DataType structFooPtr =
          GhidraDataTypeReferences.resolve(dtm, DataTypeReference.expression("struct Foo *"));
      assertEquals(
          DataTypeReference.pointerTo(DataTypeReference.named("/Foo")),
          GhidraDataTypeReferences.toReference(structFooPtr));

      // 6. int[4]
      DataType intArray =
          GhidraDataTypeReferences.resolve(dtm, DataTypeReference.expression("int[4]"));
      assertInstanceOf(Array.class, intArray);
      assertEquals(16, intArray.getLength());
      assertEquals(
          DataTypeReference.arrayOf(DataTypeReference.named("/int"), 4),
          GhidraDataTypeReferences.toReference(intArray));

      // 7. void * and pointer
      DataType voidPtr =
          GhidraDataTypeReferences.resolve(dtm, DataTypeReference.expression("void *"));
      assertInstanceOf(Pointer.class, voidPtr);
      assertInstanceOf(VoidDataType.class, ((Pointer) voidPtr).getDataType());
      assertEquals(
          DataTypeReference.pointerTo(DataTypeReference.named("/void")),
          GhidraDataTypeReferences.toReference(voidPtr));

      DataType genericPtr =
          GhidraDataTypeReferences.resolve(dtm, DataTypeReference.expression("pointer"));
      assertInstanceOf(Pointer.class, genericPtr);
      assertNull(((Pointer) genericPtr).getDataType());
      assertEquals(
          DataTypeReference.untypedPointer(), GhidraDataTypeReferences.toReference(genericPtr));

      // 8. void (*)(int)
      DataType fnPtr =
          GhidraDataTypeReferences.resolve(dtm, DataTypeReference.expression("void (*)(int)"));
      Pointer fnPointer = assertInstanceOf(Pointer.class, fnPtr);
      assertEquals(8, fnPointer.getLength());
      FunctionDefinition fnDef = assertInstanceOf(FunctionDefinition.class, fnPointer.getDataType());
      assertEquals(1, fnDef.getArguments().length);
      assertEquals("/int", fnDef.getArguments()[0].getDataType().getPathName());

      // Invalid expressions fail with IllegalArgumentException (HTTP 400).
      assertThrows(
          IllegalArgumentException.class,
          () -> GhidraDataTypeReferences.resolve(dtm, DataTypeReference.expression("enum Foo *")));
      assertThrows(
          IllegalArgumentException.class,
          () ->
              GhidraDataTypeReferences.resolve(
                  dtm, DataTypeReference.expression("struct Bar { int x; }")));
      assertThrows(
          IllegalArgumentException.class,
          () ->
              GhidraDataTypeReferences.resolve(dtm, DataTypeReference.expression("UnknownType *")));
    } finally {
      program.endTransaction(tx, false);
      program.release(CONSUMER);
    }
  }

  @Test
  void declarationsCreateAndUpsertSingleTypesAndRejectZeroOrMultipleWith400() throws Exception {
    Program program = newX64Program("decl_test");
    int tx = program.startTransaction("test");
    try {
      GhidraSession session = testSession(program);
      DataTypeServiceImpl service = new DataTypeServiceImpl(session);

      // struct create, 409 conflict, and upsert replacement with a self-reference
      String structPath =
          service.createDataTypeFromDeclaration(
              "/net", "struct Node { int id; struct Node *next; };");
      assertEquals("/net/Node", structPath);
      DataTypeResource node = service.getDataType("/net/Node");
      assertEquals(DataTypeResource.Kind.STRUCT, node.kind());
      assertEquals(16, node.length());

      DataTypeAlreadyExistsException exists =
          assertThrows(
              DataTypeAlreadyExistsException.class,
              () -> service.createDataTypeFromDeclaration("/net", "struct Node { long id; };"));
      assertEquals(409, ApiFailures.normalize(exists).status());

      String upsertedStruct =
          service.upsertDataTypeFromDeclaration(
              "/net", "struct Node { long long id; long long flags; struct Node *next; };");
      assertEquals("/net/Node", upsertedStruct);
      DataTypeResource updatedNode = service.getDataType("/net/Node");
      assertEquals(3, updatedNode.fields().size());
      assertEquals("flags", updatedNode.fields().get(1).name());
      assertEquals(24, updatedNode.length());

      // union
      String unionPath =
          service.createDataTypeFromDeclaration("/", "union Payload { int i; double d; };");
      assertEquals("/Payload", unionPath);
      assertEquals(DataTypeResource.Kind.UNION, service.getDataType("/Payload").kind());
      service.upsertDataTypeFromDeclaration("/", "union Payload { char bytes[32]; long q; };");
      assertEquals(32, service.getDataType("/Payload").length());

      // enum
      String enumPath =
          service.createDataTypeFromDeclaration("/", "enum Status { OK = 0, ERR = 1 };");
      assertEquals("/Status", enumPath);
      assertEquals(DataTypeResource.Kind.ENUM, service.getDataType("/Status").kind());
      service.upsertDataTypeFromDeclaration("/", "enum Status { OK = 0, ERR = 1, RETRY = 2 };");
      assertEquals(3, service.getDataType("/Status").values().size());

      // typedef with a function pointer typedef
      String tdPath =
          service.createDataTypeFromDeclaration(
              "/", "typedef void (*handler_t)(const char *msg, int code);");
      assertEquals("/handler_t", tdPath);
      assertEquals(DataTypeResource.Kind.TYPEDEF, service.getDataType("/handler_t").kind());
      service.upsertDataTypeFromDeclaration("/", "typedef unsigned long handler_t;");
      assertEquals(
          DataTypeReference.named("/ulong"), service.getDataType("/handler_t").baseType());

      // function definition
      String fnPath =
          service.createDataTypeFromDeclaration(
              "/functions", "int parse_packet(const /net/Node *node, unsigned int len);");
      assertEquals("/functions/parse_packet", fnPath);
      assertEquals(
          DataTypeResource.Kind.FUNCTION, service.getDataType("/functions/parse_packet").kind());
      service.upsertDataTypeFromDeclaration("/functions", "long parse_packet(void);");
      assertEquals(
          DataTypeReference.named("/long"),
          service.getDataType("/functions/parse_packet").signature().returnType());

      // Zero or multiple top-level types must reject with HTTP 400.
      List<String> invalidDeclarations =
          List.of(
              ";",
              "/* comment only */",
              "int global_counter;",
              "struct A { int x; }; struct B { int y; };",
              "typedef int A, B;",
              "typedef struct Inner { int x; } Outer;",
              "struct WithVar { int x; } instance;",
              "int f(void) { return 0; }",
              "int f(void); int g(void);");
      for (String invalid : invalidDeclarations) {
        IllegalArgumentException err =
            assertThrows(
                IllegalArgumentException.class,
                () -> service.createDataTypeFromDeclaration("/", invalid),
                "Expected rejection for: " + invalid);
        assertEquals(400, ApiFailures.normalize(err).status());
      }
    } finally {
      program.endTransaction(tx, false);
      program.release(CONSUMER);
    }
  }

  @Test
  void functionPatchAppliesAtomicParametersAndSignaturePreservingCustomStorage() throws Exception {
    Program program = newX64Program("fn_test");
    int tx = program.startTransaction("test");
    try {
      Address entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
      program
          .getMemory()
          .createInitializedBlock(".text", entry, 0x100, (byte) 0x90, TaskMonitor.DUMMY, false)
          .putByte(entry, (byte) 0xc3);
      program
          .getFunctionManager()
          .createFunction("work", entry, new AddressSet(entry, entry), SourceType.USER_DEFINED);

      GhidraSession session = testSession(program);
      FunctionServiceImpl functions = new FunctionServiceImpl(session);

      // 1. Dynamic storage atomic parameter replacement and C string types with a function pointer
      functions.patchFunction(
          "0x1000",
          null,
          null,
          false,
          DataTypeReference.expression("unsigned int"),
          null,
          null,
          FunctionAttributePatch.empty(),
          List.of(
              new ParameterPatch("first", DataTypeReference.expression("int"), null),
              new ParameterPatch("cb", DataTypeReference.expression("void (*)(int)"), null)),
          null);
      FunctionResource dynamic = functions.getFunction("0x1000", Set.of("parameters"));
      assertFalse(dynamic.hasCustomVariableStorage());
      assertEquals(2, dynamic.parameters().size());
      assertEquals("first", dynamic.parameters().get(0).name());
      assertEquals("cb", dynamic.parameters().get(1).name());

      // Swap dynamic parameters (first, cb) -> (cb, first) atomically without name collision!
      functions.patchFunction(
          "0x1000",
          null,
          null,
          false,
          null,
          null,
          null,
          FunctionAttributePatch.empty(),
          List.of(
              new ParameterPatch("cb", DataTypeReference.expression("void (*)(int)"), null),
              new ParameterPatch("first", DataTypeReference.expression("int"), null)),
          null);
      FunctionResource swappedDynamic = functions.getFunction("0x1000", Set.of("parameters"));
      assertEquals("cb", swappedDynamic.parameters().get(0).name());
      assertEquals("first", swappedDynamic.parameters().get(1).name());

      // 2. Establish custom variable storage in R8D / R9D and EAX return
      functions.patchFunction(
          "0x1000",
          null,
          null,
          false,
          DataTypeReference.expression("int"),
          new VariableStorageReference.Register("EAX"),
          null,
          new FunctionAttributePatch(null, null, null, true, null),
          List.of(
              new ParameterPatch(
                  "alpha",
                  DataTypeReference.expression("int"),
                  new VariableStorageReference.Register("R8D")),
              new ParameterPatch(
                  "beta",
                  DataTypeReference.expression("int"),
                  new VariableStorageReference.Register("R9D"))),
          null);
      FunctionResource customInitial = functions.getFunction("0x1000", Set.of("parameters"));
      assertTrue(customInitial.hasCustomVariableStorage());
      VariableStorageReference alphaStorage = customInitial.parameters().get(0).storage();
      VariableStorageReference betaStorage = customInitial.parameters().get(1).storage();
      assertNotNull(alphaStorage);
      assertNotNull(betaStorage);

      // Pure swap and type widen on custom-storage function with cloned VariableStorageReferences.
      functions.patchFunction(
          "0x1000",
          null,
          null,
          false,
          null,
          null,
          "unknown",
          FunctionAttributePatch.empty(),
          List.of(
              new ParameterPatch(
                  "beta", DataTypeReference.expression("const char *"), betaStorage),
              new ParameterPatch("alpha", DataTypeReference.expression("int"), alphaStorage)),
          null);
      FunctionResource customSwapped = functions.getFunction("0x1000", Set.of("parameters"));
      assertTrue(customSwapped.hasCustomVariableStorage());
      assertEquals("beta", customSwapped.parameters().get(0).name());
      assertEquals(
          DataTypeReference.pointerTo(DataTypeReference.named("/char")),
          customSwapped.parameters().get(0).dataType());
      assertEquals("alpha", customSwapped.parameters().get(1).name());
      assertEquals(alphaStorage, customSwapped.parameters().get(1).storage());

      // 3. C signature update on custom-storage function keeps custom storage intact!
      String r9WideSerialization =
          ((VariableStorageReference.Serialization) customSwapped.parameters().get(0).storage())
              .serialization();
      functions.patchFunction(
          "0x1000",
          null,
          null,
          false,
          null,
          null,
          null,
          FunctionAttributePatch.empty(),
          null,
          "long renamed_work(const char *msg, unsigned int count, ...)");
      FunctionResource afterSig = functions.getFunction("0x1000", Set.of("parameters"));
      assertEquals("renamed_work", afterSig.name());
      assertTrue(afterSig.hasCustomVariableStorage());
      assertTrue(afterSig.hasVarArgs());
      assertEquals(DataTypeReference.named("/long"), afterSig.returnType());
      assertEquals("msg", afterSig.parameters().get(0).name());
      assertEquals(
          r9WideSerialization,
          ((VariableStorageReference.Serialization) afterSig.parameters().get(0).storage())
              .serialization());
      assertEquals("count", afterSig.parameters().get(1).name());
      assertEquals(alphaStorage, afterSig.parameters().get(1).storage());
    } finally {
      program.endTransaction(tx, false);
      program.release(CONSUMER);
    }
  }

  private static GhidraSession testSession(Program program) {
    GhidraScript script =
        new GhidraScript() {
          @Override
          protected void run() {}
        };
    script.set(
        new GhidraState(null, null, program, null, null, null),
        TaskMonitor.DUMMY,
        new PrintWriter(Writer.nullWriter()));
    return new GhidraSession(script);
  }
}
