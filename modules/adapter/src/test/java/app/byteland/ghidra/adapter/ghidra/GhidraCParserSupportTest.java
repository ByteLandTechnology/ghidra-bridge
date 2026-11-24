package app.byteland.ghidra.adapter.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.datatype.DataTypeReference;
import ghidra.GhidraTestApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataOrganizationImpl;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class GhidraCParserSupportTest {

  @BeforeAll
  static void initializeGhidra() throws IOException, CancelledException {
    if (!Application.isInitialized()) {
      ApplicationConfiguration config = new ApplicationConfiguration();
      config.setInitializeLogging(false);
      Application.initializeApplication(
          new GhidraTestApplicationLayout(Files.createTempDirectory("ghidra-test").toFile()),
          config);
      ClassSearcher.search(TaskMonitor.DUMMY);
    }
  }

  @Test
  void stripQualifiersRemovesCvrTokensWithoutManglingIdentifiersOrPaths() {
    assertEquals("char *", GhidraCParserSupport.stripQualifiers("const char *"));
    assertEquals(
        "unsigned int * ptr",
        GhidraCParserSupport.stripQualifiers("const volatile unsigned int * __restrict ptr"));
    assertEquals(
        "const_value *",
        GhidraCParserSupport.stripQualifiers("const const_value * volatile"));
    assertEquals(
        "/My const Types/const_struct *",
        GhidraCParserSupport.stripQualifiers("/My const Types/const_struct const *"));
  }

  @Test
  void resolvesAllEightStandardCTypeFormsAndLeavesZeroOrphansOnErrors() {
    try (StandAloneDataTypeManager manager =
        new StandAloneDataTypeManager("test_prog", DataOrganizationImpl.getDefaultOrganization())) {
      int tx = manager.startTransaction("setup");
      try {
        StructureDataType foo = new StructureDataType(CategoryPath.ROOT, "Foo", 0, manager);
        foo.add(IntegerDataType.dataType, "field", null);
        manager.addDataType(foo, DataTypeConflictHandler.DEFAULT_HANDLER);

        StructureDataType catType =
            new StructureDataType(new CategoryPath("/My const Dir"), "Bar", 0, manager);
        catType.add(IntegerDataType.dataType, "x", null);
        manager.addDataType(catType, DataTypeConflictHandler.DEFAULT_HANDLER);

        // 1. int
        assertEquals(
            DataTypeReference.named("/int"),
            resolveCanonical(manager, "int"));
        // 2. unsigned int
        assertEquals(
            DataTypeReference.named("/uint"),
            resolveCanonical(manager, "unsigned int"));
        // 3. const char *
        assertEquals(
            DataTypeReference.pointerTo(DataTypeReference.named("/char")),
            resolveCanonical(manager, "const char *"));
        // 4. struct Foo *
        assertEquals(
            DataTypeReference.pointerTo(DataTypeReference.named("/Foo")),
            resolveCanonical(manager, "struct Foo *"));
        // 5. uint32_t[16]
        assertEquals(
            DataTypeReference.arrayOf(DataTypeReference.named("/uint32_t"), 16),
            resolveCanonical(manager, "uint32_t[16]"));
        // 6. int (*)[4] (pointer to array of 4 ints, distinct from array of 4 int pointers)
        assertEquals(
            DataTypeReference.pointerTo(
                DataTypeReference.arrayOf(DataTypeReference.named("/int"), 4)),
            resolveCanonical(manager, "int (*)[4]"));
        assertEquals(
            DataTypeReference.arrayOf(
                DataTypeReference.pointerTo(DataTypeReference.named("/int")), 4),
            resolveCanonical(manager, "int *[4]"));
        // 7. void (*)(int)
        DataType fnPtr =
            GhidraDataTypeReferences.resolve(manager, DataTypeReference.cType("void (*)(int)"));
        Pointer pointer = assertInstanceOf(Pointer.class, fnPtr);
        FunctionDefinition fnDef = assertInstanceOf(FunctionDefinition.class, pointer.getDataType());
        assertEquals(1, fnDef.getArguments().length);
        assertEquals("/int", fnDef.getArguments()[0].getDataType().getPathName());
        // 8. void * and untyped pointer shorthand
        assertEquals(
            DataTypeReference.pointerTo(DataTypeReference.named("/void")),
            resolveCanonical(manager, "void *"));
        assertEquals(
            DataTypeReference.untypedPointer(),
            resolveCanonical(manager, "pointer"));
        // Category path that contains a qualifier word
        assertEquals(
            DataTypeReference.pointerTo(DataTypeReference.named("/My const Dir/Bar")),
            resolveCanonical(manager, "/My const Dir/Bar const *"));

        int countBeforeFailures = countDataTypes(manager);
        assertThrows(
            IllegalArgumentException.class,
            () ->
                GhidraDataTypeReferences.resolve(
                    manager, DataTypeReference.cType("struct MissingStruct *")));
        assertThrows(
            IllegalArgumentException.class,
            () ->
                GhidraDataTypeReferences.resolve(
                    manager, DataTypeReference.cType("void (*)(NonExistentType)")));
        assertThrows(
            IllegalArgumentException.class,
            () ->
                GhidraDataTypeReferences.resolve(manager, DataTypeReference.cType("int (*)[0]")));
        assertEquals(countBeforeFailures, countDataTypes(manager));
      } finally {
        manager.endTransaction(tx, true);
      }
    }
  }

  @Test
  void parseCHeaderCreatesMultiTypeGraphAndRejectsIncludesOrSyntaxErrorsCleanly() {
    try (StandAloneDataTypeManager manager =
        new StandAloneDataTypeManager("test_prog", DataOrganizationImpl.getDefaultOrganization())) {
      int tx = manager.startTransaction("parse_header");
      try {
        int baselineCount = countDataTypes(manager);
        assertThrows(
            IllegalArgumentException.class,
            () ->
                GhidraCParserSupport.parseCHeader(
                    manager, "#include <stdio.h>\nstruct Bad { int x; };", "/hdr"));
        assertEquals(baselineCount, countDataTypes(manager));

        assertThrows(
            IllegalArgumentException.class,
            () ->
                GhidraCParserSupport.parseCHeader(
                    manager, "struct Good { int a; };\nstruct Broken { MissingType b; };", "/hdr"));
        assertNull(manager.getDataType("/hdr/Good"));
        assertEquals(baselineCount, countDataTypes(manager));

        String header =
            """
            enum PacketState {
              STATE_IDLE = 0,
              STATE_ACTIVE = 1
            };
            struct PacketNode {
              struct PacketNode *next;
              const char * restrict payload;
              uint32_t words[4];
            };
            typedef struct PacketNode PacketNode_t;
            union PacketValue {
              uint32_t raw;
              PacketNode_t *node;
            };
            int dispatch_packet(const PacketNode_t *pkt, enum PacketState state);
            """;
        List<DataType> created = GhidraCParserSupport.parseCHeader(manager, header, "/hdr");
        assertEquals(5, created.size());
        assertInstanceOf(ghidra.program.model.data.Enum.class, manager.getDataType("/hdr/PacketState"));
        Structure structType = assertInstanceOf(Structure.class, manager.getDataType("/hdr/PacketNode"));
        assertEquals(3, structType.getNumComponents());
        Array wordsArray = assertInstanceOf(Array.class, structType.getComponent(2).getDataType());
        assertEquals(4, wordsArray.getNumElements());
        assertInstanceOf(TypeDef.class, manager.getDataType("/hdr/PacketNode_t"));
        assertInstanceOf(Union.class, manager.getDataType("/hdr/PacketValue"));
        FunctionDefinition fn =
            assertInstanceOf(FunctionDefinition.class, manager.getDataType("/hdr/dispatch_packet"));
        assertEquals(2, fn.getArguments().length);

        // A second parse in the same category replaces prior definitions cleanly.
        String updatedHeader =
            """
            struct PacketNode {
              struct PacketNode *next;
              const char *tag;
              volatile int (*matrix)[4];
              uint32_t flags;
            };
            typedef struct PacketNode PacketNode_t;
            typedef struct SameTag {
              int id;
            } SameTag;
            """;
        List<DataType> reimported =
            GhidraCParserSupport.parseCHeader(manager, updatedHeader, "/hdr");
        assertEquals(3, reimported.size());
        Structure updatedStruct =
            assertInstanceOf(Structure.class, manager.getDataType("/hdr/PacketNode"));
        assertEquals(4, updatedStruct.getNumComponents());
        Pointer matrixPtr =
            assertInstanceOf(Pointer.class, updatedStruct.getComponent(2).getDataType());
        Array matrixArr = assertInstanceOf(Array.class, matrixPtr.getDataType());
        assertEquals(4, matrixArr.getNumElements());
        assertInstanceOf(Structure.class, manager.getDataType("/hdr/SameTag"));
      } finally {
        manager.endTransaction(tx, true);
      }
    }
  }

  @Test
  void parseFunctionSignatureSupportsFunctionPointerAndPointerToArrayParameters() {
    try (StandAloneDataTypeManager manager =
        new StandAloneDataTypeManager("test_prog", DataOrganizationImpl.getDefaultOrganization())) {
      int tx = manager.startTransaction("sig");
      try {
        var parsed =
            GhidraCParserSupport.parseFunctionSignature(
                manager,
                null,
                "int process_matrix(const int (*matrix)[4], void (*on_row)(int), uint32_t count)");
        assertEquals("process_matrix", parsed.definition().getName());
        assertEquals(3, parsed.definition().getArguments().length);
        DataType arg0 = parsed.definition().getArguments()[0].getDataType();
        assertEquals(
            DataTypeReference.pointerTo(
                DataTypeReference.arrayOf(DataTypeReference.named("/int"), 4)),
            GhidraDataTypeReferences.toReference(arg0));
        DataType arg1 = parsed.definition().getArguments()[1].getDataType();
        Pointer cbPtr = assertInstanceOf(Pointer.class, arg1);
        assertInstanceOf(FunctionDefinition.class, cbPtr.getDataType());
        assertTrue(
            parsed.definition().getArguments()[2].getDataType().getPathName().endsWith("uint32_t"));
      } finally {
        manager.endTransaction(tx, true);
      }
    }
  }

  private static DataTypeReference resolveCanonical(
      StandAloneDataTypeManager manager, String declaration) {
    DataType resolved =
        GhidraDataTypeReferences.resolve(manager, DataTypeReference.cType(declaration));
    return GhidraDataTypeReferences.toReference(resolved);
  }

  private static int countDataTypes(StandAloneDataTypeManager manager) {
    List<DataType> list = new ArrayList<>();
    manager.getAllDataTypes(list);
    return list.size();
  }
}
