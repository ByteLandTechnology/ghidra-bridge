package app.byteland.ghidra.adapter.ghidra.datatype;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.service.datatype.DataTypeMutationValidationException;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeResource;
import app.byteland.ghidra.service.datatype.DataTypeService.ConflictMode;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import java.io.File;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class GhidraCDeclarationsAndReferencesTest {

  @BeforeAll
  static void initializeGhidraIfNeeded() throws Exception {
    if (Application.isInitialized()) {
      return;
    }
    String installDir = System.getenv("GHIDRA_INSTALL_DIR");
    if (installDir != null && !installDir.isBlank()) {
      ApplicationConfiguration config = new ApplicationConfiguration();
      Application.initializeApplication(new GhidraApplicationLayout(new File(installDir)), config);
    }
  }

  @Test
  void resolvesCTypeExpressionsIncludingQualifiersArraysAndFunctionPointers() {
    try (StandAloneDataTypeManager dtm = new StandAloneDataTypeManager("test-c-refs")) {
      int tx = dtm.startTransaction("seed");
      try {
        CDeclarationParser.parseAndStore(
            dtm, "struct Socket { int fd; uint16_t port; };", "/net", ConflictMode.REPLACE);
      } finally {
        dtm.endTransaction(tx, true);
      }

      DataType constCharPtr =
          GhidraDataTypeReferences.resolve(dtm, DataTypeReference.cExpression("const char *"));
      Pointer charPtr = assertInstanceOf(Pointer.class, constCharPtr);
      assertEquals("char", charPtr.getDataType().getName());

      DataType volatileU32Ptr =
          GhidraDataTypeReferences.resolve(
              dtm, DataTypeReference.cExpression("volatile uint32_t * restrict"));
      Pointer u32Ptr = assertInstanceOf(Pointer.class, volatileU32Ptr);
      assertEquals(4, u32Ptr.getDataType().getLength());

      DataType fixedArray =
          GhidraDataTypeReferences.resolve(dtm, DataTypeReference.cExpression("int[4]"));
      Array arrayType = assertInstanceOf(Array.class, fixedArray);
      assertEquals(4, arrayType.getNumElements());

      DataType ptrToArrayType =
          GhidraDataTypeReferences.resolve(dtm, DataTypeReference.cExpression("int (*)[4]"));
      Pointer ptrToArray = assertInstanceOf(Pointer.class, ptrToArrayType);
      Array pointedArray = assertInstanceOf(Array.class, ptrToArray.getDataType());
      assertEquals(4, pointedArray.getNumElements());

      DataType fnPtrType =
          GhidraDataTypeReferences.resolve(
              dtm, DataTypeReference.cExpression("int (*)(void *)"));
      Pointer fnPtr = assertInstanceOf(Pointer.class, fnPtrType);
      FunctionDefinition fnDef = assertInstanceOf(FunctionDefinition.class, fnPtr.getDataType());
      assertEquals(1, fnDef.getArguments().length);
      assertInstanceOf(Pointer.class, fnDef.getArguments()[0].getDataType());

      DataType qualifiedCategoryPtr =
          GhidraDataTypeReferences.resolve(
              dtm, DataTypeReference.cExpression("const /net/Socket *"));
      Pointer socketPtr = assertInstanceOf(Pointer.class, qualifiedCategoryPtr);
      assertEquals("/net/Socket", socketPtr.getDataType().getPathName());

      // Round-trip back to canonical structured DataTypeReference
      DataTypeReference canonical = GhidraDataTypeReferences.toReference(socketPtr);
      DataTypeReference.Pointer canonicalPtr =
          assertInstanceOf(DataTypeReference.Pointer.class, canonical);
      DataTypeReference.Named canonicalTarget =
          assertInstanceOf(DataTypeReference.Named.class, canonicalPtr.target());
      assertEquals("/net/Socket", canonicalTarget.name());

      IllegalArgumentException unknown =
          assertThrows(
              IllegalArgumentException.class,
              () ->
                  GhidraDataTypeReferences.resolve(
                      dtm, DataTypeReference.cExpression("UnknownWidget *")));
      assertFalse(unknown.getMessage().contains("<html>"));
    }
  }

  @Test
  void parsesStructsBitfieldsUnionsEnumsTypedefsAndConflictModes() {
    try (StandAloneDataTypeManager dtm = new StandAloneDataTypeManager("test-parse-c")) {
      String declarations =
          """
          enum PacketKind { PKT_DATA = 1, PKT_ACK = 2 };
          union Payload { uint32_t word; uint8_t bytes[4]; };
          struct PacketHeader {
            uint8_t version : 4;
            uint8_t flags : 4;
            uint16_t length;
            enum PacketKind kind;
            union Payload payload;
          };
          typedef struct PacketHeader packet_header_t;
          typedef int (*packet_handler_t)(packet_header_t *hdr, const uint8_t *body, size_t len);
          """;

      int tx = dtm.startTransaction("parse");
      List<DataTypeResource> created;
      try {
        created =
            CDeclarationParser.parseAndStore(dtm, declarations, "/proto", ConflictMode.REPLACE);
      } finally {
        dtm.endTransaction(tx, true);
      }

      assertEquals(5, created.size());
      assertInstanceOf(Enum.class, dtm.getDataType("/proto/PacketKind"));
      assertInstanceOf(Union.class, dtm.getDataType("/proto/Payload"));
      Structure header = assertInstanceOf(Structure.class, dtm.getDataType("/proto/PacketHeader"));
      assertTrue(header.getNumComponents() >= 4);
      assertInstanceOf(TypeDef.class, dtm.getDataType("/proto/packet_header_t"));
      TypeDef handlerTypedef =
          assertInstanceOf(TypeDef.class, dtm.getDataType("/proto/packet_handler_t"));
      assertInstanceOf(Pointer.class, handlerTypedef.getBaseDataType());

      // ConflictMode.KEEP preserves original struct fields
      int keepTx = dtm.startTransaction("keep");
      try {
        List<DataTypeResource> kept =
            CDeclarationParser.parseAndStore(
                dtm, "struct PacketHeader { uint64_t different; };", "/proto", ConflictMode.KEEP);
        assertEquals(header.getLength(), kept.get(0).length());
      } finally {
        dtm.endTransaction(keepTx, true);
      }

      // ConflictMode.RENAME adds a .conflict suffix and keeps the prior type
      int renameTx = dtm.startTransaction("rename");
      try {
        List<DataTypeResource> renamed =
            CDeclarationParser.parseAndStore(
                dtm,
                "struct PacketHeader { uint64_t different; };",
                "/proto",
                ConflictMode.RENAME);
        assertEquals(1, renamed.size());
        assertTrue(renamed.get(0).name().startsWith("PacketHeader.conflict"));
        assertNotNull(dtm.getDataType("/proto/PacketHeader"));
      } finally {
        dtm.endTransaction(renameTx, true);
      }

      // Malformed C throws DataTypeMutationValidationException (400) and closes all sub-transactions
      DataTypeMutationValidationException syntaxError =
          assertThrows(
              DataTypeMutationValidationException.class,
              () ->
                  CDeclarationParser.parseAndStore(
                      dtm,
                      "struct Broken { MissingType x; };",
                      "/proto",
                      ConflictMode.REPLACE));
      assertEquals(400, syntaxError.status());
      assertEquals("declarations", syntaxError.target());
      assertFalse(syntaxError.getMessage().contains("<html>"));
      assertNull(dtm.getDataType("/proto/Broken"));
    }
  }
}
