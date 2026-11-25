package app.byteland.ghidra.adapter.ghidra.datatype;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.GhidraServiceFactory;
import app.byteland.ghidra.adapter.ghidra.GhidraTestSupport;
import app.byteland.ghidra.api.ApiException;
import app.byteland.ghidra.api.ApiFailures;
import app.byteland.ghidra.api.ApiRegistry;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.datatype.DataTypeResource;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class DataTypeMutationsTest {

  @Test
  void upsertsFullLayoutsAcrossKindsAndPreservesExistingReferences() {
    try (GhidraTestSupport.ProgramHolder holder =
        GhidraTestSupport.createX64Program("upsert-layouts")) {
      TestBridge bridge = new TestBridge(holder.program());

      // Create self-referential struct Node { Node *next; int id; } with fixed offset gap and size.
      bridge.dispatch(
          "data_type.upsert",
          Map.of(
              "resource",
              Map.of(
                  "kind",
                  "struct",
                  "category_path",
                  "/net",
                  "name",
                  "Node",
                  "size",
                  24,
                  "fields",
                  List.of(
                      Map.of(
                          "name",
                          "next",
                          "offset",
                          0,
                          "data_type",
                          Map.of(
                              "kind", "pointer", "target", Map.of("kind", "named", "name", "/net/Node")),
                          "comment",
                          "Next linked node"),
                      Map.of(
                          "name",
                          "id",
                          "offset",
                          12,
                          "data_type",
                          Map.of("kind", "named", "name", "int"),
                          "comment",
                          "Node identifier")))));

      DataTypeResource initialNode = bridge.services.dataTypeService().getDataType("/net/Node");
      assertEquals(DataTypeResource.Kind.STRUCT, initialNode.kind());
      assertEquals(24, initialNode.size());
      List<DataTypeResource.Field> initialDefined =
          initialNode.fields().stream().filter(f -> !f.isUndefined()).toList();
      assertEquals(2, initialDefined.size());
      assertEquals("next", initialDefined.get(0).name());
      assertEquals(0, initialDefined.get(0).offset());
      assertEquals(8, initialDefined.get(0).length());
      assertEquals("Next linked node", initialDefined.get(0).comment());
      assertEquals("id", initialDefined.get(1).name());
      assertEquals(12, initialDefined.get(1).offset());
      assertEquals("Node identifier", initialDefined.get(1).comment());

      // Build dependent types that reference /net/Node: enum State, union Payload,
      // typedef NodeAlias, parent struct Envelope, and function signature ProcessNode.
      bridge.dispatch(
          "data_type.create",
          Map.of(
              "resource",
              Map.of(
                  "kind",
                  "enum",
                  "category_path",
                  "/net",
                  "name",
                  "State",
                  "size",
                  4,
                  "values",
                  List.of(
                      Map.of("name", "INIT", "value", 0, "comment", "Initial"),
                      Map.of("name", "ACTIVE", "value", 1, "comment", "Active")))));

      bridge.dispatch(
          "data_type.create",
          Map.of(
              "resource",
              Map.of(
                  "kind",
                  "union",
                  "category_path",
                  "/net",
                  "name",
                  "Payload",
                  "fields",
                  List.of(
                      Map.of(
                          "name",
                          "node_ptr",
                          "data_type",
                          Map.of(
                              "kind", "pointer", "target", Map.of("kind", "named", "name", "/net/Node")),
                          "comment",
                          "Pointer arm"),
                      Map.of(
                          "name",
                          "state",
                          "data_type",
                          Map.of("kind", "named", "name", "/net/State"),
                          "comment",
                          "State arm")))));

      bridge.dispatch(
          "data_type.create",
          Map.of(
              "resource",
              Map.of(
                  "kind",
                  "typedef",
                  "category_path",
                  "/net",
                  "name",
                  "NodeAlias",
                  "base_type",
                  Map.of("kind", "named", "name", "/net/Node"))));

      bridge.dispatch(
          "data_type.create",
          Map.of(
              "resource",
              Map.of(
                  "kind",
                  "struct",
                  "category_path",
                  "/net",
                  "name",
                  "Envelope",
                  "fields",
                  List.of(
                      Map.of(
                          "name",
                          "embedded",
                          "offset",
                          0,
                          "data_type",
                          Map.of("kind", "named", "name", "/net/Node")),
                      Map.of(
                          "name",
                          "payload",
                          "offset",
                          32,
                          "data_type",
                          Map.of("kind", "named", "name", "/net/Payload"))))));

      bridge.dispatch(
          "data_type.upsert",
          Map.of(
              "resource",
              Map.of(
                  "kind",
                  "function",
                  "category_path",
                  "/net",
                  "name",
                  "ProcessNode",
                  "signature",
                  Map.of(
                      "return_type",
                      Map.of("kind", "named", "name", "/net/State"),
                      "parameters",
                      List.of(
                          Map.of(
                              "name",
                              "item",
                              "data_type",
                              Map.of(
                                  "kind",
                                  "pointer",
                                  "target",
                                  Map.of("kind", "named", "name", "/net/NodeAlias")))),
                      "calling_convention",
                      "default",
                      "has_var_args",
                      false,
                      "has_no_return",
                      false))));

      // Upsert /net/Node in place with a new 32-byte layout and new comments.
      // Also upsert /net/State in place.
      bridge.dispatch(
          "data_type.upsert",
          Map.of(
              "resource",
              Map.of(
                  "kind",
                  "struct",
                  "category_path",
                  "/net",
                  "name",
                  "Node",
                  "size",
                  32,
                  "fields",
                  List.of(
                      Map.of(
                          "name",
                          "id",
                          "offset",
                          0,
                          "data_type",
                          Map.of("kind", "named", "name", "ulonglong"),
                          "comment",
                          "64-bit id moved to offset 0"),
                      Map.of(
                          "name",
                          "next",
                          "offset",
                          16,
                          "data_type",
                          Map.of(
                              "kind", "pointer", "target", Map.of("kind", "named", "name", "/net/Node")),
                          "comment",
                          "Moved pointer"),
                      Map.of(
                          "name",
                          "state",
                          "offset",
                          24,
                          "data_type",
                          Map.of("kind", "named", "name", "/net/State"))))));

      bridge.dispatch(
          "data_type.upsert",
          Map.of(
              "resource",
              Map.of(
                  "kind",
                  "enum",
                  "category_path",
                  "/net",
                  "name",
                  "State",
                  "size",
                  4,
                  "values",
                  List.of(
                      Map.of("name", "INIT", "value", 0, "comment", "Booting"),
                      Map.of("name", "CLOSED", "value", 9, "comment", "Closed")))));

      DataTypeResource updatedNode = bridge.services.dataTypeService().getDataType("/net/Node");
      assertEquals(32, updatedNode.size());
      List<DataTypeResource.Field> updatedDefined =
          updatedNode.fields().stream().filter(f -> !f.isUndefined()).toList();
      assertEquals(3, updatedDefined.size());
      assertEquals("id", updatedDefined.get(0).name());
      assertEquals(0, updatedDefined.get(0).offset());
      assertEquals("64-bit id moved to offset 0", updatedDefined.get(0).comment());
      assertEquals("next", updatedDefined.get(1).name());
      assertEquals(16, updatedDefined.get(1).offset());
      assertEquals("Moved pointer", updatedDefined.get(1).comment());

      // Check that references update in place without .conflict duplicates.
      DataTypeResource envelope = bridge.services.dataTypeService().getDataType("/net/Envelope");
      assertEquals(40, envelope.size());
      assertEquals(32, envelope.fields().get(0).length());
      assertEquals(32, envelope.fields().get(1).offset());
      assertNotNull(envelope.fields().get(0).dataType());
      assertNull(holder.program().getDataTypeManager().getDataType("/net/Node.conflict"));

      DataTypeResource state = bridge.services.dataTypeService().getDataType("/net/State");
      assertEquals(2, state.values().size());
      assertEquals("Booting", state.values().get(0).comment());
      assertEquals("CLOSED", state.values().get(1).name());
      assertEquals(9L, state.values().get(1).value());
      assertEquals("Closed", state.values().get(1).comment());

      DataTypeResource alias = bridge.services.dataTypeService().getDataType("/net/NodeAlias");
      assertEquals(32, alias.length());

      DataTypeResource fn = bridge.services.dataTypeService().getDataType("/net/ProcessNode");
      assertEquals(1, fn.signature().parameters().size());
    }
  }

  @Test
  void structPatchSupportsPreserveOffsetsModeByteShiftingUndefinedSlotsAndPackedStructs() {
    try (GhidraTestSupport.ProgramHolder holder =
        GhidraTestSupport.createX64Program("struct-patch-modes")) {
      TestBridge bridge = new TestBridge(holder.program());

      // Create 16-byte struct with alpha at 0x0 (4B), gap at 0x4..0x7, beta at 0x8 (4B), gap 0xc..0xf.
      bridge.dispatch(
          "data_type.create",
          Map.of(
              "resource",
              Map.of(
                  "kind",
                  "struct",
                  "category_path",
                  "/layout",
                  "name",
                  "Frame",
                  "size",
                  16,
                  "fields",
                  List.of(
                      Map.of(
                          "name",
                          "alpha",
                          "offset",
                          0,
                          "data_type",
                          Map.of("kind", "named", "name", "int"),
                          "comment",
                          "First field"),
                      Map.of(
                          "name",
                          "beta",
                          "offset",
                          8,
                          "data_type",
                          Map.of("kind", "named", "name", "int"),
                          "comment",
                          "Anchored at 0x8")))));

      // Default preserve_offsets=true: remove alpha (0x0..0x3) -> beta MUST stay at offset 8!
      bridge.dispatch(
          "data_type.patch",
          Map.of(
              "selector",
              Map.of("path", "/layout/Frame"),
              "patch",
              Map.of("kind", "struct", "remove_fields", List.of(Map.of("name", "alpha")))));

      DataTypeResource afterClear = bridge.services.dataTypeService().getDataType("/layout/Frame");
      assertEquals(16, afterClear.size());
      DataTypeResource.Field betaAfterClear =
          afterClear.fields().stream().filter(f -> "beta".equals(f.name())).findFirst().orElseThrow();
      assertEquals(8, betaAfterClear.offset());
      assertEquals("Anchored at 0x8", betaAfterClear.comment());

      // Materialize undefined byte slots:
      // - at offset 0: assign concrete short (2B) + name + comment with update_fields
      // - at offset 4: assign comment + name on raw undefined placeholder bytes without data_type
      bridge.dispatch(
          "data_type.patch",
          Map.of(
              "selector",
              Map.of("path", "/layout/Frame"),
              "patch",
              Map.of(
                  "kind",
                  "struct",
                  "update_fields",
                  List.of(
                      Map.of(
                          "offset",
                          0,
                          "new_name",
                          "header",
                          "data_type",
                          Map.of("kind", "named", "name", "ushort"),
                          "comment",
                          "2-byte header"),
                      Map.of(
                          "offset",
                          4,
                          "length",
                          2,
                          "new_name",
                          "reserved_gap",
                          "comment",
                          "Reserved bytes")),
                  "add_fields",
                  List.of(
                      Map.of(
                          "name",
                          "tail",
                          "offset",
                          12,
                          "data_type",
                          Map.of("kind", "named", "name", "uint"),
                          "comment",
                          "Tail field")))));

      DataTypeResource afterUndefinedUpdate =
          bridge.services.dataTypeService().getDataType("/layout/Frame");
      assertEquals(16, afterUndefinedUpdate.size());
      Map<Integer, DataTypeResource.Field> byOffset = new LinkedHashMap<>();
      for (DataTypeResource.Field f : afterUndefinedUpdate.fields()) {
        byOffset.put(f.offset(), f);
      }
      assertEquals("header", byOffset.get(0).name());
      assertEquals(2, byOffset.get(0).length());
      assertEquals("2-byte header", byOffset.get(0).comment());
      assertFalse(byOffset.get(0).isUndefined());
      assertTrue(byOffset.get(2).isUndefined());
      assertEquals("reserved_gap", byOffset.get(4).name());
      assertEquals(2, byOffset.get(4).length());
      assertEquals("Reserved bytes", byOffset.get(4).comment());
      assertFalse(byOffset.get(4).isUndefined());
      assertEquals("beta", byOffset.get(8).name());
      assertEquals("tail", byOffset.get(12).name());
      assertEquals("Tail field", byOffset.get(12).comment());

      // Grow header at offset 0 from 2B ushort to 4B uint across undefined gap bytes.
      // Then shrink header back to 2B ushort and keep beta at offset 8.
      bridge.dispatch(
          "data_type.patch",
          Map.of(
              "selector",
              Map.of("path", "/layout/Frame"),
              "patch",
              Map.of(
                  "kind",
                  "struct",
                  "update_fields",
                  List.of(
                      Map.of(
                          "name",
                          "header",
                          "data_type",
                          Map.of("kind", "named", "name", "uint"))))));
      DataTypeResource afterHeaderGrow =
          bridge.services.dataTypeService().getDataType("/layout/Frame");
      assertEquals(4, afterHeaderGrow.fields().getFirst().length());
      assertEquals(
          8,
          afterHeaderGrow.fields().stream()
              .filter(f -> "beta".equals(f.name()))
              .findFirst()
              .orElseThrow()
              .offset());

      bridge.dispatch(
          "data_type.patch",
          Map.of(
              "selector",
              Map.of("path", "/layout/Frame"),
              "patch",
              Map.of(
                  "kind",
                  "struct",
                  "update_fields",
                  List.of(
                      Map.of(
                          "name",
                          "header",
                          "data_type",
                          Map.of("kind", "named", "name", "ushort"))))));

      // Explicit preserve_offsets: false shifts later fields on remove and insertAtOffset.
      bridge.dispatch(
          "data_type.patch",
          Map.of(
              "selector",
              Map.of("path", "/layout/Frame"),
              "patch",
              Map.of(
                  "kind",
                  "struct",
                  "preserve_offsets",
                  false,
                  "remove_fields",
                  List.of(Map.of("offset", 0)),
                  "add_fields",
                  List.of(
                      Map.of(
                          "name",
                          "inserted",
                          "offset",
                          0,
                          "data_type",
                          Map.of("kind", "named", "name", "ulonglong"))))));

      DataTypeResource afterShift = bridge.services.dataTypeService().getDataType("/layout/Frame");
      DataTypeResource.Field betaShifted =
          afterShift.fields().stream().filter(f -> "beta".equals(f.name())).findFirst().orElseThrow();
      // Deletion of 2-byte header shifted beta from 8 to 6; 8-byte ulonglong at 0 shifted 6 to 14.
      assertEquals(14, betaShifted.offset());

      // Verify packed struct compatibility across upsert and patch.
      holder.inTransaction(
          program -> {
            StructureDataType packed =
                new StructureDataType(new CategoryPath("/layout"), "Packed", 0, program.getDataTypeManager());
            packed.setPackingEnabled(true);
            packed.add(IntegerDataType.dataType, "a", "first");
            program.getDataTypeManager().addDataType(packed, DataTypeConflictHandler.DEFAULT_HANDLER);
          });

      bridge.dispatch(
          "data_type.upsert",
          Map.of(
              "resource",
              Map.of(
                  "kind",
                  "struct",
                  "category_path",
                  "/layout",
                  "name",
                  "Packed",
                  "fields",
                  List.of(
                      Map.of("name", "tag", "data_type", Map.of("kind", "named", "name", "byte")),
                      Map.of("name", "aligned", "data_type", Map.of("kind", "named", "name", "int"))))));

      DataType packedResolved =
          holder.program().getDataTypeManager().getDataType(new CategoryPath("/layout"), "Packed");
      assertTrue(((Structure) packedResolved).isPackingEnabled());
      assertEquals(8, packedResolved.getLength()); // 1-byte tag + 3-byte alignment + 4-byte int

      bridge.dispatch(
          "data_type.patch",
          Map.of(
              "selector",
              Map.of("path", "/layout/Packed"),
              "patch",
              Map.of(
                  "kind",
                  "struct",
                  "add_fields",
                  List.of(
                      Map.of(
                          "name",
                          "extra",
                          "data_type",
                          Map.of("kind", "named", "name", "short"),
                          "comment",
                          "Packed extra")))));
      DataTypeResource packedAfterPatch =
          bridge.services.dataTypeService().getDataType("/layout/Packed");
      assertEquals(12, packedAfterPatch.size());
      assertEquals(
          "Packed extra",
          packedAfterPatch.fields().stream()
              .filter(f -> "extra".equals(f.name()))
              .findFirst()
              .orElseThrow()
              .comment());
    }
  }

  @Test
  void memberCommentsPreserveWhenOmittedAndClearWhenNullAcrossStructUnionAndEnum() {
    try (GhidraTestSupport.ProgramHolder holder =
        GhidraTestSupport.createX64Program("member-comments")) {
      TestBridge bridge = new TestBridge(holder.program());

      bridge.dispatch(
          "data_type.create",
          Map.of(
              "resource",
              Map.of(
                  "kind",
                  "union",
                  "category_path",
                  "/doc",
                  "name",
                  "RegisterView",
                  "fields",
                  List.of(
                      Map.of(
                          "name",
                          "raw",
                          "data_type",
                          Map.of("kind", "named", "name", "uint"),
                          "comment",
                          "Original union comment")))));

      // Rename without comment key -> preserves "Original union comment".
      bridge.dispatch(
          "data_type.patch",
          Map.of(
              "selector",
              Map.of("path", "/doc/RegisterView"),
              "patch",
              Map.of(
                  "kind",
                  "union",
                  "rename_fields",
                  List.of(Map.of("name", "raw", "new_name", "raw32")))));
      assertEquals(
          "Original union comment",
          bridge
              .services
              .dataTypeService()
              .getDataType("/doc/RegisterView")
              .fields()
              .getFirst()
              .comment());

      // Update with comment: null -> clears comment.
      Map<String, Object> clearUnionComment = new LinkedHashMap<>();
      clearUnionComment.put("name", "raw32");
      clearUnionComment.put("comment", null);
      bridge.dispatch(
          "data_type.patch",
          Map.of(
              "selector",
              Map.of("path", "/doc/RegisterView"),
              "patch",
              Map.of("kind", "union", "update_fields", List.of(clearUnionComment))));
      assertNull(
          bridge
              .services
              .dataTypeService()
              .getDataType("/doc/RegisterView")
              .fields()
              .getFirst()
              .comment());

      // Enum add_values, rename_values (preserve comment), update_values (set & clear comment).
      bridge.dispatch(
          "data_type.create",
          Map.of(
              "resource",
              Map.of(
                  "kind",
                  "enum",
                  "category_path",
                  "/doc",
                  "name",
                  "Flags",
                  "values",
                  List.of(Map.of("name", "READ", "value", 1, "comment", "Readable")))));

      bridge.dispatch(
          "data_type.patch",
          Map.of(
              "selector",
              Map.of("path", "/doc/Flags"),
              "patch",
              Map.of(
                  "kind",
                  "enum",
                  "add_values",
                  List.of(Map.of("name", "WRITE", "value", 2, "comment", "Writable")),
                  "rename_values",
                  List.of(Map.of("name", "READ", "new_name", "PERM_READ")))));

      DataTypeResource flagsAfterRename = bridge.services.dataTypeService().getDataType("/doc/Flags");
      assertEquals("Readable", flagsAfterRename.values().get(0).comment());
      assertEquals("Writable", flagsAfterRename.values().get(1).comment());

      Map<String, Object> clearEnumComment = new LinkedHashMap<>();
      clearEnumComment.put("name", "PERM_READ");
      clearEnumComment.put("comment", null);
      bridge.dispatch(
          "data_type.patch",
          Map.of(
              "selector",
              Map.of("path", "/doc/Flags"),
              "patch",
              Map.of(
                  "kind",
                  "enum",
                  "update_values",
                  List.of(
                      clearEnumComment,
                      Map.of("name", "WRITE", "comment", "Mutated comment")))));

      DataTypeResource flagsAfterClear = bridge.services.dataTypeService().getDataType("/doc/Flags");
      assertEquals("", flagsAfterClear.values().get(0).comment());
      assertEquals("Mutated comment", flagsAfterClear.values().get(1).comment());
    }
  }

  @Test
  void rejectsOverlapsKindCollisionsAndRecursiveCompositeOrTypedefCyclesWithHttp400() {
    try (GhidraTestSupport.ProgramHolder holder =
        GhidraTestSupport.createX64Program("validation-edge-cases")) {
      TestBridge bridge = new TestBridge(holder.program());

      // 1. Fixed-offset field overlap in upsert returns HTTP 400.
      assertStatus400(
          () ->
              bridge.dispatch(
                  "data_type.upsert",
                  Map.of(
                      "resource",
                      Map.of(
                          "kind",
                          "struct",
                          "category_path",
                          "/err",
                          "name",
                          "OverlapStruct",
                          "fields",
                          List.of(
                              Map.of(
                                  "name",
                                  "a",
                                  "offset",
                                  0,
                                  "data_type",
                                  Map.of("kind", "named", "name", "int")),
                              Map.of(
                                  "name",
                                  "b",
                                  "offset",
                                  2,
                                  "data_type",
                                  Map.of("kind", "named", "name", "int")))))));
      assertNull(holder.program().getDataTypeManager().getDataType("/err/OverlapStruct"));

      // 2. Fixed-offset field overlap in preserve_offsets=true patch returns HTTP 400.
      bridge.dispatch(
          "data_type.create",
          Map.of(
              "resource",
              Map.of(
                  "kind",
                  "struct",
                  "category_path",
                  "/err",
                  "name",
                  "SafeStruct",
                  "size",
                  16,
                  "fields",
                  List.of(
                      Map.of(
                          "name",
                          "first",
                          "offset",
                          0,
                          "data_type",
                          Map.of("kind", "named", "name", "int")),
                      Map.of(
                          "name",
                          "second",
                          "offset",
                          4,
                          "data_type",
                          Map.of("kind", "named", "name", "int"))))));

      assertStatus400(
          () ->
              bridge.dispatch(
                  "data_type.patch",
                  Map.of(
                      "selector",
                      Map.of("path", "/err/SafeStruct"),
                      "patch",
                      Map.of(
                          "kind",
                          "struct",
                          "add_fields",
                          List.of(
                              Map.of(
                                  "name",
                                  "collide",
                                  "offset",
                                  2,
                                  "data_type",
                                  Map.of("kind", "named", "name", "int")))))));

      assertStatus400(
          () ->
              bridge.dispatch(
                  "data_type.patch",
                  Map.of(
                      "selector",
                      Map.of("path", "/err/SafeStruct"),
                      "patch",
                      Map.of(
                          "kind",
                          "struct",
                          "update_fields",
                          List.of(
                              Map.of(
                                  "name",
                                  "first",
                                  "data_type",
                                  Map.of("kind", "named", "name", "ulonglong")))))));

      // 3. Kind collisions on upsert and patch -> HTTP 400.
      assertStatus400(
          () ->
              bridge.dispatch(
                  "data_type.upsert",
                  Map.of(
                      "resource",
                      Map.of("kind", "enum", "category_path", "/err", "name", "SafeStruct"))));
      assertStatus400(
          () ->
              bridge.dispatch(
                  "data_type.upsert",
                  Map.of("resource", Map.of("kind", "struct", "category_path", "/", "name", "int"))));
      assertStatus400(
          () ->
              bridge.dispatch(
                  "data_type.patch",
                  Map.of(
                      "selector",
                      Map.of("path", "/err/SafeStruct"),
                      "patch",
                      Map.of(
                          "kind",
                          "typedef",
                          "base_type",
                          Map.of("kind", "named", "name", "uint")))));

      // 4. Valid typedef patch + valid forward-pointer typedef cycle (typedef struct Node *NodePtr),
      //    and HTTP 400 rejection for direct/indirect/pointer-self/composite typedef & struct cycles!
      bridge.dispatch(
          "data_type.create",
          Map.of(
              "resource",
              Map.of(
                  "kind",
                  "typedef",
                  "category_path",
                  "/err",
                  "name",
                  "AliasA",
                  "base_type",
                  Map.of("kind", "named", "name", "int"))));
      bridge.dispatch(
          "data_type.create",
          Map.of(
              "resource",
              Map.of(
                  "kind",
                  "typedef",
                  "category_path",
                  "/err",
                  "name",
                  "AliasB",
                  "base_type",
                  Map.of("kind", "named", "name", "/err/AliasA"))));

      // Valid non-cyclic typedef patch (AliasB -> uint).
      bridge.dispatch(
          "data_type.patch",
          Map.of(
              "selector",
              Map.of("path", "/err/AliasB"),
              "patch",
              Map.of("kind", "typedef", "base_type", Map.of("kind", "named", "name", "uint"))));
      assertEquals(
          DataTypeResource.Kind.TYPEDEF,
          bridge.services.dataTypeService().getDataType("/err/AliasB").kind());

      // Point AliasB back to AliasA, then reject AliasA -> AliasB (2-hop typedef cycle) on both patch and upsert!
      bridge.dispatch(
          "data_type.patch",
          Map.of(
              "selector",
              Map.of("path", "/err/AliasB"),
              "patch",
              Map.of("kind", "typedef", "base_type", Map.of("kind", "named", "name", "/err/AliasA"))));

      assertStatus400(
          () ->
              bridge.dispatch(
                  "data_type.patch",
                  Map.of(
                      "selector",
                      Map.of("path", "/err/AliasA"),
                      "patch",
                      Map.of(
                          "kind",
                          "typedef",
                          "base_type",
                          Map.of("kind", "named", "name", "/err/AliasB")))));
      assertStatus400(
          () ->
              bridge.dispatch(
                  "data_type.upsert",
                  Map.of(
                      "resource",
                      Map.of(
                          "kind",
                          "typedef",
                          "category_path",
                          "/err",
                          "name",
                          "AliasA",
                          "base_type",
                          Map.of("kind", "pointer", "target", Map.of("kind", "named", "name", "/err/AliasA"))))));

      // Direct and indirect struct or union value cycles return HTTP 400 and keep SafeStruct intact.
      assertStatus400(
          () ->
              bridge.dispatch(
                  "data_type.patch",
                  Map.of(
                      "selector",
                      Map.of("path", "/err/SafeStruct"),
                      "patch",
                      Map.of(
                          "kind",
                          "struct",
                          "add_fields",
                          List.of(
                              Map.of(
                                  "name",
                                  "self_patch",
                                  "data_type",
                                  Map.of("kind", "named", "name", "/err/SafeStruct")))))));
      assertStatus400(
          () ->
              bridge.dispatch(
                  "data_type.upsert",
                  Map.of(
                      "resource",
                      Map.of(
                          "kind",
                          "struct",
                          "category_path",
                          "/err",
                          "name",
                          "SafeStruct",
                          "fields",
                          List.of(
                              Map.of(
                                  "name",
                                  "self_by_value",
                                  "data_type",
                                  Map.of("kind", "named", "name", "/err/SafeStruct")))))));

      // Struct -> Typedef -> Struct by-value cycle rejected with HTTP 400!
      bridge.dispatch(
          "data_type.create",
          Map.of(
              "resource",
              Map.of(
                  "kind",
                  "struct",
                  "category_path",
                  "/err",
                  "name",
                  "Holder",
                  "fields",
                  List.of(
                      Map.of(
                          "name",
                          "val",
                          "data_type",
                          Map.of("kind", "named", "name", "/err/AliasA"))))));
      assertStatus400(
          () ->
              bridge.dispatch(
                  "data_type.patch",
                  Map.of(
                      "selector",
                      Map.of("path", "/err/AliasA"),
                      "patch",
                      Map.of(
                          "kind",
                          "typedef",
                          "base_type",
                          Map.of("kind", "named", "name", "/err/Holder")))));

      // Meanwhile, C forward-pointer typedef pattern (struct HolderPtrNode { NodePtr next; }; typedef NodePtr -> HolderPtrNode*) MUST succeed!
      bridge.dispatch(
          "data_type.create",
          Map.of(
              "resource",
              Map.of(
                  "kind",
                  "typedef",
                  "category_path",
                  "/err",
                  "name",
                  "NodePtr",
                  "base_type",
                  Map.of("kind", "untyped_pointer"))));
      bridge.dispatch(
          "data_type.create",
          Map.of(
              "resource",
              Map.of(
                  "kind",
                  "struct",
                  "category_path",
                  "/err",
                  "name",
                  "ListNode",
                  "fields",
                  List.of(
                      Map.of(
                          "name",
                          "next",
                          "data_type",
                          Map.of("kind", "named", "name", "/err/NodePtr"))))));
      bridge.dispatch(
          "data_type.patch",
          Map.of(
              "selector",
              Map.of("path", "/err/NodePtr"),
              "patch",
              Map.of(
                  "kind",
                  "typedef",
                  "base_type",
                  Map.of(
                      "kind",
                      "pointer",
                      "target",
                      Map.of("kind", "named", "name", "/err/ListNode")))));
      assertEquals(8, bridge.services.dataTypeService().getDataType("/err/NodePtr").length());
    }
  }

  private static void assertStatus400(Runnable action) {
    Throwable thrown = assertThrows(Throwable.class, action::run);
    ApiFailures.Failure normalized =
        thrown instanceof ApiException api
            ? new ApiFailures.Failure(api.status(), api.error())
            : ApiFailures.normalize(thrown);
    assertEquals(400, normalized.status(), "Expected HTTP 400 for: " + thrown);
  }

  private static final class TestBridge {
    private final BridgeServices services;
    private final ApiRegistry registry;

    private TestBridge(Program program) {
      int tx = program.startTransaction("seed-builtins");
      try {
        DataTypeManager dtm = program.getDataTypeManager();
        for (DataType builtin :
            List.of(
                ByteDataType.dataType,
                ShortDataType.dataType,
                UnsignedShortDataType.dataType,
                IntegerDataType.dataType,
                UnsignedIntegerDataType.dataType,
                UnsignedLongLongDataType.dataType)) {
          dtm.addDataType(builtin, DataTypeConflictHandler.DEFAULT_HANDLER);
        }
      } finally {
        program.endTransaction(tx, true);
      }
      this.services =
          GhidraServiceFactory.create(
              new GhidraScript() {
                {
                  set(program, TaskMonitor.DUMMY);
                }

                @Override
                protected void run() {}
              });
      this.registry = new ApiRegistry(services, "test-session", Map::of, () -> {});
    }

    private Object dispatch(String method, Map<String, Object> params) {
      try {
        return registry.dispatch(method, params);
      } catch (RuntimeException runtime) {
        throw runtime;
      } catch (Exception checked) {
        throw new IllegalStateException(checked);
      }
    }
  }
}
