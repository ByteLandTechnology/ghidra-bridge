package app.byteland.ghidra.adapter.ghidra.function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.GhidraTestSupport;
import app.byteland.ghidra.adapter.ghidra.GhidraTestSupport.ProgramHolder;
import app.byteland.ghidra.adapter.ghidra.datatype.DataTypeServiceImpl;
import app.byteland.ghidra.service.datatype.DataTypeMutationValidationException;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeService.ConflictMode;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.FunctionService.FunctionAttributePatch;
import app.byteland.ghidra.service.function.FunctionService.ParameterPatch;
import app.byteland.ghidra.service.function.VariableStorageReference;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class FunctionParameterPatchSupportTest {

  @Test
  void patchesParameterListAtomicallyInDynamicModeAndPreservesComments() {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("param-patch-dynamic")) {
      holder.inTransaction(
          program -> {
            seedCodeBlockAndFunction(program, 0x100000L, "process_packet");
            GhidraSession session = GhidraTestSupport.sessionFor(program);
            new DataTypeServiceImpl(session)
                .parseCDeclarations(
                    "struct Socket { int fd; uint16_t port; };", "/net", ConflictMode.REPLACE);
            FunctionServiceImpl service = new FunctionServiceImpl(session);

            service.patchFunction(
                "0x100000",
                null,
                "Process packet",
                true,
                null,
                DataTypeReference.cExpression("int"),
                null,
                null,
                List.of(
                    new ParameterPatch("sock", DataTypeReference.cExpression("/net/Socket *"), null),
                    new ParameterPatch(
                        "buf", DataTypeReference.cExpression("const uint8_t *"), null),
                    new ParameterPatch(
                        "hook", DataTypeReference.cExpression("int (*)(void *)"), null)),
                FunctionAttributePatch.empty());

            Function fn =
                program.getFunctionManager().getFunctionAt(addr(program, 0x100000L));
            fn.getParameter(0).setComment("socket handle");
            fn.getParameter(1).setComment("payload bytes");

            FunctionResource initial = service.getFunction("0x100000", Set.of("parameters"));
            assertFalse(initial.hasCustomVariableStorage());
            assertEquals(3, initial.parameterCount());
            assertEquals(
                List.of("sock", "buf", "hook"),
                initial.parameters().stream().map(FunctionResource.ParameterResource::name).toList());
            assertInstanceOf(
                DataTypeReference.Pointer.class, initial.parameters().get(0).dataType());

            // Reorder and drop middle parameter while preserving comment on "sock"
            service.patchFunction(
                "0x100000",
                null,
                null,
                false,
                null,
                null,
                null,
                null,
                List.of(
                    new ParameterPatch("len", DataTypeReference.cExpression("size_t"), null),
                    new ParameterPatch(
                        "sock", DataTypeReference.cExpression("/net/Socket *"), null)),
                FunctionAttributePatch.empty());

            Function reordered =
                program.getFunctionManager().getFunctionAt(addr(program, 0x100000L));
            assertEquals(2, reordered.getParameterCount());
            assertEquals("len", reordered.getParameter(0).getName());
            assertEquals("sock", reordered.getParameter(1).getName());
            assertEquals("socket handle", reordered.getParameter(1).getComment());

            // Empty list clears all formal parameters
            service.patchFunction(
                "0x100000",
                null,
                null,
                false,
                null,
                DataTypeReference.cExpression("void"),
                null,
                null,
                List.of(),
                FunctionAttributePatch.empty());
            Function cleared =
                program.getFunctionManager().getFunctionAt(addr(program, 0x100000L));
            assertEquals(0, cleared.getParameterCount());

            // Pointer-to-array declarator works in both patch.parameters and patch.signature
            service.patchFunction(
                "0x100000",
                null,
                null,
                false,
                "int process_packet(const uint8_t (*block)[16])",
                null,
                null,
                null,
                null,
                FunctionAttributePatch.empty());
            FunctionResource withPtrToArray =
                service.getFunction("0x100000", Set.of("parameters"));
            DataTypeReference.Pointer blockPtr =
                assertInstanceOf(
                    DataTypeReference.Pointer.class,
                    withPtrToArray.parameters().get(0).dataType());
            DataTypeReference.Array blockArray =
                assertInstanceOf(DataTypeReference.Array.class, blockPtr.target());
            assertEquals(16, blockArray.count());
          });
    }
  }

  @Test
  void preservesCustomVariableStorageAcrossParameterReorderingInsertionResizingAndSignature() {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("param-patch-custom")) {
      holder.inTransaction(
          program -> {
            seedCodeBlockAndFunction(program, 0x100100L, "custom_fn");
            String r12 = registerSerialization(program, "R12");
            String r12d = registerSerialization(program, "R12D");
            String r13 = registerSerialization(program, "R13");
            String rax = registerSerialization(program, "RAX");
            String eax = registerSerialization(program, "EAX");
            String rcx = registerSerialization(program, "RCX");

            GhidraSession session = GhidraTestSupport.sessionFor(program);
            FunctionServiceImpl service = new FunctionServiceImpl(session);

            // 1. Establish custom variable storage via patch.parameters + return_storage
            service.patchFunction(
                "0x100100",
                null,
                null,
                false,
                null,
                DataTypeReference.cExpression("uint64_t"),
                VariableStorageReference.register("RAX"),
                null,
                List.of(
                    new ParameterPatch(
                        "first",
                        DataTypeReference.cExpression("uint64_t"),
                        VariableStorageReference.register("R12")),
                    new ParameterPatch(
                        "second",
                        DataTypeReference.cExpression("const uint8_t *"),
                        VariableStorageReference.register("R13"))),
                FunctionAttributePatch.empty());

            FunctionResource customInitial = service.getFunction("0x100100", Set.of("parameters"));
            assertTrue(customInitial.hasCustomVariableStorage());
            assertEquals(
                VariableStorageReference.serialization(rax), customInitial.returnStorage());
            assertEquals(
                VariableStorageReference.serialization(r12),
                customInitial.parameters().get(0).storage());
            assertEquals(
                VariableStorageReference.serialization(r13),
                customInitial.parameters().get(1).storage());

            // 2. Reorder [first, second] -> [second, first] WITHOUT repeating storage;
            //    also shrink "first" from uint64_t (8B) to uint32_t (4B -> R12D) and return to int (EAX)
            service.patchFunction(
                "0x100100",
                null,
                null,
                false,
                null,
                DataTypeReference.cExpression("int"),
                null,
                null,
                List.of(
                    new ParameterPatch(
                        "second", DataTypeReference.cExpression("const uint8_t *"), null),
                    new ParameterPatch("first", DataTypeReference.cExpression("uint32_t"), null)),
                FunctionAttributePatch.empty());

            FunctionResource swapped = service.getFunction("0x100100", Set.of("parameters"));
            assertTrue(swapped.hasCustomVariableStorage());
            assertEquals(VariableStorageReference.serialization(eax), swapped.returnStorage());
            assertEquals("second", swapped.parameters().get(0).name());
            assertEquals(
                VariableStorageReference.serialization(r13),
                swapped.parameters().get(0).storage());
            assertEquals("first", swapped.parameters().get(1).name());
            assertEquals(
                VariableStorageReference.serialization(r12d),
                swapped.parameters().get(1).storage());

            // 3. Insert a new leading parameter "prefix" at ordinal 0 without storage:
            //    "prefix" derives ABI RDI while "second" keeps R13 and "first" keeps R12D
            service.patchFunction(
                "0x100100",
                null,
                null,
                false,
                null,
                null,
                null,
                null,
                List.of(
                    new ParameterPatch("prefix", DataTypeReference.cExpression("uint64_t"), null),
                    new ParameterPatch(
                        "second", DataTypeReference.cExpression("const uint8_t *"), null),
                    new ParameterPatch("first", DataTypeReference.cExpression("uint32_t"), null)),
                FunctionAttributePatch.empty());

            FunctionResource withPrefix = service.getFunction("0x100100", Set.of("parameters"));
            assertTrue(withPrefix.hasCustomVariableStorage());
            assertEquals(
                VariableStorageReference.serialization(rcx),
                withPrefix.parameters().get(0).storage());
            assertEquals(
                VariableStorageReference.serialization(r13),
                withPrefix.parameters().get(1).storage());
            assertEquals(
                VariableStorageReference.serialization(r12d),
                withPrefix.parameters().get(2).storage());

            // 4. Apply C prototype via patch.signature and preserve custom parameter/return storage
            service.patchFunction(
                "0x100100",
                null,
                null,
                false,
                "int custom_fn(uint32_t first, const uint8_t *second)",
                null,
                null,
                null,
                null,
                FunctionAttributePatch.empty());

            FunctionResource afterSig = service.getFunction("0x100100", Set.of("parameters"));
            assertTrue(afterSig.hasCustomVariableStorage());
            assertEquals(VariableStorageReference.serialization(eax), afterSig.returnStorage());
            assertEquals("first", afterSig.parameters().get(0).name());
            assertEquals(
                VariableStorageReference.serialization(r12d),
                afterSig.parameters().get(0).storage());
            assertEquals("second", afterSig.parameters().get(1).name());
            assertEquals(
                VariableStorageReference.serialization(r13),
                afterSig.parameters().get(1).storage());

            // 5. Disable custom storage via hasCustomVariableStorage=false
            service.patchFunction(
                "0x100100",
                null,
                null,
                false,
                null,
                null,
                null,
                null,
                List.of(
                    new ParameterPatch("first", DataTypeReference.cExpression("uint32_t"), null),
                    new ParameterPatch(
                        "second", DataTypeReference.cExpression("const uint8_t *"), null)),
                new FunctionAttributePatch(null, null, null, false, null));

            FunctionResource dynamicAgain = service.getFunction("0x100100", Set.of("parameters"));
            assertFalse(dynamicAgain.hasCustomVariableStorage());
          });
    }
  }

  @Test
  void rejectsInvalidParameterPatchesWithTargetedValidationErrors() {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("param-patch-errors")) {
      holder.inTransaction(
          program -> {
            seedCodeBlockAndFunction(program, 0x100200L, "validate_fn");
            GhidraSession session = GhidraTestSupport.sessionFor(program);
            FunctionServiceImpl service = new FunctionServiceImpl(session);

            DataTypeMutationValidationException duplicateName =
                assertThrows(
                    DataTypeMutationValidationException.class,
                    () ->
                        service.patchFunction(
                            "0x100200",
                            null,
                            null,
                            false,
                            null,
                            null,
                            null,
                            null,
                            List.of(
                                new ParameterPatch("dup", DataTypeReference.cExpression("int"), null),
                                new ParameterPatch(
                                    "dup", DataTypeReference.cExpression("long"), null)),
                            FunctionAttributePatch.empty()));
            assertEquals(400, duplicateName.status());
            assertEquals("/patch/parameters/1/name", duplicateName.target());

            DataTypeMutationValidationException voidParam =
                assertThrows(
                    DataTypeMutationValidationException.class,
                    () ->
                        service.patchFunction(
                            "0x100200",
                            null,
                            null,
                            false,
                            null,
                            null,
                            null,
                            null,
                            List.of(
                                new ParameterPatch(
                                    "bad", DataTypeReference.cExpression("void"), null)),
                            FunctionAttributePatch.empty()));
            assertEquals(400, voidParam.status());
            assertEquals("/patch/parameters/0/data_type", voidParam.target());

            DataTypeMutationValidationException mismatchedStorage =
                assertThrows(
                    DataTypeMutationValidationException.class,
                    () ->
                        service.patchFunction(
                            "0x100200",
                            null,
                            null,
                            false,
                            null,
                            null,
                            null,
                            null,
                            List.of(
                                new ParameterPatch(
                                    "bad_reg",
                                    DataTypeReference.cExpression("int"),
                                    VariableStorageReference.register("R12"))),
                            FunctionAttributePatch.empty()));
            assertEquals(400, mismatchedStorage.status());
            assertEquals("/patch/parameters/0/storage", mismatchedStorage.target());

            DataTypeMutationValidationException conflictingCustomFlag =
                assertThrows(
                    DataTypeMutationValidationException.class,
                    () ->
                        service.patchFunction(
                            "0x100200",
                            null,
                            null,
                            false,
                            null,
                            null,
                            null,
                            null,
                            List.of(
                                new ParameterPatch(
                                    "reg_param",
                                    DataTypeReference.cExpression("uint64_t"),
                                    VariableStorageReference.register("R12"))),
                            new FunctionAttributePatch(null, null, null, false, null)));
            assertEquals(400, conflictingCustomFlag.status());
            assertEquals("/patch/has_custom_variable_storage", conflictingCustomFlag.target());

            DataTypeMutationValidationException oversizedSignature =
                assertThrows(
                    DataTypeMutationValidationException.class,
                    () ->
                        service.patchFunction(
                            "0x100200",
                            null,
                            null,
                            false,
                            "int validate_fn("
                                + " ".repeat(
                                    app.byteland.ghidra.service.function.FunctionService
                                        .MAX_SIGNATURE_BYTES)
                                + ")",
                            null,
                            null,
                            null,
                            null,
                            FunctionAttributePatch.empty()));
            assertEquals(400, oversizedSignature.status());
            assertEquals("/patch/signature", oversizedSignature.target());
          });
    }
  }

  private static Address addr(ProgramDB program, long offset) {
    return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
  }

  private static void seedCodeBlockAndFunction(ProgramDB program, long offset, String name)
      throws Exception {
    Address entry = addr(program, offset);
    if (program.getMemory().getBlock(".text") == null) {
      MemoryBlock block =
          program
              .getMemory()
              .createInitializedBlock(
                  ".text", addr(program, 0x100000L), 0x1000L, (byte) 0xc3, TaskMonitor.DUMMY, false);
      block.setExecute(true);
    }
    program
        .getFunctionManager()
        .createFunction(name, entry, new AddressSet(entry, entry), SourceType.USER_DEFINED);
  }

  private static String registerSerialization(ProgramDB program, String registerName)
      throws Exception {
    Register register = program.getLanguage().getRegister(registerName);
    return new VariableStorage(program, register).getSerializationString();
  }
}
