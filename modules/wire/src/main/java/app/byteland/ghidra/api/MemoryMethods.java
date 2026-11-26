package app.byteland.ghidra.api;

import static app.byteland.ghidra.api.ApiRegistry.bool;
import static app.byteland.ghidra.api.ApiRegistry.byteEncoding;
import static app.byteland.ghidra.api.ApiRegistry.filter;
import static app.byteland.ghidra.api.ApiRegistry.integer;
import static app.byteland.ghidra.api.ApiRegistry.nullableText;
import static app.byteland.ghidra.api.ApiRegistry.object;
import static app.byteland.ghidra.api.ApiRegistry.optionalInteger;
import static app.byteland.ghidra.api.ApiRegistry.optionalText;
import static app.byteland.ghidra.api.ApiRegistry.patch;
import static app.byteland.ghidra.api.ApiRegistry.resource;
import static app.byteland.ghidra.api.ApiRegistry.selector;
import static app.byteland.ghidra.api.ApiRegistry.text;
import static app.byteland.ghidra.api.ApiRegistry.validateByteLength;

import app.byteland.ghidra.api.ApiMethod.MethodEffects;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.memory.MemoryService;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class MemoryMethods implements ApiMethodProvider {
  private final ApiRegistry registry;

  MemoryMethods(ApiRegistry registry) {
    this.registry = registry;
  }

  @Override
  public void register() {
    Map<String, Object> fields = ApiRegistry.fieldsSchema();
    Map<String, Object> addressSelector = ApiRegistry.addressSelector();
    Map<String, Object> nameSelector = ApiRegistry.selectorSchema(ApiVocabulary.NAME);
    registry.read(
        "memory_block.get",
        ApiSchemaCatalog.selectorInput(nameSelector),
        ApiSchemaCatalog.memoryBlockFields(),
        List.of(ApiVocabulary.NAME),
        request ->
            registry
                .services()
                .memoryService()
                .getMemoryBlockByName(text(selector(request), ApiVocabulary.NAME)));
    registry.list(
        "memory_block.list",
        ApiSchemaCatalog.listInput(
            WireSchema.object(
                ApiSchemaCatalog.props(
                    ApiVocabulary.NAME,
                    WireSchema.string(),
                    "read",
                    WireSchema.bool(),
                    "write",
                    WireSchema.bool(),
                    "execute",
                    WireSchema.bool()))),
        ApiSchemaCatalog.memoryBlockFields(),
        List.of(ApiVocabulary.NAME),
        (request, page) -> {
          Map<String, Object> filter = filter(request);
          return registry
              .services()
              .memoryService()
              .listMemoryBlocks(
                  new MemoryService.MemoryBlockQuery(
                      page.limit(),
                      page.cursor(),
                      bool(filter, "execute").orElse(null),
                      bool(filter, "write").orElse(null),
                      bool(filter, "read").orElse(null),
                      optionalText(filter, ApiVocabulary.NAME)));
        });
    Map<String, Object> memoryBlockDefinition =
        WireSchema.object(
            ApiSchemaCatalog.props(
                ApiVocabulary.NAME,
                WireSchema.nonBlankString(),
                ApiVocabulary.START,
                WireSchema.nonBlankString(),
                ApiVocabulary.LENGTH,
                WireSchema.integer(1, MemoryService.MAX_BLOCK_LENGTH),
                "initialized",
                WireSchema.bool(),
                "fill_byte",
                WireSchema.integer(0, 255),
                ApiVocabulary.BYTES,
                ApiSchemaCatalog.byteSequenceSchema(),
                "read",
                WireSchema.bool(),
                "write",
                WireSchema.bool(),
                "execute",
                WireSchema.bool(),
                "is_volatile",
                WireSchema.bool(),
                "overlay",
                WireSchema.bool(),
                ApiVocabulary.COMMENT,
                WireSchema.nullable(WireSchema.string())),
            ApiVocabulary.NAME,
            ApiVocabulary.START,
            ApiVocabulary.LENGTH);
    registry.writeResource(
        "memory_block.create",
        MethodEffects.mutation(false, false),
        "Create an initialized or uninitialized memory block in the active program.",
        ApiSchemaCatalog.input(
            ApiSchemaCatalog.props(ApiVocabulary.RESOURCE, memoryBlockDefinition),
            ApiVocabulary.RESOURCE),
        ApiSchemaCatalog.memoryBlockFields(),
        List.of(ApiVocabulary.NAME),
        request ->
            registry
                .services()
                .memoryService()
                .createMemoryBlock(decodeMemoryBlockCreate(resource(request))));

    Set<String> memoryFields =
        Set.of(
            ApiVocabulary.ADDRESS,
            ApiVocabulary.BYTES,
            "bytes.encoding",
            "bytes.data",
            "bytes.length");
    registry.readWith(
        "memory.read",
        ApiSchemaCatalog.input(
            ApiSchemaCatalog.props(
                ApiVocabulary.SELECTOR,
                addressSelector,
                ApiVocabulary.LENGTH,
                WireSchema.integer(1, MemoryService.MAX_RANGE_LENGTH),
                ApiVocabulary.ENCODING,
                WireSchema.stringEnum(ApiVocabulary.HEX, "base64"),
                ApiVocabulary.FIELDS,
                fields),
            ApiVocabulary.SELECTOR),
        ApiSchemaCatalog.resourceSchema(memoryFields, List.of(ApiVocabulary.ADDRESS)),
        memoryFields,
        List.of(ApiVocabulary.ADDRESS),
        request ->
            WireValues.resource(
                registry
                    .services()
                    .memoryService()
                    .readMemoryRange(
                        text(selector(request), ApiVocabulary.ADDRESS),
                        integer(request, ApiVocabulary.LENGTH, 256),
                        byteEncoding(
                            optionalText(request, ApiVocabulary.ENCODING, ApiVocabulary.HEX)))));
    registry.writeResult(
        "memory.write",
        MethodEffects.mutation(true, true),
        ApiSchemaCatalog.input(
            ApiSchemaCatalog.props(
                ApiVocabulary.SELECTOR,
                addressSelector,
                ApiVocabulary.PATCH,
                WireSchema.object(
                    Map.of(ApiVocabulary.BYTES, ApiSchemaCatalog.byteSequenceSchema()),
                    ApiVocabulary.BYTES)),
            ApiVocabulary.SELECTOR,
            ApiVocabulary.PATCH),
        ApiSchemaCatalog.MEMORY_WRITE_RECEIPT_SCHEMA,
        request -> {
          Map<String, Object> bytes = object(patch(request), ApiVocabulary.BYTES);
          validateByteLength(bytes, "/patch/bytes");
          String start = text(selector(request), ApiVocabulary.ADDRESS);
          registry
              .services()
              .memoryService()
              .patchMemory(
                  start,
                  new ByteSequence(
                      byteEncoding(text(bytes, ApiVocabulary.ENCODING)),
                      text(bytes, ApiVocabulary.DATA),
                      integer(bytes, ApiVocabulary.LENGTH, -1)));
          return Map.of(
              ApiVocabulary.START,
              registry.services().addressService().resolveAddress(start).address(),
              ApiVocabulary.LENGTH,
              integer(bytes, ApiVocabulary.LENGTH, -1));
        });
  }

  private static MemoryService.MemoryBlockCreateRequest decodeMemoryBlockCreate(
      Map<String, Object> resource) {
    long length = ((Number) resource.get(ApiVocabulary.LENGTH)).longValue();
    Integer fillByte = optionalInteger(resource, "fill_byte");
    ByteSequence sequence = null;
    if (resource.get(ApiVocabulary.BYTES) instanceof Map<?, ?>) {
      Map<String, Object> rawBytes = object(resource, ApiVocabulary.BYTES);
      validateByteLength(rawBytes, "/resource/bytes");
      int byteLength = integer(rawBytes, ApiVocabulary.LENGTH, -1);
      if (byteLength > length) {
        throw ApiException.badRequest(
            "length_mismatch",
            "byte sequence length exceeds block length",
            "/resource/bytes/length");
      }
      sequence =
          new ByteSequence(
              byteEncoding(text(rawBytes, ApiVocabulary.ENCODING)),
              text(rawBytes, ApiVocabulary.DATA),
              byteLength);
    }
    Boolean explicitInitialized = bool(resource, "initialized").orElse(null);
    if (Boolean.FALSE.equals(explicitInitialized) && (sequence != null || fillByte != null)) {
      throw ApiException.badRequest(
          "conflicting_initialization",
          "uninitialized block cannot set bytes or fill_byte",
          "/resource/initialized");
    }
    boolean initialized =
        explicitInitialized != null ? explicitInitialized : (sequence != null || fillByte != null);
    if (initialized && length > MemoryService.MAX_INITIALIZED_BLOCK_LENGTH) {
      throw ApiException.badRequest(
          ApiVocabulary.INVALID_VALUE,
          "/resource/length must be in 1.."
              + MemoryService.MAX_INITIALIZED_BLOCK_LENGTH
              + " when initialized",
          "/resource/length");
    }
    return new MemoryService.MemoryBlockCreateRequest(
        text(resource, ApiVocabulary.NAME),
        text(resource, ApiVocabulary.START),
        length,
        initialized,
        fillByte,
        sequence,
        bool(resource, "read").orElse(true),
        bool(resource, "write").orElse(true),
        bool(resource, "execute").orElse(false),
        bool(resource, "is_volatile").orElse(false),
        bool(resource, "overlay").orElse(false),
        nullableText(resource, ApiVocabulary.COMMENT));
  }
}
