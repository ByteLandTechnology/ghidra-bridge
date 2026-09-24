package app.byteland.ghidra.api;

import static app.byteland.ghidra.api.ApiRegistry.bool;
import static app.byteland.ghidra.api.ApiRegistry.byteEncoding;
import static app.byteland.ghidra.api.ApiRegistry.filter;
import static app.byteland.ghidra.api.ApiRegistry.integer;
import static app.byteland.ghidra.api.ApiRegistry.object;
import static app.byteland.ghidra.api.ApiRegistry.optionalText;
import static app.byteland.ghidra.api.ApiRegistry.patch;
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
        ApiSchemaCatalog.resourceSchema(
            Set.of(
                ApiVocabulary.ADDRESS,
                ApiVocabulary.BYTES,
                "bytes.encoding",
                "bytes.data",
                "bytes.length")),
        Set.of(
            ApiVocabulary.ADDRESS,
            ApiVocabulary.BYTES,
            "bytes.encoding",
            "bytes.data",
            "bytes.length"),
        List.of(ApiVocabulary.ADDRESS),
        request ->
            WireValues.memory(
                registry
                    .services()
                    .memoryService()
                    .readMemoryRange(
                        text(selector(request), ApiVocabulary.ADDRESS),
                        integer(request, ApiVocabulary.LENGTH, 256),
                        byteEncoding(
                            optionalText(request, ApiVocabulary.ENCODING, ApiVocabulary.HEX)))));
    Map<String, Object> byteSequence =
        WireSchema.object(
            ApiSchemaCatalog.props(
                ApiVocabulary.ENCODING, WireSchema.stringEnum(ApiVocabulary.HEX, "base64"),
                ApiVocabulary.DATA, WireSchema.string(),
                ApiVocabulary.LENGTH, WireSchema.integer(0, Integer.MAX_VALUE)),
            ApiVocabulary.ENCODING,
            ApiVocabulary.DATA,
            ApiVocabulary.LENGTH);
    registry.writeResult(
        "memory.write",
        MethodEffects.mutation(true, true),
        ApiSchemaCatalog.input(
            ApiSchemaCatalog.props(
                ApiVocabulary.SELECTOR,
                addressSelector,
                ApiVocabulary.PATCH,
                WireSchema.object(Map.of(ApiVocabulary.BYTES, byteSequence), ApiVocabulary.BYTES)),
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
}
