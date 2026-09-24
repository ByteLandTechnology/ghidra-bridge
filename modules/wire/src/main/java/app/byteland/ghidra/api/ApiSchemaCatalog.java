package app.byteland.ghidra.api;

import static app.byteland.ghidra.api.ApiVocabulary.ADDRESS;
import static app.byteland.ghidra.api.ApiVocabulary.BASE_TYPE;
import static app.byteland.ghidra.api.ApiVocabulary.BODY;
import static app.byteland.ghidra.api.ApiVocabulary.BYTES;
import static app.byteland.ghidra.api.ApiVocabulary.CALLING_CONVENTION;
import static app.byteland.ghidra.api.ApiVocabulary.CATEGORY_PATH;
import static app.byteland.ghidra.api.ApiVocabulary.COMMENT;
import static app.byteland.ghidra.api.ApiVocabulary.CURSOR;
import static app.byteland.ghidra.api.ApiVocabulary.DATA_TYPE;
import static app.byteland.ghidra.api.ApiVocabulary.END;
import static app.byteland.ghidra.api.ApiVocabulary.ENTRY;
import static app.byteland.ghidra.api.ApiVocabulary.FIELDS;
import static app.byteland.ghidra.api.ApiVocabulary.FILTER;
import static app.byteland.ghidra.api.ApiVocabulary.FUNCTION;
import static app.byteland.ghidra.api.ApiVocabulary.HAS_NO_RETURN;
import static app.byteland.ghidra.api.ApiVocabulary.HAS_VAR_ARGS;
import static app.byteland.ghidra.api.ApiVocabulary.ITEMS;
import static app.byteland.ghidra.api.ApiVocabulary.KIND;
import static app.byteland.ghidra.api.ApiVocabulary.LENGTH;
import static app.byteland.ghidra.api.ApiVocabulary.LIMIT;
import static app.byteland.ghidra.api.ApiVocabulary.LOCAL_VARIABLES;
import static app.byteland.ghidra.api.ApiVocabulary.MEMORY_BLOCK;
import static app.byteland.ghidra.api.ApiVocabulary.MEMORY_BLOCKS;
import static app.byteland.ghidra.api.ApiVocabulary.NAME;
import static app.byteland.ghidra.api.ApiVocabulary.NAMESPACE;
import static app.byteland.ghidra.api.ApiVocabulary.OPERAND_INDEX;
import static app.byteland.ghidra.api.ApiVocabulary.ORDINAL;
import static app.byteland.ghidra.api.ApiVocabulary.PARAMETERS;
import static app.byteland.ghidra.api.ApiVocabulary.PROGRESS;
import static app.byteland.ghidra.api.ApiVocabulary.REFERENCES;
import static app.byteland.ghidra.api.ApiVocabulary.RETURN_TYPE;
import static app.byteland.ghidra.api.ApiVocabulary.SIGNATURE;
import static app.byteland.ghidra.api.ApiVocabulary.SIZE;
import static app.byteland.ghidra.api.ApiVocabulary.SOURCE_TYPE;
import static app.byteland.ghidra.api.ApiVocabulary.START;
import static app.byteland.ghidra.api.ApiVocabulary.STORAGE;
import static app.byteland.ghidra.api.ApiVocabulary.SYMBOL;
import static app.byteland.ghidra.api.ApiVocabulary.TOKENS;
import static app.byteland.ghidra.api.ApiVocabulary.TYPE;
import static app.byteland.ghidra.api.ApiVocabulary.VALUES;

import app.byteland.ghidra.service.AddressScanOptions;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class ApiSchemaCatalog {
  static final int MAX_NESTED_ITEMS = 1000;

  private ApiSchemaCatalog() {}

  static final Map<String, Object> SAVED_RECEIPT_SCHEMA =
      WireSchema.object(Map.of("saved", WireSchema.bool()), "saved");
  static final Map<String, Object> SHUTDOWN_RECEIPT_SCHEMA =
      WireSchema.object(Map.of("shutdown", WireSchema.bool()), "shutdown");
  static final Map<String, Object> DELETED_RECEIPT_SCHEMA =
      WireSchema.object(Map.of("deleted", WireSchema.bool()), "deleted");
  static final Map<String, Object> MEMORY_WRITE_RECEIPT_SCHEMA =
      WireSchema.object(
          Map.of(
              START, WireSchema.nonBlankString(),
              LENGTH, WireSchema.integer(1, Integer.MAX_VALUE)),
          START,
          LENGTH);
  static final Map<String, Object> ADDRESS_RANGE_SCHEMA =
      WireSchema.object(props(START, WireSchema.string(), END, WireSchema.string()));
  static final Map<String, Object> SCAN_PROGRESS_SCHEMA =
      WireSchema.object(
          props(
              KIND,
              WireSchema.stringEnum(ADDRESS),
              "requested_start",
              WireSchema.string(),
              "requested_end",
              WireSchema.string(),
              "scanned_start",
              WireSchema.string(),
              "scanned_end",
              WireSchema.string(),
              "complete",
              WireSchema.bool(),
              "stop_reason",
              WireSchema.stringEnum("completed", LIMIT, "timeout"),
              "elapsed_ms",
              WireSchema.integer(0, Long.MAX_VALUE)),
          KIND,
          "complete",
          "stop_reason",
          "elapsed_ms");

  static Map<String, Object> nonEmptyObject(Map<String, Map<String, Object>> properties) {
    Map<String, Object> schema = new LinkedHashMap<>(WireSchema.object(properties));
    schema.put(ApiVocabulary.MIN_PROPERTIES, 1);
    return Collections.unmodifiableMap(schema);
  }

  static Map<String, Object> input(
      Map<String, Map<String, Object>> properties, String... required) {
    return WireSchema.withDefinitions(WireSchema.object(properties, required));
  }

  static Map<String, Object> input(Map<String, Map<String, Object>> properties) {
    return WireSchema.withDefinitions(WireSchema.object(properties));
  }

  static Map<String, Object> listInput(Map<String, Object> filter) {
    return input(
        props(
            FILTER,
            filter,
            LIMIT,
            ApiRegistry.limitSchema(),
            CURSOR,
            ApiRegistry.cursorSchema(),
            FIELDS,
            ApiRegistry.fieldsSchema()));
  }

  static Map<String, Object> scanListInput(Map<String, Object> filter) {
    return input(
        props(
            FILTER,
            filter,
            "range",
            ADDRESS_RANGE_SCHEMA,
            "timeout_ms",
            scanTimeoutSchema(),
            LIMIT,
            ApiRegistry.limitSchema(),
            CURSOR,
            ApiRegistry.cursorSchema(),
            FIELDS,
            ApiRegistry.fieldsSchema()));
  }

  static Map<String, Object> requiredListInput(Map<String, Object> filter) {
    return input(
        props(
            FILTER,
            filter,
            LIMIT,
            ApiRegistry.limitSchema(),
            CURSOR,
            ApiRegistry.cursorSchema(),
            FIELDS,
            ApiRegistry.fieldsSchema()),
        FILTER);
  }

  static Map<String, Object> requiredScanListInput(Map<String, Object> filter) {
    return input(
        props(
            FILTER,
            filter,
            "timeout_ms",
            scanTimeoutSchema(),
            LIMIT,
            ApiRegistry.limitSchema(),
            CURSOR,
            ApiRegistry.cursorSchema(),
            FIELDS,
            ApiRegistry.fieldsSchema()),
        FILTER);
  }

  static Map<String, Object> selectorInput(Map<String, Object> selector) {
    return input(
        props(ApiVocabulary.SELECTOR, selector, FIELDS, ApiRegistry.fieldsSchema()),
        ApiVocabulary.SELECTOR);
  }

  static Map<String, Object> selectorOnlyInput(Map<String, Object> selector) {
    return input(props(ApiVocabulary.SELECTOR, selector), ApiVocabulary.SELECTOR);
  }

  static Map<String, Object> scanTimeoutSchema() {
    return integerWithDefault(
        AddressScanOptions.MIN_TIMEOUT_MS,
        AddressScanOptions.MAX_TIMEOUT_MS,
        AddressScanOptions.DEFAULT_TIMEOUT_MS);
  }

  static Map<String, Object> integerWithDefault(int minimum, int maximum, int defaultValue) {
    Map<String, Object> schema = new LinkedHashMap<>(WireSchema.integer(minimum, maximum));
    schema.put("default", defaultValue);
    return schema;
  }

  @SuppressWarnings("unchecked")
  static Map<String, Map<String, Object>> props(Object... pairs) {
    Map<String, Map<String, Object>> properties = new LinkedHashMap<>();
    for (int index = 0; index < pairs.length; index += 2) {
      properties.put((String) pairs[index], (Map<String, Object>) pairs[index + 1]);
    }
    return properties;
  }

  static Map<String, Object> flowSelector() {
    return WireSchema.oneOf(
        WireSchema.object(
            props(KIND, WireSchema.stringEnum(ADDRESS), ADDRESS, WireSchema.nonBlankString()),
            KIND,
            ADDRESS),
        WireSchema.object(
            props(KIND, WireSchema.stringEnum(FUNCTION), ENTRY, WireSchema.nonBlankString()),
            KIND,
            ENTRY),
        WireSchema.object(
            props(
                KIND, WireSchema.stringEnum("range"),
                START, WireSchema.nonBlankString(),
                END, WireSchema.nonBlankString()),
            KIND,
            START,
            END));
  }

  static Map<String, Object> flowOverride() {
    return WireSchema.stringEnum("none", "branch", "call", "call_return", "return");
  }

  static Map<String, Object> functionPatchSchema() {
    Map<String, Object> storage = storageSchema();
    return nonEmptyObject(
        props(
            NAME,
            WireSchema.nonBlankString(),
            COMMENT,
            WireSchema.nullable(WireSchema.string()),
            RETURN_TYPE,
            WireSchema.dataTypeReference(),
            "return_storage",
            storage,
            CALLING_CONVENTION,
            WireSchema.string(),
            "is_inline",
            WireSchema.bool(),
            HAS_NO_RETURN,
            WireSchema.bool(),
            HAS_VAR_ARGS,
            WireSchema.bool(),
            "has_custom_variable_storage",
            WireSchema.bool(),
            "stack_purge_size",
            WireSchema.integer(0, Integer.MAX_VALUE)));
  }

  static Map<String, Object> storageSchema() {
    return WireSchema.oneOf(
        WireSchema.object(
            props(
                KIND,
                WireSchema.stringEnum("serialization"),
                "serialization",
                WireSchema.nonBlankString()),
            KIND,
            "serialization"),
        WireSchema.object(
            props(KIND, WireSchema.stringEnum("register"), "register", WireSchema.nonBlankString()),
            KIND,
            "register"));
  }

  static Map<String, Object> dataTypeResourceSchema() {
    Map<String, Object> struct =
        WireSchema.object(
            props(
                KIND, WireSchema.stringEnum("struct"),
                CATEGORY_PATH, WireSchema.string(),
                NAME, WireSchema.nonBlankString(),
                SIZE, WireSchema.integer(0, Integer.MAX_VALUE)),
            KIND,
            NAME);
    Map<String, Object> union =
        WireSchema.object(
            props(
                KIND, WireSchema.stringEnum("union"),
                CATEGORY_PATH, WireSchema.string(),
                NAME, WireSchema.nonBlankString()),
            KIND,
            NAME);
    Map<String, Object> enumType =
        WireSchema.object(
            props(
                KIND, WireSchema.stringEnum("enum"),
                CATEGORY_PATH, WireSchema.string(),
                NAME, WireSchema.nonBlankString(),
                SIZE, WireSchema.integer(1, 8)),
            KIND,
            NAME);
    Map<String, Object> typedef =
        WireSchema.object(
            props(
                KIND, WireSchema.stringEnum("typedef"),
                CATEGORY_PATH, WireSchema.string(),
                NAME, WireSchema.nonBlankString(),
                BASE_TYPE, WireSchema.dataTypeReference()),
            KIND,
            NAME,
            BASE_TYPE);
    return WireSchema.oneOf(struct, union, enumType, typedef, functionDataTypeResourceSchema());
  }

  static Map<String, Object> functionDataTypeResourceSchema() {
    return WireSchema.object(
        props(
            KIND, WireSchema.stringEnum(FUNCTION),
            CATEGORY_PATH, WireSchema.string(),
            NAME, WireSchema.nonBlankString(),
            SIGNATURE, functionSignatureSchema()),
        KIND,
        NAME,
        SIGNATURE);
  }

  static Map<String, Object> functionSignatureSchema() {
    Map<String, Object> parameter =
        WireSchema.object(
            props(
                NAME, WireSchema.string(),
                DATA_TYPE, WireSchema.dataTypeReference()),
            DATA_TYPE);
    return WireSchema.object(
        props(
            RETURN_TYPE, WireSchema.dataTypeReference(),
            PARAMETERS, WireSchema.array(parameter, 0, MAX_NESTED_ITEMS),
            CALLING_CONVENTION, WireSchema.nonBlankString(),
            HAS_VAR_ARGS, WireSchema.bool(),
            HAS_NO_RETURN, WireSchema.bool()),
        RETURN_TYPE,
        PARAMETERS,
        CALLING_CONVENTION,
        HAS_VAR_ARGS,
        HAS_NO_RETURN);
  }

  static Map<String, Object> dataTypePatchSchema() {
    Map<String, Object> field =
        WireSchema.object(
            props(
                NAME,
                WireSchema.string(),
                "new_name",
                WireSchema.string(),
                "offset",
                WireSchema.integer(0, Integer.MAX_VALUE),
                LENGTH,
                WireSchema.integer(1, Integer.MAX_VALUE),
                DATA_TYPE,
                WireSchema.dataTypeReference()));
    Map<String, Object> value =
        WireSchema.object(
            props(
                NAME,
                WireSchema.string(),
                "new_name",
                WireSchema.string(),
                "value",
                WireSchema.integer(Long.MIN_VALUE, Long.MAX_VALUE)));
    return WireSchema.oneOf(
        compositePatch("struct", field),
        compositePatch("union", field),
        WireSchema.object(
            props(
                KIND,
                WireSchema.stringEnum("enum"),
                "add_values",
                WireSchema.array(value, 1, MAX_NESTED_ITEMS),
                "remove_values",
                WireSchema.array(value, 1, MAX_NESTED_ITEMS),
                "rename_values",
                WireSchema.array(value, 1, MAX_NESTED_ITEMS),
                "update_values",
                WireSchema.array(value, 1, MAX_NESTED_ITEMS)),
            KIND));
  }

  static Map<String, Object> compositePatch(String kind, Map<String, Object> field) {
    return WireSchema.object(
        props(
            KIND,
            WireSchema.stringEnum(kind),
            "add_fields",
            WireSchema.array(field, 1, MAX_NESTED_ITEMS),
            "rename_fields",
            WireSchema.array(field, 1, MAX_NESTED_ITEMS),
            "update_fields",
            WireSchema.array(field, 1, MAX_NESTED_ITEMS),
            "remove_fields",
            WireSchema.array(field, 1, MAX_NESTED_ITEMS)),
        KIND);
  }

  static Set<String> programFields() {
    return Set.of(
        NAME,
        "executable_path",
        "executable_format",
        "image_base",
        "min_address",
        "max_address",
        "language_id",
        "compiler_spec_id",
        "created_at",
        "modified_at",
        "function_count",
        "symbol_count");
  }

  static Map<String, Object> resourceSchema(Set<String> fields) {
    return resourceSchema(fields, List.of());
  }

  static Map<String, Object> resourceSchema(Set<String> fields, List<String> identityFields) {
    Map<String, Map<String, Object>> properties = new LinkedHashMap<>();
    for (String path : fields) {
      String root = path.substring(0, path.indexOf('.') < 0 ? path.length() : path.indexOf('.'));
      properties.putIfAbsent(root, outputFieldSchema(root));
    }
    return WireSchema.withDefinitions(
        WireSchema.object(properties, identityFields.toArray(String[]::new)));
  }

  static Map<String, Object> listSchema(Set<String> fields, List<String> identityFields) {
    return WireSchema.withDefinitions(
        WireSchema.object(
            Map.of(
                ITEMS,
                WireSchema.array(resourceSchema(fields, identityFields), 0, Integer.MAX_VALUE),
                ApiVocabulary.NEXT_CURSOR,
                WireSchema.nonBlankString()),
            ITEMS));
  }

  static Map<String, Object> scanListSchema(Set<String> fields, List<String> identityFields) {
    return WireSchema.withDefinitions(
        WireSchema.object(
            Map.of(
                ITEMS,
                WireSchema.array(resourceSchema(fields, identityFields), 0, Integer.MAX_VALUE),
                ApiVocabulary.NEXT_CURSOR,
                WireSchema.nonBlankString(),
                "scan",
                SCAN_PROGRESS_SCHEMA),
            ITEMS));
  }

  static Map<String, Object> outputFieldSchema(String field) {
    if (Set.of(
            "count",
            LENGTH,
            SIZE,
            "address_size",
            "function_count",
            "symbol_count",
            "parameter_count",
            "stack_purge_size",
            "category_count",
            "data_type_count",
            ORDINAL,
            "elapsed_ms")
        .contains(field)) {
      return WireSchema.integer(0, Long.MAX_VALUE);
    }
    if (OPERAND_INDEX.equals(field)) return WireSchema.integer(-1, Integer.MAX_VALUE);
    if (Set.of(
            "read",
            "write",
            "execute",
            "initialized",
            "volatile",
            "overlay",
            "default",
            "valid",
            "in_memory",
            "is_inline",
            HAS_NO_RETURN,
            HAS_VAR_ARGS,
            "has_custom_variable_storage",
            "external",
            "thunk",
            "primary",
            "completed",
            "analyzed")
        .contains(field)) {
      return WireSchema.bool();
    }
    if (Set.of(RETURN_TYPE, DATA_TYPE, BASE_TYPE).contains(field)) {
      return WireSchema.dataTypeReference();
    }
    if (BYTES.equals(field)) return byteSequenceSchema();
    if ("return_storage".equals(field) || STORAGE.equals(field)) return storageSchema();
    if (BODY.equals(field)) {
      return WireSchema.object(
          props(
              START,
              WireSchema.string(),
              END,
              WireSchema.string(),
              "num_addresses",
              WireSchema.integer(0, Long.MAX_VALUE)),
          START,
          END,
          "num_addresses");
    }
    if (PARAMETERS.equals(field)) {
      return WireSchema.array(
          WireSchema.object(
              props(
                  ORDINAL, WireSchema.integer(0, Integer.MAX_VALUE),
                  NAME, WireSchema.string(),
                  DATA_TYPE, WireSchema.dataTypeReference(),
                  STORAGE, storageSchema()),
              ORDINAL,
              NAME,
              DATA_TYPE,
              STORAGE),
          0,
          MAX_NESTED_ITEMS);
    }
    if (LOCAL_VARIABLES.equals(field)) {
      return WireSchema.array(
          WireSchema.object(
              props(
                  NAME, WireSchema.string(),
                  DATA_TYPE, WireSchema.dataTypeReference(),
                  STORAGE, storageSchema()),
              NAME,
              DATA_TYPE,
              STORAGE),
          0,
          MAX_NESTED_ITEMS);
    }
    if (FIELDS.equals(field)) {
      return WireSchema.array(
          WireSchema.object(
              props(
                  ORDINAL,
                  WireSchema.integer(0, Integer.MAX_VALUE),
                  NAME,
                  WireSchema.string(),
                  "offset",
                  WireSchema.integer(0, Integer.MAX_VALUE),
                  "end_offset",
                  WireSchema.integer(0, Integer.MAX_VALUE),
                  KIND,
                  WireSchema.string(),
                  LENGTH,
                  WireSchema.integer(0, Integer.MAX_VALUE),
                  COMMENT,
                  WireSchema.string(),
                  "is_undefined",
                  WireSchema.bool(),
                  DATA_TYPE,
                  WireSchema.dataTypeReference())),
          0,
          MAX_NESTED_ITEMS);
    }
    if (VALUES.equals(field)) {
      return WireSchema.array(
          WireSchema.object(
              props(
                  NAME,
                  WireSchema.string(),
                  "value",
                  WireSchema.integer(Long.MIN_VALUE, Long.MAX_VALUE),
                  COMMENT,
                  WireSchema.string()),
              NAME,
              "value"),
          0,
          MAX_NESTED_ITEMS);
    }
    if (SIGNATURE.equals(field)) {
      return WireSchema.oneOf(WireSchema.string(), functionSignatureSchema());
    }
    if (Set.of("operands", "tags", "warnings").contains(field)) {
      return WireSchema.array(WireSchema.string(), 0, Integer.MAX_VALUE);
    }
    if (REFERENCES.equals(field)) {
      return WireSchema.array(referenceResourceSchema(), 0, Integer.MAX_VALUE);
    }
    if (TOKENS.equals(field)) {
      return WireSchema.array(
          WireSchema.object(
              props(
                  KIND,
                  WireSchema.stringEnum(
                      "keyword",
                      COMMENT,
                      TYPE,
                      FUNCTION,
                      "variable",
                      "constant",
                      "parameter",
                      "global",
                      ApiVocabulary.DEFAULT,
                      "error",
                      "special"),
                  "text",
                  WireSchema.string(),
                  ADDRESS,
                  WireSchema.string()),
              KIND,
              ApiVocabulary.TEXT),
          0,
          Integer.MAX_VALUE);
    }
    if (MEMORY_BLOCKS.equals(field)) {
      return WireSchema.array(memoryBlockSummarySchema(), 0, Integer.MAX_VALUE);
    }
    if (PROGRESS.equals(field)) return WireSchema.number(0.0, 100.0);
    if (MEMORY_BLOCK.equals(field)) return memoryBlockSummarySchema();
    if (FUNCTION.equals(field)) return functionSummarySchema();
    if (SYMBOL.equals(field)) return symbolSummarySchema();
    return WireSchema.string();
  }

  static Map<String, Object> memoryBlockSummarySchema() {
    return WireSchema.object(
        props(
            NAME,
            WireSchema.string(),
            START,
            WireSchema.string(),
            END,
            WireSchema.string(),
            LENGTH,
            WireSchema.integer(0, Long.MAX_VALUE),
            "read",
            WireSchema.bool(),
            "write",
            WireSchema.bool(),
            "execute",
            WireSchema.bool()),
        NAME);
  }

  static Map<String, Object> functionSummarySchema() {
    return WireSchema.object(
        props(ENTRY, WireSchema.string(), NAME, WireSchema.string()), ENTRY, NAME);
  }

  static Map<String, Object> symbolSummarySchema() {
    return WireSchema.object(
        props("id", WireSchema.string(), NAME, WireSchema.string(), TYPE, WireSchema.string()),
        "id",
        NAME,
        TYPE);
  }

  static Map<String, Object> referenceResourceSchema() {
    return WireSchema.object(
        props(
            "from",
            WireSchema.string(),
            "to",
            WireSchema.string(),
            TYPE,
            WireSchema.string(),
            SOURCE_TYPE,
            WireSchema.string(),
            OPERAND_INDEX,
            WireSchema.integer(-1, Integer.MAX_VALUE),
            "primary",
            WireSchema.bool()),
        "from",
        "to",
        TYPE,
        OPERAND_INDEX);
  }

  static Map<String, Object> byteSequenceSchema() {
    return WireSchema.object(
        props(
            "encoding",
            WireSchema.stringEnum("hex", "base64"),
            "data",
            WireSchema.string(),
            LENGTH,
            WireSchema.integer(0, Integer.MAX_VALUE)),
        "encoding",
        "data",
        LENGTH);
  }

  static Set<String> memoryBlockFields() {
    return Set.of(
        NAME,
        START,
        END,
        LENGTH,
        "read",
        "write",
        "execute",
        "initialized",
        "volatile",
        "overlay",
        KIND,
        COMMENT);
  }

  static Set<String> instructionFields() {
    return Set.of(
        ADDRESS,
        LENGTH,
        BYTES,
        "mnemonic",
        "operands",
        "flow_override",
        "default_flow_type",
        "flow_type",
        "fall_through");
  }

  static Set<String> functionFields() {
    return Set.of(
        ENTRY,
        NAME,
        NAMESPACE,
        BODY,
        "body.start",
        "body.end",
        "body.num_addresses",
        SIGNATURE,
        RETURN_TYPE,
        "return_storage",
        "parameter_count",
        CALLING_CONVENTION,
        PARAMETERS,
        "parameters.ordinal",
        "parameters.name",
        "parameters.data_type",
        "parameters.storage",
        LOCAL_VARIABLES,
        "local_variables.name",
        "local_variables.data_type",
        "local_variables.storage",
        COMMENT,
        "is_inline",
        HAS_NO_RETURN,
        HAS_VAR_ARGS,
        "has_custom_variable_storage",
        "stack_purge_size",
        "external",
        "thunk",
        "repeatable_comment",
        "tags");
  }

  static Set<String> symbolFields() {
    return Set.of("id", NAME, ADDRESS, TYPE, NAMESPACE, SOURCE_TYPE, "primary");
  }

  static Set<String> commentFields() {
    return Set.of(ADDRESS, TYPE, ApiVocabulary.TEXT);
  }

  static Set<String> dataTypeFields() {
    return Set.of(
        "path",
        NAME,
        CATEGORY_PATH,
        KIND,
        LENGTH,
        "description",
        SIZE,
        FIELDS,
        VALUES,
        BASE_TYPE,
        SIGNATURE,
        "signature.return_type",
        "signature.parameters");
  }

  static Map<String, Object> commentTypeSchema() {
    return WireSchema.stringEnum("plate", "pre", "eol", "repeatable", "post");
  }
}
