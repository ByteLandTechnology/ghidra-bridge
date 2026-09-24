package app.byteland.ghidra.api;

import app.byteland.ghidra.JsonUtil;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public final class ApiContractGenerator {
  private static final String JSONRPC_FIELD = "jsonrpc";
  private static final String METHOD_FIELD = "method";
  private static final String PARAMS_FIELD = "params";
  private static final String SCHEMA_TYPE_FIELD = "type";
  private static final String SCHEMA_CONST_FIELD = "const";
  private static final String SCHEMA_STRING_TYPE = "string";
  private static final String JSONRPC_VERSION = "2.0";
  private static final int MARKDOWN_BASE_CAPACITY = 256;
  private static final int MARKDOWN_METHOD_CAPACITY = 128;

  private ApiContractGenerator() {}

  public static void main(String[] args) throws IOException {
    Path root = Path.of(args.length == 0 ? "." : args[0]).toAbsolutePath().normalize();
    ApiCatalog catalog = ApiRegistry.catalog();
    write(root.resolve("docs/asyncapi.yaml"), JsonUtil.toJson(canonical(asyncApi(catalog))) + "\n");
    write(root.resolve("docs/api.md"), markdown(catalog));
  }

  private static Map<String, Object> asyncApi(ApiCatalog catalog) {
    List<ApiCatalog.MethodDescriptor> methods = catalog.methods();
    List<Map<String, Object>> requests =
        methods.stream().map(ApiContractGenerator::request).toList();
    List<Map<String, Object>> results =
        methods.stream().map(ApiCatalog.MethodDescriptor::outputSchema).toList();
    Map<String, Object> response =
        WireSchema.oneOf(
            WireSchema.object(
                Map.of(
                    JSONRPC_FIELD,
                    constantStringSchema(JSONRPC_VERSION),
                    "id",
                    nullableJsonRpcId(),
                    "result",
                    Map.of("anyOf", results)),
                JSONRPC_FIELD,
                "id",
                "result"),
            WireSchema.object(
                Map.of(
                    JSONRPC_FIELD,
                    constantStringSchema(JSONRPC_VERSION),
                    "id",
                    nullableJsonRpcId(),
                    "error",
                    WireSchema.openObject()),
                JSONRPC_FIELD,
                "id",
                "error"));
    Map<String, Object> ready =
        WireSchema.object(
            Map.of(
                JSONRPC_FIELD, constantStringSchema(JSONRPC_VERSION),
                METHOD_FIELD, constantStringSchema("ghidra.ready"),
                PARAMS_FIELD,
                    WireSchema.object(
                        Map.of(
                            "session_id", WireSchema.nonBlankString(),
                            "program_name", WireSchema.nonBlankString()),
                        "session_id",
                        "program_name")),
            JSONRPC_FIELD,
            METHOD_FIELD,
            PARAMS_FIELD);
    Map<String, Object> descriptors = new LinkedHashMap<>();
    methods.forEach(method -> descriptors.put(method.name(), method.contractValue()));
    Map<String, Object> document = new LinkedHashMap<>();
    document.put("asyncapi", "2.6.0");
    document.put(
        "info",
        Map.of(
            "title",
            "Ghidra Bridge JSON-RPC WebSocket Interface",
            "version",
            catalog.interfaceVersion(),
            "description",
            "Generated contract for the canonical dotted-method interface."));
    document.put(
        "servers",
        Map.of("local", Map.of("url", "ws://127.0.0.1:8765/ws/agent", "protocol", "ws")));
    document.put(
        "channels",
        Map.of(
            "/ws/agent",
            Map.of(
                "publish",
                Map.of(
                    "message",
                    Map.of(
                        "oneOf", List.of(Map.of("payload", response), Map.of("payload", ready)))),
                "subscribe",
                Map.of("message", Map.of("payload", Map.of("oneOf", requests))))));
    document.put("x-ghidra-bridge-methods", descriptors);
    return document;
  }

  private static Map<String, Object> request(ApiCatalog.MethodDescriptor method) {
    return WireSchema.object(
        Map.of(
            JSONRPC_FIELD,
            constantStringSchema(JSONRPC_VERSION),
            "id",
            jsonRpcId(),
            METHOD_FIELD,
            constantStringSchema(method.name()),
            PARAMS_FIELD,
            method.inputSchema()),
        JSONRPC_FIELD,
        "id",
        METHOD_FIELD,
        PARAMS_FIELD);
  }

  private static Map<String, Object> jsonRpcId() {
    return WireSchema.oneOf(WireSchema.nonBlankString(), Map.of(SCHEMA_TYPE_FIELD, "number"));
  }

  private static Map<String, Object> nullableJsonRpcId() {
    return WireSchema.oneOf(jsonRpcId(), Map.of(SCHEMA_TYPE_FIELD, "null"));
  }

  private static Map<String, Object> constantStringSchema(String value) {
    return Map.of(SCHEMA_TYPE_FIELD, SCHEMA_STRING_TYPE, SCHEMA_CONST_FIELD, value);
  }

  private static String markdown(ApiCatalog catalog) {
    List<ApiCatalog.MethodDescriptor> methods = catalog.methods();
    int estimatedCapacity = MARKDOWN_BASE_CAPACITY + methods.size() * MARKDOWN_METHOD_CAPACITY;
    StringBuilder output = new StringBuilder(estimatedCapacity);
    output.append("# Ghidra Bridge method reference\n\n");
    output.append("`ApiRegistry` generates this catalog. Interface version: `");
    output.append(catalog.interfaceVersion()).append("`.\n\n");
    output.append("| Method | Effect | Description |\n");
    output.append("|---|---|---|\n");
    for (ApiCatalog.MethodDescriptor method : methods) {
      output
          .append("| `")
          .append(method.name())
          .append("` | `")
          .append(method.effectSummary())
          .append("` | ")
          .append(method.description())
          .append(" |\n");
    }
    output.append("\nUse the input schema for each method. The bridge rejects unknown fields and type conversions.\n");
    return output.toString();
  }

  private static void write(Path path, String content) throws IOException {
    Path parent = path.getParent();
    if (parent != null) Files.createDirectories(parent);
    Files.writeString(path, content, StandardCharsets.UTF_8);
  }

  private static Object canonical(Object value) {
    if (value instanceof Map<?, ?> map) {
      Map<String, Object> result = new TreeMap<>();
      for (Map.Entry<?, ?> entry : map.entrySet()) {
        result.put(String.valueOf(entry.getKey()), canonical(entry.getValue()));
      }
      return result;
    }
    if (value instanceof Iterable<?> iterable) {
      List<Object> result = new ArrayList<>();
      for (Object item : iterable) result.add(canonical(item));
      return result;
    }
    return value;
  }
}
