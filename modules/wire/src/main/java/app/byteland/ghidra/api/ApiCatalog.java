package app.byteland.ghidra.api;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable catalog of registered API methods and their metadata.
 */
public final class ApiCatalog {
  private final String apiInterfaceVersion;
  private final List<MethodDescriptor> methodDescriptors;

  private ApiCatalog(String interfaceVersion, List<MethodDescriptor> methods) {
    if (interfaceVersion == null || interfaceVersion.isBlank()) {
      throw new IllegalArgumentException("interfaceVersion must not be blank");
    }
    this.apiInterfaceVersion = interfaceVersion;
    this.methodDescriptors = List.copyOf(methods);
  }

  static ApiCatalog from(
      String interfaceVersion, Iterable<ApiMethod<Map<String, Object>, Object>> registeredMethods) {
    Objects.requireNonNull(registeredMethods, "registeredMethods");
    Map<String, MethodDescriptor> ordered = new LinkedHashMap<>();
    for (ApiMethod<Map<String, Object>, Object> method : registeredMethods) {
      MethodDescriptor descriptor = MethodDescriptor.from(method);
      if (ordered.put(descriptor.name(), descriptor) != null) {
        throw new IllegalArgumentException("duplicate method descriptor: " + descriptor.name());
      }
    }
    return new ApiCatalog(interfaceVersion, List.copyOf(ordered.values()));
  }

  public String interfaceVersion() {
    return apiInterfaceVersion;
  }

  public List<MethodDescriptor> methods() {
    return methodDescriptors;
  }

  public Map<String, Object> interfaceDescription() {
    return Map.of(
        "interface_version",
        apiInterfaceVersion,
        "methods",
        methodDescriptors.stream().map(MethodDescriptor::interfaceValue).toList());
  }

  /**
   * Describes a registered method and its input and output schemas.
   */
  public static final class MethodDescriptor {
    private final String methodName;
    private final String methodDescription;
    private final Map<String, Object> requestSchema;
    private final Map<String, Object> responseSchema;
    private final boolean readOnly;
    private final boolean mutatesProgram;
    private final boolean requiresTransaction;
    private final boolean allowedDuringAnalysis;
    private final boolean destructive;
    private final boolean idempotent;
    private final String title;
    private final boolean readOnlyHint;
    private final boolean destructiveHint;
    private final boolean idempotentHint;

    private MethodDescriptor(ApiMethod<Map<String, Object>, Object> method) {
      Objects.requireNonNull(method, "method");
      ApiMethod.MethodEffects effects = method.effects();
      ApiMethod.McpAnnotations annotations = method.mcpAnnotations();
      this.methodName = method.name();
      this.methodDescription = method.description();
      this.requestSchema = immutableSchemaSnapshot(method.requestCodec().schema());
      this.responseSchema = immutableSchemaSnapshot(method.responseCodec().schema());
      this.readOnly = effects.readOnly();
      this.mutatesProgram = effects.mutatesProgram();
      this.requiresTransaction = effects.requiresTransaction();
      this.allowedDuringAnalysis = effects.allowedDuringAnalysis();
      this.destructive = effects.destructive();
      this.idempotent = effects.idempotent();
      this.title = annotations.title();
      this.readOnlyHint = annotations.readOnlyHint();
      this.destructiveHint = annotations.destructiveHint();
      this.idempotentHint = annotations.idempotentHint();
    }

    private static MethodDescriptor from(ApiMethod<Map<String, Object>, Object> method) {
      return new MethodDescriptor(method);
    }

    public String name() {
      return methodName;
    }

    public String description() {
      return methodDescription;
    }

    public Map<String, Object> inputSchema() {
      return requestSchema;
    }

    public Map<String, Object> outputSchema() {
      return responseSchema;
    }

    public Map<String, Object> contractValue() {
      Map<String, Object> descriptor = new LinkedHashMap<>();
      descriptor.put("description", methodDescription);
      descriptor.put("input_schema", inputSchema());
      descriptor.put("output_schema", outputSchema());
      descriptor.put("effects", effectsValue());
      return Collections.unmodifiableMap(descriptor);
    }

    public Map<String, Object> interfaceValue() {
      Map<String, Object> descriptor = new LinkedHashMap<>();
      descriptor.put(ApiVocabulary.NAME, methodName);
      descriptor.putAll(contractValue());
      return Collections.unmodifiableMap(descriptor);
    }

    public Map<String, Object> mcpTool() {
      Map<String, Object> tool = new LinkedHashMap<>();
      tool.put("name", methodName);
      tool.put("title", title);
      tool.put("description", methodDescription);
      tool.put(
          "annotations",
          Map.of(
              "readOnlyHint", readOnlyHint,
              "destructiveHint", destructiveHint,
              "idempotentHint", idempotentHint,
              "openWorldHint", false));
      tool.put("inputSchema", inputSchema());
      tool.put("outputSchema", outputSchema());
      return Collections.unmodifiableMap(tool);
    }

    public String effectSummary() {
      if (readOnly) return "read-only";
      if (!mutatesProgram) return "lifecycle";
      return destructive ? "destructive mutation" : "mutation";
    }

    private Map<String, Object> effectsValue() {
      return Map.of(
          "read_only", readOnly,
          "mutates_program", mutatesProgram,
          "requires_transaction", requiresTransaction,
          "allowed_during_analysis", allowedDuringAnalysis,
          "destructive", destructive,
          "idempotent", idempotent);
    }
  }

  private static Map<String, Object> immutableSchemaSnapshot(Map<?, ?> source) {
    Objects.requireNonNull(source, "schema");
    Map<String, Object> copy = new LinkedHashMap<>();
    for (Map.Entry<?, ?> entry : source.entrySet()) {
      if (!(entry.getKey() instanceof String key)) {
        throw new IllegalArgumentException("schema object keys must be strings");
      }
      copy.put(key, immutableJsonSnapshot(entry.getValue()));
    }
    return Collections.unmodifiableMap(copy);
  }

  private static Object immutableJsonSnapshot(Object value) {
    if (value instanceof Map<?, ?> map) {
      return immutableSchemaSnapshot(map);
    }
    if (value instanceof List<?> list) {
      List<Object> copy = new ArrayList<>(list.size());
      for (Object item : list) {
        copy.add(immutableJsonSnapshot(item));
      }
      return Collections.unmodifiableList(copy);
    }
    if (value == null
        || value instanceof String
        || value instanceof Number
        || value instanceof Boolean) {
      return value;
    }
    throw new IllegalArgumentException("unsupported schema value: " + value.getClass().getName());
  }
}
