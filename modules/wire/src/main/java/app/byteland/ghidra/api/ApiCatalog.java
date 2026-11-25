package app.byteland.ghidra.api;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Immutable catalog of API methods and their metadata.
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

  /**
   * Returns the semantic version of the public bridge interface.
   *
   * @return non-blank interface version string
   */
  public String interfaceVersion() {
    return apiInterfaceVersion;
  }

  /**
   * Returns all registered method descriptors in deterministic registration order.
   *
   * @return immutable list of method descriptors
   */
  public List<MethodDescriptor> methods() {
    return methodDescriptors;
  }

  /**
   * Builds the wire payload returned by {@code interface.get}.
   *
   * @return map containing {@code interface_version} and serialized method descriptors
   */
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

    private MethodDescriptor(ApiMethod<Map<String, Object>, Object> method) {
      Objects.requireNonNull(method, "method");
      ApiMethod.MethodEffects effects = method.effects();
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
    }

    private static MethodDescriptor from(ApiMethod<Map<String, Object>, Object> method) {
      return new MethodDescriptor(method);
    }

    /**
     * Returns the canonical dotted API method name.
     *
     * @return dotted method name
     */
    public String name() {
      return methodName;
    }

    /**
     * Returns the human-readable method summary.
     *
     * @return method description text
     */
    public String description() {
      return methodDescription;
    }

    /**
     * Returns the immutable JSON Schema for method request parameters.
     *
     * @return input JSON Schema map
     */
    public Map<String, Object> inputSchema() {
      return requestSchema;
    }

    /**
     * Returns the immutable JSON Schema for method results.
     *
     * @return output JSON Schema map
     */
    public Map<String, Object> outputSchema() {
      return responseSchema;
    }

    /**
     * Returns the contract metadata map without the method name key.
     *
     * @return unmodifiable map of description, schemas, and effect flags
     */
    public Map<String, Object> contractValue() {
      Map<String, Object> descriptor = new LinkedHashMap<>();
      descriptor.put("description", methodDescription);
      descriptor.put("input_schema", inputSchema());
      descriptor.put("output_schema", outputSchema());
      descriptor.put("effects", effectsValue());
      return Collections.unmodifiableMap(descriptor);
    }

    /**
     * Returns the wire descriptor entry included in {@code interface.get}.
     *
     * @return unmodifiable map of method name, description, schemas, and effect flags
     */
    public Map<String, Object> interfaceValue() {
      Map<String, Object> descriptor = new LinkedHashMap<>();
      descriptor.put(ApiVocabulary.NAME, methodName);
      descriptor.putAll(contractValue());
      return Collections.unmodifiableMap(descriptor);
    }

    /**
     * Summarizes the method's side-effect category for generated documentation.
     *
     * @return {@code "read-only"}, {@code "lifecycle"}, {@code "mutation"}, or {@code "destructive mutation"}
     */
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
