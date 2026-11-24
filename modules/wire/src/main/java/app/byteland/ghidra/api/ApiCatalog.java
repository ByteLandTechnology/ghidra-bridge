package app.byteland.ghidra.api;

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

    private MethodDescriptor(ApiMethod<Map<String, Object>, Object> method) {
      Objects.requireNonNull(method, "method");
      ApiMethod.MethodEffects effects = method.effects();
      this.methodName = method.name();
      this.methodDescription = method.description();
      this.requestSchema = WireSchema.snapshot(method.requestCodec().schema());
      this.responseSchema = WireSchema.snapshot(method.responseCodec().schema());
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
}
