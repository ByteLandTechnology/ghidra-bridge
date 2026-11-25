package app.byteland.ghidra.mcp;

import app.byteland.ghidra.api.ApiCatalog;
import app.byteland.ghidra.api.ApiCatalog.MethodDescriptor;
import app.byteland.ghidra.api.ApiException;
import app.byteland.ghidra.api.WireSchema;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Groups the API methods into MCP tools named {@code <prefix>_<domain>}, plus
 * {@code <prefix>_help}.
 */
final class McpToolRegistry {
  private static final String OPERATION_FIELD = "operation";
  private static final String PARAMS_FIELD = "params";
  private static final String DOMAIN_FIELD = "domain";
  private static final Map<String, Object> HELP_ENVELOPE_SCHEMA =
      WireSchema.object(
          Map.of(
              DOMAIN_FIELD,
                  Map.of(
                      "type", "string",
                      "minLength", 1,
                      "description", "Domain name or tool name to inspect"),
              OPERATION_FIELD,
                  Map.of(
                      "type", "string",
                      "minLength", 1,
                      "description", "Operation name within the selected domain")));

  private final String prefix;
  private final Map<String, Map<String, MethodDescriptor>> domains = new LinkedHashMap<>();
  private final Map<String, Map<String, Object>> domainEnvelopeSchemas = new LinkedHashMap<>();
  private final List<Map<String, Object>> listedTools;

  McpToolRegistry(ApiCatalog catalog) {
    this(catalog, McpConfig.DEFAULT_TOOL_PREFIX);
  }

  McpToolRegistry(ApiCatalog catalog, String prefix) {
    this.prefix = McpConfig.requireToolPrefix(prefix);
    for (MethodDescriptor method : catalog.methods()) {
      if (method.name().equals("interface.get")) continue;
      String[] target = target(method.name());
      domains.computeIfAbsent(target[0], ignored -> new LinkedHashMap<>())
          .put(target[1], method);
    }
    List<Map<String, Object>> tools = new ArrayList<>();
    tools.add(
        Map.of(
            "name",
            helpToolName(),
            "description",
            "Get domains, operations, schemas, and effects.",
            "inputSchema",
            HELP_ENVELOPE_SCHEMA,
            "annotations",
            Map.of(
                "readOnlyHint", true,
                "destructiveHint", false,
                "idempotentHint", true,
                "openWorldHint", false)));
    domains.forEach(
        (domain, operations) -> {
          domainEnvelopeSchemas.put(
              domain,
              WireSchema.object(
                  Map.of(
                      OPERATION_FIELD,
                      WireSchema.stringEnum(operations.keySet().toArray(String[]::new)),
                      PARAMS_FIELD,
                      WireSchema.openObject()),
                  OPERATION_FIELD));
          tools.add(groupTool(domain, operations));
        });
    listedTools = List.copyOf(tools);
  }

  private static String[] target(String name) {
    int dot = name.indexOf('.');
    String prefix = name.substring(0, dot);
    String operation = name.substring(dot + 1);
    return switch (prefix) {
      case "session" -> new String[] {"bridge", operation};
      case "program_language" -> new String[] {"program", "language." + operation};
      case "address_space" -> new String[] {"address", "space." + operation};
      case "memory_block" -> new String[] {"memory", "block." + operation};
      case "code_unit", "data_unit", "instruction", "flow_override" ->
          new String[] {"listing", prefix + "." + operation};
      case "function_call" -> new String[] {"function", "call." + operation};
      case "function_parameter" -> new String[] {"function", "parameter." + operation};
      case "function_local_variable" -> new String[] {"function", "local_variable." + operation};
      case "data_type_category" -> new String[] {"data_type", "category." + operation};
      default -> new String[] {prefix, operation};
    };
  }

  private Map<String, Object> groupTool(
      String domain, Map<String, MethodDescriptor> operations) {
    Map<String, Object> properties = new LinkedHashMap<>();
    properties.put(
        OPERATION_FIELD,
        Map.of(
            "type", "string",
            "description", "The operation to perform",
            "enum", List.copyOf(operations.keySet())));
    properties.put(
        PARAMS_FIELD,
        WireSchema.withDefault(
            Map.of("type", "object", "description", "Parameters for the operation"), Map.of()));

    List<Map<String, Object>> branches = new ArrayList<>(operations.size());
    boolean usesDefinitions = false;
    for (Map.Entry<String, MethodDescriptor> entry : operations.entrySet()) {
      String opName = entry.getKey();
      Map<String, Object> methodSchema = entry.getValue().inputSchema();
      if (methodSchema.containsKey("$defs")) {
        usesDefinitions = true;
      }
      Map<String, Object> opParamsSchema = withoutDefinitions(methodSchema);
      boolean paramsRequired = opParamsSchema.containsKey("required");
      if (!paramsRequired) {
        opParamsSchema = WireSchema.withDefault(opParamsSchema, Map.of());
      }
      Map<String, Map<String, Object>> branchProps = new LinkedHashMap<>();
      branchProps.put(OPERATION_FIELD, Map.of("type", "string", "const", opName));
      branchProps.put(PARAMS_FIELD, opParamsSchema);
      branches.add(
          paramsRequired
              ? WireSchema.object(branchProps, OPERATION_FIELD, PARAMS_FIELD)
              : WireSchema.object(branchProps, OPERATION_FIELD));
    }

    Map<String, Object> tagged = WireSchema.taggedOneOf(OPERATION_FIELD, branches);
    Map<String, Object> rawInputSchema = new LinkedHashMap<>();
    rawInputSchema.put("type", "object");
    rawInputSchema.put("additionalProperties", false);
    rawInputSchema.put("properties", properties);
    rawInputSchema.put("required", List.of(OPERATION_FIELD));
    rawInputSchema.put("discriminator", tagged.get("discriminator"));
    rawInputSchema.put("oneOf", tagged.get("oneOf"));
    Map<String, Object> inputSchema =
        usesDefinitions
            ? Collections.unmodifiableMap(WireSchema.withDefinitions(rawInputSchema))
            : Collections.unmodifiableMap(rawInputSchema);

    String purpose = "listing".equals(domain)
        ? "for code units, instructions, and flow overrides" : "for " + domain + " data";
    return Map.of("name", toolName(domain),
        "description", "Use this tool " + purpose + ". Select an operation: "
            + String.join(", ", operations.keySet()) + ".",
        "inputSchema", inputSchema,
        "annotations", Map.of("readOnlyHint", false, "destructiveHint", true,
            "idempotentHint", false, "openWorldHint", false));
  }

  private static Map<String, Object> withoutDefinitions(Map<String, Object> schema) {
    Map<String, Object> copy = new LinkedHashMap<>(schema);
    copy.remove("$defs");
    return Collections.unmodifiableMap(copy);
  }

  List<Map<String, Object>> listTools() { return listedTools; }

  MethodDescriptor findTool(String name, String operation) {
    String domain = domainOf(name);
    Map<String, MethodDescriptor> methods = domain == null ? null : domains.get(domain);
    return methods == null ? null : methods.get(operation);
  }

  boolean hasTool(String name) {
    if (isHelpTool(name)) return true;
    String domain = domainOf(name);
    return domain != null && domains.containsKey(domain);
  }

  String unknownToolMessage(String name) {
    List<String> validTools = new ArrayList<>(domains.size() + 1);
    validTools.add(helpToolName());
    domains.keySet().forEach(domain -> validTools.add(toolName(domain)));
    String validToolsList = String.join(", ", validTools);
    String candidate = stripPrefixIfPresent(name);
    if (candidate != null && candidate.indexOf('.') > 0 && candidate.indexOf('.') < candidate.length() - 1) {
      String[] resolved = target(candidate);
      Map<String, MethodDescriptor> ops = domains.get(resolved[0]);
      if (ops != null && ops.containsKey(resolved[1])) {
        return "Unknown tool \""
            + name
            + "\". Call tool \""
            + toolName(resolved[0])
            + "\" with bare operation \""
            + resolved[1]
            + "\" instead. Valid tools: "
            + validToolsList
            + ".";
      }
      String beforeDot = candidate.substring(0, candidate.indexOf('.'));
      if (domains.containsKey(beforeDot)) {
        return "Unknown tool \""
            + name
            + "\". Use tool \""
            + toolName(beforeDot)
            + "\" instead of a dotted tool name. Valid tools: "
            + validToolsList
            + ".";
      }
    }
    return "Unknown tool \"" + name + "\". Valid tools: " + validToolsList + ".";
  }

  ResolvedToolCall resolveDomainCall(String name, Object rawArguments) {
    String domain = domainOf(name);
    Map<String, MethodDescriptor> operations = domain == null ? null : domains.get(domain);
    Map<String, Object> envelopeSchema = domain == null ? null : domainEnvelopeSchemas.get(domain);
    if (operations == null || envelopeSchema == null) {
      throw ApiException.badRequest("invalid_value", unknownToolMessage(name), "/name");
    }
    String canonicalTool = toolName(domain);
    Map<String, Object> rawMap = validateArgumentsObject(rawArguments, envelopeSchema);
    Map<String, Object> arguments = new LinkedHashMap<>(rawMap);
    if (arguments.containsKey(PARAMS_FIELD) && arguments.get(PARAMS_FIELD) == null) {
      arguments.remove(PARAMS_FIELD);
    }
    try {
      WireSchema.validate(arguments, envelopeSchema, "");
    } catch (ApiException error) {
      throw formatDomainEnvelopeError(canonicalTool, domain, operations, arguments, error);
    }
    String operation = (String) arguments.get(OPERATION_FIELD);
    @SuppressWarnings("unchecked")
    Map<String, Object> operationParams =
        arguments.containsKey(PARAMS_FIELD)
            ? (Map<String, Object>) arguments.get(PARAMS_FIELD)
            : Map.of();
    return new ResolvedToolCall(operation, operations.get(operation), operationParams);
  }

  Map<String, Object> help(Object rawArguments) {
    Map<String, Object> rawMap = validateArgumentsObject(rawArguments, HELP_ENVELOPE_SCHEMA);
    Map<String, Object> arguments = new LinkedHashMap<>(rawMap);
    if (arguments.containsKey(DOMAIN_FIELD) && arguments.get(DOMAIN_FIELD) == null) {
      arguments.remove(DOMAIN_FIELD);
    }
    if (arguments.containsKey(OPERATION_FIELD) && arguments.get(OPERATION_FIELD) == null) {
      arguments.remove(OPERATION_FIELD);
    }
    try {
      WireSchema.validate(arguments, HELP_ENVELOPE_SCHEMA, "");
    } catch (ApiException error) {
      throw formatHelpEnvelopeError(error);
    }
    Object domainValue = arguments.get(DOMAIN_FIELD);
    if (domainValue == null) {
      if (arguments.containsKey(OPERATION_FIELD)) {
        throw ApiException.badRequest(
            "missing_field",
            "Argument \"domain\" is required when \"operation\" is provided for "
                + helpToolName()
                + ". Valid domains: "
                + validDomainsText()
                + ".",
            "/domain");
      }
      return Map.of("domains", domains.keySet().stream().map(this::toolName).toList());
    }
    String rawDomain = domainValue.toString();
    String domain = helpDomain(rawDomain);
    Map<String, MethodDescriptor> operations = domains.get(domain);
    if (operations == null) {
      throw ApiException.badRequest(
          "invalid_enum", unknownHelpDomainMessage(rawDomain), "/domain");
    }
    Object operationValue = arguments.get(OPERATION_FIELD);
    if (operationValue == null) {
      return Map.of(
          "domain", toolName(domain), "operations", List.copyOf(operations.keySet()));
    }
    String rawOperation = operationValue.toString();
    MethodDescriptor descriptor = operations.get(rawOperation);
    if (descriptor == null) {
      throw ApiException.badRequest(
          "invalid_enum",
          unknownOperationMessage(toolName(domain), domain, operations, rawOperation, true),
          "/operation");
    }
    return Map.of("domain", toolName(domain), "operation", rawOperation,
        "method", descriptor.name(), "description", descriptor.description(),
        "inputSchema", descriptor.inputSchema(), "outputSchema", descriptor.outputSchema(),
        "effects", descriptor.contractValue().get("effects"));
  }

  private Map<String, Object> validateArgumentsObject(
      Object rawArguments, Map<String, Object> schema) {
    Object candidate = rawArguments == null ? Map.of() : rawArguments;
    if (!(candidate instanceof Map<?, ?>)) {
      try {
        WireSchema.validate(candidate, schema, "/arguments");
      } catch (ApiException error) {
        throw ApiException.badRequest(
            error.error().code(),
            "Tool arguments at /arguments must be a JSON object.",
            "/arguments");
      }
    }
    @SuppressWarnings("unchecked")
    Map<String, Object> cast = (Map<String, Object>) candidate;
    return cast;
  }

  private ApiException formatHelpEnvelopeError(ApiException error) {
    String code = error.error().code();
    String target = error.error().target();
    if ("unknown_field".equals(code)) {
      String badKey = pointerLeaf(target);
      return ApiException.badRequest(
          code,
          "Unknown argument \""
              + badKey
              + "\" for "
              + helpToolName()
              + ". Valid arguments: domain, operation.",
          target);
    }
    if ("/domain".equals(target)) {
      return ApiException.badRequest(
          code,
          "Argument \"domain\" for "
              + helpToolName()
              + " must be a non-empty string. Valid domains: "
              + validDomainsText()
              + ".",
          target);
    }
    if ("/operation".equals(target)) {
      return ApiException.badRequest(
          code,
          "Argument \"operation\" for " + helpToolName() + " must be a non-empty string.",
          target);
    }
    return error;
  }

  private ApiException formatDomainEnvelopeError(
      String canonicalTool,
      String domain,
      Map<String, MethodDescriptor> operations,
      Map<String, Object> arguments,
      ApiException error) {
    String code = error.error().code();
    String target = error.error().target();
    String validOps = String.join(", ", operations.keySet());
    if ("missing_field".equals(code) && "/operation".equals(target)) {
      return ApiException.badRequest(
          code,
          "Missing required argument \"operation\" for "
              + canonicalTool
              + ". Valid operations: "
              + validOps
              + ".",
          target);
    }
    if ("unknown_field".equals(code)) {
      String badKey = pointerLeaf(target);
      return ApiException.badRequest(
          code,
          "Unknown argument \""
              + badKey
              + "\" for "
              + canonicalTool
              + ". Valid arguments: operation, params.",
          target);
    }
    if ("/operation".equals(target)) {
      Object rawOp = arguments.get(OPERATION_FIELD);
      if (rawOp instanceof String text) {
        return ApiException.badRequest(
            "invalid_enum",
            unknownOperationMessage(canonicalTool, domain, operations, text, false),
            target);
      }
      return ApiException.badRequest(
          code,
          "Argument \"operation\" for "
              + canonicalTool
              + " must be a non-empty string. Valid operations: "
              + validOps
              + ".",
          target);
    }
    if ("/params".equals(target)) {
      return ApiException.badRequest(
          code,
          "Argument \"params\" for " + canonicalTool + " must be a JSON object.",
          target);
    }
    return error;
  }

  private String unknownHelpDomainMessage(String rawDomain) {
    String stripped = stripPrefixIfPresent(rawDomain);
    if (stripped != null && stripped.indexOf('.') > 0 && stripped.indexOf('.') < stripped.length() - 1) {
      String[] resolved = target(stripped);
      Map<String, MethodDescriptor> ops = domains.get(resolved[0]);
      if (ops != null && ops.containsKey(resolved[1])) {
        return "Unknown domain \""
            + rawDomain
            + "\". Use bare domain \""
            + resolved[0]
            + "\" with operation \""
            + resolved[1]
            + "\" instead. Valid domains: "
            + validDomainsText()
            + ".";
      }
      String beforeDot = stripped.substring(0, stripped.indexOf('.'));
      if (domains.containsKey(beforeDot)) {
        return "Unknown domain \""
            + rawDomain
            + "\". Use bare domain \""
            + beforeDot
            + "\" instead of \""
            + rawDomain
            + "\". Valid domains: "
            + validDomainsText()
            + ".";
      }
    }
    return "Unknown domain \""
        + rawDomain
        + "\". Valid domains: "
        + validDomainsText()
        + ".";
  }

  private String unknownOperationMessage(
      String canonicalTool,
      String domain,
      Map<String, MethodDescriptor> operations,
      String rawOperation,
      boolean helpCall) {
    String validOps = String.join(", ", operations.keySet());
    String stripped = stripPrefixIfPresent(rawOperation);
    if (stripped != null && stripped.startsWith(domain + ".")) {
      String bare = stripped.substring(domain.length() + 1);
      if (operations.containsKey(bare)) {
        return "Unknown operation \""
            + rawOperation
            + "\" for "
            + canonicalTool
            + ". Use bare operation \""
            + bare
            + "\" instead of \""
            + rawOperation
            + "\". Valid operations: "
            + validOps
            + ".";
      }
    }
    if (stripped != null && stripped.indexOf('.') > 0 && stripped.indexOf('.') < stripped.length() - 1) {
      String[] resolved = target(stripped);
      if (domain.equals(resolved[0]) && operations.containsKey(resolved[1])) {
        return "Unknown operation \""
            + rawOperation
            + "\" for "
            + canonicalTool
            + ". Use bare operation \""
            + resolved[1]
            + "\" instead of \""
            + rawOperation
            + "\". Valid operations: "
            + validOps
            + ".";
      }
      Map<String, MethodDescriptor> otherDomainOps = domains.get(resolved[0]);
      if (otherDomainOps != null && otherDomainOps.containsKey(resolved[1])) {
        String redirect =
            helpCall
                ? "Use domain \""
                    + resolved[0]
                    + "\" with bare operation \""
                    + resolved[1]
                    + "\" instead"
                : "Call tool \""
                    + toolName(resolved[0])
                    + "\" with bare operation \""
                    + resolved[1]
                    + "\" instead";
        return "Unknown operation \""
            + rawOperation
            + "\" for "
            + canonicalTool
            + ". "
            + redirect
            + ". Valid operations for "
            + canonicalTool
            + ": "
            + validOps
            + ".";
      }
      String lastSegment = stripped.substring(stripped.lastIndexOf('.') + 1);
      if (operations.containsKey(lastSegment)) {
        return "Unknown operation \""
            + rawOperation
            + "\" for "
            + canonicalTool
            + ". Use bare operation \""
            + lastSegment
            + "\" instead of \""
            + rawOperation
            + "\". Valid operations: "
            + validOps
            + ".";
      }
    }
    return "Unknown operation \""
        + rawOperation
        + "\" for "
        + canonicalTool
        + ". Valid operations: "
        + validOps
        + ".";
  }

  private String validDomainsText() {
    return String.join(", ", domains.keySet());
  }

  private String stripPrefixIfPresent(String value) {
    if (value == null) {
      return null;
    }
    if (value.startsWith(prefix + "_") || value.startsWith(prefix + ".")) {
      return value.substring(prefix.length() + 1);
    }
    return value;
  }

  private static String pointerLeaf(String pointer) {
    if (pointer == null || pointer.isEmpty()) {
      return "";
    }
    int slash = pointer.lastIndexOf('/');
    String segment = slash >= 0 ? pointer.substring(slash + 1) : pointer;
    return segment.replace("~1", "/").replace("~0", "~");
  }

  boolean isHelpTool(String name) {
    return "help".equals(domainOf(name));
  }

  private String helpToolName() {
    return toolName("help");
  }

  private String toolName(String domain) {
    return prefix + "_" + domain;
  }

  /** Returns the domain of a tool name with this prefix, or null for any other name. */
  private String domainOf(String name) {
    if (name == null) {
      return null;
    }
    if (name.startsWith(prefix + "_")) {
      return name.substring(prefix.length() + 1);
    }
    if (name.startsWith(prefix + ".")) {
      return name.substring(prefix.length() + 1);
    }
    return null;
  }

  /** Accepts a domain in {@code ghidra_help} as a full tool name or as a bare domain name. */
  private String helpDomain(String value) {
    String domain = domainOf(value);
    return domain == null ? value : domain;
  }

  record ResolvedToolCall(
      String operation, MethodDescriptor descriptor, Map<String, Object> operationParams) {}
}
