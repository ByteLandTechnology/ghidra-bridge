package app.byteland.ghidra.mcp;

import app.byteland.ghidra.api.ApiCatalog;
import app.byteland.ghidra.api.ApiCatalog.MethodDescriptor;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Groups the API methods into MCP tools named {@code <prefix>_<domain>} and
 * {@code <prefix>_<domain>_write}, plus {@code <prefix>_help}.
 */
final class McpToolRegistry {
  static final String WRITE_SUFFIX = "_write";

  private final String prefix;
  private final Map<String, Map<String, MethodDescriptor>> domains = new LinkedHashMap<>();
  private final Map<String, Map<String, MethodDescriptor>> splitWriteDomains =
      new LinkedHashMap<>();
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
            Map.of(
                "type",
                "object",
                "properties",
                Map.of(
                    "domain", Map.of("type", "string"),
                    "operation", Map.of("type", "string"))),
            "annotations",
            Map.of(
                "readOnlyHint", true,
                "destructiveHint", false,
                "idempotentHint", true,
                "openWorldHint", false)));
    domains.forEach(
        (domain, operations) -> {
          Map<String, MethodDescriptor> readOperations = new LinkedHashMap<>();
          Map<String, MethodDescriptor> writeOperations = new LinkedHashMap<>();
          operations.forEach(
              (opName, descriptor) -> {
                if (effectFlag(descriptor, "read_only")) {
                  readOperations.put(opName, descriptor);
                } else {
                  writeOperations.put(opName, descriptor);
                }
              });
          if (!readOperations.isEmpty() && !writeOperations.isEmpty()) {
            splitWriteDomains.put(
                domain + WRITE_SUFFIX, Collections.unmodifiableMap(writeOperations));
            tools.add(groupTool(domain, toolName(domain), readOperations));
            tools.add(groupTool(domain, toolName(domain + WRITE_SUFFIX), writeOperations));
          } else {
            tools.add(groupTool(domain, toolName(domain), operations));
          }
        });
    for (Map<String, Object> tool : tools) {
      String toolName = String.valueOf(tool.get("name"));
      if (toolName.length() > McpConfig.MAX_TOOL_NAME_LENGTH) {
        throw new IllegalArgumentException(
            "MCP tool name exceeds " + McpConfig.MAX_TOOL_NAME_LENGTH + " characters: " + toolName);
      }
    }
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
      String domain, String resolvedName, Map<String, MethodDescriptor> operations) {
    Map<String, Object> properties = new LinkedHashMap<>();
    properties.put(
        "operation",
        Map.of(
            "type", "string",
            "description", "The operation to perform",
            "enum", List.copyOf(operations.keySet())));
    properties.put(
        "params", McpSchemaBuilder.paramsSchema(domain, operations, helpToolName()));

    Map<String, Object> inputSchema =
        Map.of(
            "type", "object",
            "properties", Collections.unmodifiableMap(properties),
            "required", List.of("operation"));

    String purpose =
        "listing".equals(domain)
            ? "for code units, data units, instructions, and flow overrides"
            : "for " + domain + " data";
    boolean readOnlyHint =
        operations.values().stream().allMatch(op -> effectFlag(op, "read_only"));
    boolean destructiveHint =
        operations.values().stream().anyMatch(op -> effectFlag(op, "destructive"));
    boolean idempotentHint =
        operations.values().stream().allMatch(op -> effectFlag(op, "idempotent"));
    return Map.of(
        "name",
        resolvedName,
        "description",
        "Use this tool "
            + purpose
            + ". Select an operation: "
            + String.join(", ", operations.keySet())
            + ".",
        "inputSchema",
        inputSchema,
        "annotations",
        Map.of(
            "readOnlyHint", readOnlyHint,
            "destructiveHint", destructiveHint,
            "idempotentHint", idempotentHint,
            "openWorldHint", false));
  }

  @SuppressWarnings("unchecked")
  private static boolean effectFlag(MethodDescriptor descriptor, String key) {
    Object effectsObj = descriptor.contractValue().get("effects");
    if (!(effectsObj instanceof Map<?, ?> effects)) {
      throw new IllegalStateException("Missing effects on " + descriptor.name());
    }
    return Boolean.TRUE.equals(((Map<String, Object>) effects).get(key));
  }

  List<Map<String, Object>> listTools() {
    return listedTools;
  }

  MethodDescriptor findTool(String name, String operation) {
    String domain = domainOf(name);
    if (domain == null) {
      return null;
    }
    Map<String, MethodDescriptor> methods = dispatchOperations(domain);
    return methods == null ? null : methods.get(operation);
  }

  boolean hasTool(String name) {
    if (isHelpTool(name)) return true;
    String domain = domainOf(name);
    return domain != null && dispatchOperations(domain) != null;
  }

  private Map<String, MethodDescriptor> dispatchOperations(String domain) {
    Map<String, MethodDescriptor> fullDomain = domains.get(domain);
    if (fullDomain != null) {
      return fullDomain;
    }
    return splitWriteDomains.get(domain);
  }

  Map<String, Object> help(Map<String, Object> arguments) {
    if (!List.of("domain", "operation").containsAll(arguments.keySet())) {
      throw new IllegalArgumentException("Unknown help argument");
    }
    Object domainValue = arguments.get("domain");
    if (domainValue == null) {
      if (arguments.containsKey("operation")) {
        throw new IllegalArgumentException("operation requires domain");
      }
      return Map.of("domains", domains.keySet().stream().map(this::toolName).toList());
    }
    String domain = helpDomain(domainValue.toString());
    Map<String, MethodDescriptor> operations = dispatchOperations(domain);
    if (operations == null) throw new IllegalArgumentException("Unknown domain: " + domainValue);
    String resolvedDomainTool = toolName(domain);
    Object operationValue = arguments.get("operation");
    if (operationValue == null) {
      List<Map<String, Object>> operationEntries =
          operations.entrySet().stream()
              .map(entry -> operationHelp(entry.getKey(), entry.getValue()))
              .toList();
      return Map.of("domain", resolvedDomainTool, "operations", operationEntries);
    }
    MethodDescriptor descriptor = operations.get(operationValue.toString());
    if (descriptor == null) {
      throw new IllegalArgumentException("Unknown operation: " + operationValue);
    }
    return Map.of(
        "domain", resolvedDomainTool,
        "operation", operationValue,
        "method", descriptor.name(),
        "description", descriptor.description(),
        "inputSchema", descriptor.inputSchema(),
        "outputSchema", descriptor.outputSchema(),
        "effects", descriptor.contractValue().get("effects"));
  }

  private static Map<String, Object> operationHelp(
      String operationName, MethodDescriptor descriptor) {
    Map<String, Object> entry = new LinkedHashMap<>();
    entry.put("name", operationName);
    entry.put("method", descriptor.name());
    entry.put("description", descriptor.description());
    entry.put("inputSchema", descriptor.inputSchema());
    entry.put("outputSchema", descriptor.outputSchema());
    entry.put("effects", descriptor.contractValue().get("effects"));
    return Collections.unmodifiableMap(entry);
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
}
