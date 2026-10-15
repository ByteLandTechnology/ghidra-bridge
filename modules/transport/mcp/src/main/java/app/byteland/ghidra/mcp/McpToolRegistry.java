package app.byteland.ghidra.mcp;

import app.byteland.ghidra.api.ApiCatalog;
import app.byteland.ghidra.api.ApiCatalog.MethodDescriptor;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Groups the API methods into MCP tools named {@code <prefix>_<domain>}, plus
 * {@code <prefix>_help}.
 */
final class McpToolRegistry {
  private final String prefix;
  private final Map<String, Map<String, MethodDescriptor>> domains = new LinkedHashMap<>();
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
    tools.add(Map.of("name", helpToolName(), "description", "Get domains, operations, schemas, and effects.",
        "inputSchema", Map.of("type", "object", "properties", Map.of(
            "domain", Map.of("type", "string"), "operation", Map.of("type", "string")),
            "additionalProperties", false),
        "annotations", Map.of("readOnlyHint", true, "destructiveHint", false,
            "idempotentHint", true, "openWorldHint", false)));
    domains.forEach((domain, operations) -> tools.add(groupTool(domain, operations)));
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
    properties.put("operation", Map.of(
        "type", "string",
        "description", "The operation to perform",
        "enum", List.copyOf(operations.keySet())));
    properties.put("params", Map.of(
        "type", "object",
        "description", "Parameters for the operation"));

    Map<String, Object> inputSchema = Map.of(
        "type", "object",
        "properties", properties,
        "required", List.of("operation"));

    return Map.of("name", toolName(domain),
        "description", "Use this tool for " + domain + " data. Select an operation: "
            + String.join(", ", operations.keySet()) + ".",
        "inputSchema", inputSchema,
        "annotations", Map.of("readOnlyHint", false, "destructiveHint", true,
            "idempotentHint", false, "openWorldHint", false));
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
    Map<String, MethodDescriptor> operations = domains.get(domain);
    if (operations == null) throw new IllegalArgumentException("Unknown domain: " + domainValue);
    Object operationValue = arguments.get("operation");
    if (operationValue == null) return Map.of("domain", toolName(domain),
        "operations", List.copyOf(operations.keySet()));
    MethodDescriptor descriptor = operations.get(operationValue.toString());
    if (descriptor == null) throw new IllegalArgumentException("Unknown operation: " + operationValue);
    return Map.of("domain", toolName(domain), "operation", operationValue,
        "method", descriptor.name(), "description", descriptor.description(),
        "inputSchema", descriptor.inputSchema(), "outputSchema", descriptor.outputSchema(),
        "effects", descriptor.contractValue().get("effects"));
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
