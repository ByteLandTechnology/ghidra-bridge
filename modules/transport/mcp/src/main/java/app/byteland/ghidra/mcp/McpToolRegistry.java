package app.byteland.ghidra.mcp;

import static app.byteland.ghidra.mcp.McpSchemaFlattener.orderedMap;

import app.byteland.ghidra.api.ApiCatalog;
import app.byteland.ghidra.api.ApiCatalog.MethodDescriptor;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Publishes per-operation MCP tools named {@code <prefix>_<domain>_<operation>} plus
 * {@code <prefix>_help}, while retaining lookup for legacy {@code <prefix>_<domain>} calls.
 */
final class McpToolRegistry {
  record OperationTarget(String domain, String operation, MethodDescriptor descriptor) {}

  private final String prefix;
  private final Map<String, Map<String, MethodDescriptor>> domains = new LinkedHashMap<>();
  private final Map<String, OperationTarget> operationsBySuffix = new LinkedHashMap<>();
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
      operationsBySuffix.put(
          operationSuffix(target[0], target[1]),
          new OperationTarget(target[0], target[1], method));
    }
    List<Map<String, Object>> tools = new ArrayList<>(1 + operationsBySuffix.size());
    tools.add(
        orderedMap(
            "name",
            helpToolName(),
            "description",
            "Get domains, operations, schemas, and effects.",
            "inputSchema",
            orderedMap(
                "type",
                "object",
                "properties",
                orderedMap(
                    "domain",
                    Map.of("type", "string"),
                    "operation",
                    Map.of("type", "string"))),
            "annotations",
            annotations(true, false, true)));
    operationsBySuffix.values().forEach(target -> tools.add(operationTool(target)));
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

  private Map<String, Object> operationTool(OperationTarget target) {
    MethodDescriptor method = target.descriptor();
    Map<?, ?> effects = (Map<?, ?>) method.contractValue().get("effects");
    return orderedMap(
        "name",
        operationToolName(target.domain(), target.operation()),
        "description",
        method.description(),
        "inputSchema",
        McpSchemaFlattener.flattenOperationSchema(method.inputSchema()),
        "annotations",
        annotations(
            Boolean.TRUE.equals(effects.get("read_only")),
            Boolean.TRUE.equals(effects.get("destructive")),
            Boolean.TRUE.equals(effects.get("idempotent"))));
  }

  private static Map<String, Object> annotations(
      boolean readOnly, boolean destructive, boolean idempotent) {
    return orderedMap(
        "readOnlyHint",
        readOnly,
        "destructiveHint",
        destructive,
        "idempotentHint",
        idempotent,
        "openWorldHint",
        false);
  }

  List<Map<String, Object>> listTools() {
    return listedTools;
  }

  OperationTarget findOperationTool(String name) {
    String suffix = underscoreSuffixOf(name);
    return suffix == null ? null : operationsBySuffix.get(suffix);
  }

  MethodDescriptor findTool(String name, String operation) {
    String domain = domainOf(name);
    Map<String, MethodDescriptor> methods = domain == null ? null : domains.get(domain);
    return methods == null ? null : methods.get(operation);
  }

  boolean hasTool(String name) {
    if (isHelpTool(name)) return true;
    if (findOperationTool(name) != null) return true;
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
    if (operationValue == null) {
      List<Map<String, Object>> entries = new ArrayList<>(operations.size());
      operations.forEach(
          (operationName, descriptor) ->
              entries.add(
                  orderedMap(
                      "name",
                      operationName,
                      "tool",
                      operationToolName(domain, operationName),
                      "method",
                      descriptor.name(),
                      "description",
                      descriptor.description(),
                      "effects",
                      descriptor.contractValue().get("effects"),
                      "inputSchema",
                      descriptor.inputSchema(),
                      "outputSchema",
                      descriptor.outputSchema())));
      return orderedMap("domain", toolName(domain), "operations", List.copyOf(entries));
    }
    String operationName = operationValue.toString();
    MethodDescriptor descriptor = operations.get(operationName);
    if (descriptor == null) throw new IllegalArgumentException("Unknown operation: " + operationValue);
    return orderedMap(
        "domain",
        toolName(domain),
        "operation",
        operationName,
        "tool",
        operationToolName(domain, operationName),
        "method",
        descriptor.name(),
        "description",
        descriptor.description(),
        "inputSchema",
        descriptor.inputSchema(),
        "outputSchema",
        descriptor.outputSchema(),
        "effects",
        descriptor.contractValue().get("effects"));
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

  private String operationToolName(String domain, String operation) {
    return prefix + "_" + operationSuffix(domain, operation);
  }

  private static String operationSuffix(String domain, String operation) {
    return domain + "_" + operation.replace('.', '_');
  }

  private String underscoreSuffixOf(String name) {
    if (name == null || !name.startsWith(prefix + "_")) {
      return null;
    }
    return name.substring(prefix.length() + 1);
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
