package app.byteland.ghidra.mcp;

import app.byteland.ghidra.api.ApiCatalog;
import app.byteland.ghidra.api.ApiCatalog.MethodDescriptor;
import app.byteland.ghidra.api.ApiException;
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
  private final Map<String, MethodTarget> methodTargets = new LinkedHashMap<>();
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
      methodTargets.put(method.name(), new MethodTarget(target[0], target[1]));
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

    String purpose = "listing".equals(domain)
        ? "for code units, instructions, and flow overrides" : "for " + domain + " data";
    return Map.of("name", toolName(domain),
        "description", "Use this tool " + purpose + ". Select an operation: "
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
    for (String key : arguments.keySet()) {
      if (!"domain".equals(key) && !"operation".equals(key)) {
        throw ApiException.badRequest(
            "unknown_field",
            "Unknown argument \"" + key + "\" for tool \"" + helpToolName()
                + "\". Valid arguments are: domain, operation.",
            "/" + escapePointer(key));
      }
    }
    String validDomains = "Valid domains are: " + String.join(", ", domainToolNames()) + ".";
    if (!arguments.containsKey("domain") || arguments.get("domain") == null) {
      if (arguments.containsKey("operation") && arguments.get("operation") != null) {
        Object rawOperation = arguments.get("operation");
        MethodTarget hint =
            rawOperation instanceof String opText ? suggestFromDotted(null, opText) : null;
        String suggestion = hint == null
            ? ""
            : " Did you mean domain \"" + toolName(hint.domain())
                + "\" and operation \"" + hint.operation() + "\"?";
        throw ApiException.badRequest(
            "missing_field",
            "Argument \"domain\" is required when \"operation\" is provided for tool \""
                + helpToolName() + "\"." + suggestion + " " + validDomains,
            "/domain");
      }
      return Map.of("domains", domainToolNames());
    }
    Object domainValue = arguments.get("domain");
    if (!(domainValue instanceof String rawDomain)) {
      throw ApiException.badRequest(
          "invalid_type",
          "Argument \"domain\" for tool \"" + helpToolName() + "\" must be a string. "
              + validDomains,
          "/domain");
    }
    if (rawDomain.isBlank()) {
      throw ApiException.badRequest(
          "invalid_value",
          "Argument \"domain\" for tool \"" + helpToolName() + "\" must not be empty. "
              + validDomains,
          "/domain");
    }
    String domain = helpDomain(rawDomain);
    Map<String, MethodDescriptor> operations = domains.get(domain);
    if (operations == null) {
      MethodTarget hint = suggestFromDotted(null, rawDomain);
      String suggestion = hint == null
          ? ""
          : " Did you mean domain \"" + toolName(hint.domain())
              + "\" and operation \"" + hint.operation() + "\"?";
      throw ApiException.badRequest(
          "invalid_enum",
          "Unknown domain \"" + rawDomain + "\" for tool \"" + helpToolName() + "\"."
              + suggestion + " " + validDomains,
          "/domain");
    }
    if (!arguments.containsKey("operation") || arguments.get("operation") == null) {
      return Map.of("domain", toolName(domain), "operations", List.copyOf(operations.keySet()));
    }
    Object operationValue = arguments.get("operation");
    String validOperations =
        "Valid operations for \"" + toolName(domain) + "\" are: "
            + String.join(", ", operations.keySet()) + ".";
    if (!(operationValue instanceof String rawOperation)) {
      throw ApiException.badRequest(
          "invalid_type",
          "Argument \"operation\" for tool \"" + helpToolName() + "\" must be a string. "
              + validOperations,
          "/operation");
    }
    if (rawOperation.isBlank()) {
      throw ApiException.badRequest(
          "invalid_value",
          "Argument \"operation\" for tool \"" + helpToolName() + "\" must not be empty. "
              + validOperations,
          "/operation");
    }
    MethodDescriptor descriptor = operations.get(rawOperation);
    if (descriptor == null) {
      throw ApiException.badRequest(
          "invalid_enum", unknownOperationMessage(toolName(domain), rawOperation), "/operation");
    }
    return Map.of("domain", toolName(domain), "operation", rawOperation,
        "method", descriptor.name(), "description", descriptor.description(),
        "inputSchema", descriptor.inputSchema(), "outputSchema", descriptor.outputSchema(),
        "effects", descriptor.contractValue().get("effects"));
  }

  List<String> operationsForTool(String name) {
    String domain = domainOf(name);
    Map<String, MethodDescriptor> operations = domain == null ? null : domains.get(domain);
    return operations == null ? List.of() : List.copyOf(operations.keySet());
  }

  String unknownToolMessage(String rawName) {
    List<String> validTools = new ArrayList<>();
    validTools.add(helpToolName());
    validTools.addAll(domainToolNames());
    String suggestion = "";
    if (rawName != null) {
      if ("help".equals(rawName)) {
        suggestion = " Did you mean \"" + helpToolName() + "\"?";
      } else if (domains.containsKey(rawName)) {
        suggestion = " Did you mean \"" + toolName(rawName) + "\"?";
      } else {
        MethodTarget hint = suggestFromDotted(null, rawName);
        if (hint != null) {
          suggestion =
              " Did you mean tool \"" + toolName(hint.domain())
                  + "\" with operation \"" + hint.operation() + "\"?";
        }
      }
    }
    return "Unknown tool \"" + rawName + "\"." + suggestion
        + " Valid tools are: " + String.join(", ", validTools) + ".";
  }

  String unknownOperationMessage(String toolName, String rawOperation) {
    String domain = domainOf(toolName);
    String canonicalTool = domain == null ? toolName : toolName(domain);
    List<String> validOperations = operationsForTool(toolName);
    MethodTarget hint = suggestFromDotted(domain, rawOperation);
    if (hint != null) {
      if (hint.domain().equals(domain)) {
        return "Unknown operation \"" + rawOperation + "\" for tool \"" + canonicalTool
            + "\". Did you mean \"" + hint.operation() + "\"? Valid operations are: "
            + String.join(", ", validOperations) + ".";
      }
      return "Unknown operation \"" + rawOperation + "\" for tool \"" + canonicalTool
          + "\". Did you mean operation \"" + hint.operation() + "\" on tool \""
          + toolName(hint.domain()) + "\"? Valid operations for \"" + canonicalTool + "\" are: "
          + String.join(", ", validOperations) + ".";
    }
    return "Unknown operation \"" + rawOperation + "\" for tool \"" + canonicalTool
        + "\". Valid operations are: " + String.join(", ", validOperations) + ".";
  }

  static String escapePointer(String value) {
    return value.replace("~", "~0").replace("/", "~1");
  }

  private List<String> domainToolNames() {
    return domains.keySet().stream().map(this::toolName).toList();
  }

  private MethodTarget suggestFromDotted(String currentDomain, String rawValue) {
    if (rawValue == null) return null;
    String candidate = rawValue.trim();
    if (!candidate.contains(".")) return null;
    MethodTarget direct = methodTargets.get(candidate);
    if (direct != null) return direct;
    String stripped = stripToolPrefix(candidate);
    if (stripped != null) {
      MethodTarget prefixedMethod = methodTargets.get(stripped);
      if (prefixedMethod != null) return prefixedMethod;
      MethodTarget prefixedDomainOp = matchDomainPrefix(stripped);
      if (prefixedDomainOp != null) return prefixedDomainOp;
    }
    MethodTarget domainOp = matchDomainPrefix(candidate);
    if (domainOp != null) return domainOp;
    if (currentDomain != null && domains.containsKey(currentDomain)) {
      String bestMatch = null;
      for (String op : domains.get(currentDomain).keySet()) {
        if (candidate.endsWith("." + op)
            && (bestMatch == null || op.length() > bestMatch.length())) {
          bestMatch = op;
        }
      }
      if (bestMatch != null) {
        return new MethodTarget(currentDomain, bestMatch);
      }
    }
    return null;
  }

  private String stripToolPrefix(String value) {
    if (value.startsWith(prefix + "_") || value.startsWith(prefix + ".")) {
      return value.substring(prefix.length() + 1);
    }
    return null;
  }

  private MethodTarget matchDomainPrefix(String value) {
    for (Map.Entry<String, Map<String, MethodDescriptor>> entry : domains.entrySet()) {
      String domainPrefix = entry.getKey() + ".";
      if (value.startsWith(domainPrefix)) {
        String op = value.substring(domainPrefix.length());
        if (entry.getValue().containsKey(op)) {
          return new MethodTarget(entry.getKey(), op);
        }
      }
    }
    return null;
  }

  private record MethodTarget(String domain, String operation) {}

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
