package app.byteland.ghidra.mcp;

import app.byteland.ghidra.api.ApiCatalog;
import app.byteland.ghidra.api.ApiCatalog.MethodDescriptor;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class McpToolRegistry {
  private final Map<String, Map<String, MethodDescriptor>> domains = new LinkedHashMap<>();
  private final List<Map<String, Object>> listedTools;

  McpToolRegistry(ApiCatalog catalog) {
    for (MethodDescriptor method : catalog.methods()) {
      if (method.name().equals("interface.get")) continue;
      String[] target = target(method.name());
      domains.computeIfAbsent(target[0], ignored -> new LinkedHashMap<>())
          .put(target[1], method);
    }
    List<Map<String, Object>> tools = new ArrayList<>();
    tools.add(Map.of("name", "ghidra.help", "description", "Get domains, operations, schemas, and effects.",
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

  private static Map<String, Object> groupTool(
      String domain, Map<String, MethodDescriptor> operations) {
    List<Map<String, Object>> inputs = new ArrayList<>();
    List<Map<String, Object>> outputs = new ArrayList<>();
    for (var entry : operations.entrySet()) {
      inputs.add(Map.of("type", "object", "properties", Map.of(
          "operation", Map.of("const", entry.getKey()), "params", entry.getValue().inputSchema()),
          "required", List.of("operation"), "additionalProperties", false));
      outputs.add(Map.of("type", "object", "properties", Map.of(
          "operation", Map.of("const", entry.getKey()), "result", entry.getValue().outputSchema()),
          "required", List.of("operation", "result"), "additionalProperties", false));
    }
    return Map.of("name", "ghidra." + domain,
        "description", "Use this tool for " + domain + " data. Select an operation: "
            + String.join(", ", operations.keySet()) + ".",
        "inputSchema", Map.of("type", "object", "oneOf", inputs),
        "outputSchema", Map.of("type", "object", "oneOf", outputs),
        "annotations", Map.of("readOnlyHint", false, "destructiveHint", true,
            "idempotentHint", false, "openWorldHint", false));
  }

  List<Map<String, Object>> listTools() { return listedTools; }

  MethodDescriptor findTool(String name, String operation) {
    Map<String, MethodDescriptor> methods = domains.get(stripPrefix(name));
    return methods == null ? null : methods.get(operation);
  }

  boolean hasTool(String name) {
    return name.equals("ghidra.help") ||
        (name.startsWith("ghidra.") && domains.containsKey(stripPrefix(name)));
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
      return Map.of("domains", domains.keySet().stream().map(d -> "ghidra." + d).toList());
    }
    String domain = stripPrefix(domainValue.toString());
    Map<String, MethodDescriptor> operations = domains.get(domain);
    if (operations == null) throw new IllegalArgumentException("Unknown domain: " + domainValue);
    Object operationValue = arguments.get("operation");
    if (operationValue == null) return Map.of("domain", "ghidra." + domain,
        "operations", List.copyOf(operations.keySet()));
    MethodDescriptor descriptor = operations.get(operationValue.toString());
    if (descriptor == null) throw new IllegalArgumentException("Unknown operation: " + operationValue);
    return Map.of("domain", "ghidra." + domain, "operation", operationValue,
        "method", descriptor.name(), "description", descriptor.description(),
        "inputSchema", descriptor.inputSchema(), "outputSchema", descriptor.outputSchema(),
        "effects", descriptor.contractValue().get("effects"));
  }

  private static String stripPrefix(String name) {
    return name.startsWith("ghidra.") ? name.substring(7) : name;
  }
}
