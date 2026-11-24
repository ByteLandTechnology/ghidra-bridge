package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.JsonUtil;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.snakeyaml.engine.v2.api.Load;
import org.snakeyaml.engine.v2.api.LoadSettings;

class ApiContractGeneratorTest {
  @Test
  void formattedYamlPreservesValues() {
    Map<String, Object> value = new LinkedHashMap<>();
    value.put("z", List.of("quoted \"text\"", "line\n{value}", "control \u007f and \u0085"));
    value.put("a", List.of());
    value.put("null", null);
    value.put("objects", List.of(Map.of(), Map.of("enabled", true, "count", 5)));
    value.put("description", "word ".repeat(40));

    String formatted = ApiContractGenerator.formattedYaml(value);
    assertEquals(value, new Load(LoadSettings.builder().build()).loadFromString(formatted));
    assertTrue(formatted.lines().allMatch(line -> line.length() <= 100));
  }

  @Test
  void formattedYamlRejectsLinesOverTheLimit() {
    Map<String, String> value = Map.of("description", "x".repeat(200));
    IllegalArgumentException error =
        assertThrows(
            IllegalArgumentException.class, () -> ApiContractGenerator.formattedYaml(value));
    assertTrue(error.getMessage().contains("100"));
  }

  @Test
  void generatedContractIsStableAndMatchesTheCatalog(@TempDir Path directory) throws Exception {
    ApiContractGenerator.main(new String[] {directory.toString()});
    Path contractPath = directory.resolve("docs/asyncapi.yaml");
    String first = Files.readString(contractPath, StandardCharsets.UTF_8);
    assertTrue(first.endsWith("\n"));
    assertTrue(first.lines().allMatch(line -> line.length() <= 100));
    ApiCatalog catalog = ApiRegistry.catalog();
    Object document = new Load(LoadSettings.builder().build()).loadFromString(first);
    Object expected = JsonUtil.parse(JsonUtil.toJson(ApiContractGenerator.asyncApi(catalog)));
    Object actual = JsonUtil.parse(JsonUtil.toJson(document));
    assertEquals(expected, actual);
    ApiContractGenerator.main(new String[] {directory.toString()});
    assertEquals(first, Files.readString(contractPath, StandardCharsets.UTF_8));
  }

  @Test
  @SuppressWarnings("unchecked")
  void analysisMethodsExposeTelemetryFieldsInContract() {
    ApiCatalog catalog = ApiRegistry.catalog();
    Map<String, Object> document = ApiContractGenerator.asyncApi(catalog);
    Map<String, Object> methods = (Map<String, Object>) document.get("x-ghidra-bridge-methods");

    for (String methodName : List.of("analysis.get", "analysis.start")) {
      Map<String, Object> method = (Map<String, Object>) methods.get(methodName);
      Map<String, Object> outputSchema = (Map<String, Object>) method.get("output_schema");
      assertEquals(false, outputSchema.get("additionalProperties"));
      assertEquals(List.of("kind"), outputSchema.get("required"));
      Map<String, Object> properties = (Map<String, Object>) outputSchema.get("properties");
      assertEquals(Map.of("type", "string"), properties.get("message"));
      assertEquals(Map.of("type", "string"), properties.get("error"));
      assertTrue(properties.containsKey("status"));
      assertTrue(properties.containsKey("progress"));
    }

    for (ApiCatalog.MethodDescriptor descriptor : catalog.methods()) {
      if ("analysis.get".equals(descriptor.name()) || "analysis.start".equals(descriptor.name())) {
        Map<String, Object> descriptorProps =
            (Map<String, Object>) descriptor.outputSchema().get("properties");
        assertEquals(Map.of("type", "string"), descriptorProps.get("message"));
        assertEquals(Map.of("type", "string"), descriptorProps.get("error"));
      }
    }
  }
}
