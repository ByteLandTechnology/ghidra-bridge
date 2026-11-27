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
  void asyncApiPublishesDiscriminatorsAndDefaultMetadata() {
    Map<String, Object> document = ApiContractGenerator.asyncApi(ApiRegistry.catalog());
    Map<String, Object> channels = (Map<String, Object>) document.get("channels");
    Map<String, Object> agentChannel = (Map<String, Object>) channels.get("/ws/agent");
    Map<String, Object> subscribe = (Map<String, Object>) agentChannel.get("subscribe");
    Map<String, Object> message = (Map<String, Object>) subscribe.get("message");
    Map<String, Object> payload = (Map<String, Object>) message.get("payload");
    assertEquals(Map.of("propertyName", "method"), payload.get("discriminator"));

    Map<String, Object> methods = (Map<String, Object>) document.get("x-ghidra-bridge-methods");
    Map<String, Object> dataTypeCreate = (Map<String, Object>) methods.get("data_type.create");
    Map<String, Object> dtCreateSchema =
        (Map<String, Object>) dataTypeCreate.get("input_schema");
    Map<String, Object> dtCreateProps =
        (Map<String, Object>) dtCreateSchema.get("properties");
    Map<String, Object> resourceSchema =
        (Map<String, Object>) dtCreateProps.get("resource");
    assertEquals(Map.of("propertyName", "kind"), resourceSchema.get("discriminator"));

    Map<String, Object> defs = (Map<String, Object>) dtCreateSchema.get("$defs");
    Map<String, Object> dtRef = (Map<String, Object>) defs.get("data_type_reference");
    assertEquals(Map.of("propertyName", "kind"), dtRef.get("discriminator"));

    Map<String, Object> codeUnitList = (Map<String, Object>) methods.get("code_unit.list");
    Map<String, Object> cuProps =
        (Map<String, Object>) ((Map<String, Object>) codeUnitList.get("input_schema")).get("properties");
    Map<String, Object> filterProps =
        (Map<String, Object>) ((Map<String, Object>) cuProps.get("filter")).get("properties");
    assertEquals("all", ((Map<String, Object>) filterProps.get("kind")).get("default"));
    Map<String, Object> pageProps =
        (Map<String, Object>) ((Map<String, Object>) cuProps.get("page")).get("properties");
    assertEquals(100, ((Map<String, Object>) pageProps.get("limit")).get("default"));

    Map<String, Object> batchExecute = (Map<String, Object>) methods.get("batch.execute");
    Map<String, Object> batchProps =
        (Map<String, Object>) ((Map<String, Object>) batchExecute.get("input_schema")).get("properties");
    assertEquals(
        "per_item", ((Map<String, Object>) batchProps.get("transaction_mode")).get("default"));
    Map<String, Object> batchItems = (Map<String, Object>) batchProps.get("items");
    Map<String, Object> batchItemSchema = (Map<String, Object>) batchItems.get("items");
    assertEquals(Map.of("propertyName", "method"), batchItemSchema.get("discriminator"));
  }
}
