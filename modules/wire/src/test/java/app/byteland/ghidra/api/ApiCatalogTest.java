package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.RecordComponent;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

class ApiCatalogTest {
  @Test
  void apiMethodExposesEightRecordComponentsAndExpectedNestedTypes() {
    List<String> components =
        Arrays.stream(ApiMethod.class.getRecordComponents())
            .map(RecordComponent::getName)
            .toList();
    assertEquals(
        List.of(
            "name",
            "description",
            "effects",
            "requestCodec",
            "responseCodec",
            "fields",
            "identityFields",
            "handler"),
        components);

    Set<String> publicNestedTypes =
        Arrays.stream(ApiMethod.class.getDeclaredClasses())
            .filter(type -> Modifier.isPublic(type.getModifiers()))
            .map(Class::getSimpleName)
            .collect(Collectors.toSet());
    assertEquals(Set.of("Handler", "MethodEffects"), publicNestedTypes);
  }

  @Test
  void methodDescriptorExposesOnlyContractAndInterfaceMetadata() {
    Set<String> publicMethods =
        Arrays.stream(ApiCatalog.MethodDescriptor.class.getDeclaredMethods())
            .filter(method -> Modifier.isPublic(method.getModifiers()))
            .map(Method::getName)
            .collect(Collectors.toSet());
    assertEquals(
        Set.of(
            "name",
            "description",
            "inputSchema",
            "outputSchema",
            "contractValue",
            "interfaceValue",
            "effectSummary"),
        publicMethods);

    ApiCatalog catalog = ApiRegistry.catalog();
    assertEquals(56, catalog.methods().size());
    Map<String, Object> description = catalog.interfaceDescription();
    assertEquals(catalog.interfaceVersion(), description.get("interface_version"));
    List<?> methods = (List<?>) description.get("methods");
    assertEquals(56, methods.size());

    for (ApiCatalog.MethodDescriptor descriptor : catalog.methods()) {
      Map<String, Object> contract = descriptor.contractValue();
      assertEquals(
          List.of("description", "input_schema", "output_schema", "effects"),
          List.copyOf(contract.keySet()));
      Map<String, Object> interfaceValue = descriptor.interfaceValue();
      assertEquals(
          List.of("name", "description", "input_schema", "output_schema", "effects"),
          List.copyOf(interfaceValue.keySet()));
      assertTrue(
          Set.of("read-only", "lifecycle", "mutation", "destructive mutation")
              .contains(descriptor.effectSummary()));
    }
  }
}
