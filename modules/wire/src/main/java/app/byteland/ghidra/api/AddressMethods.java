package app.byteland.ghidra.api;

import static app.byteland.ghidra.api.ApiRegistry.selector;
import static app.byteland.ghidra.api.ApiRegistry.text;

import java.util.List;
import java.util.Map;
import java.util.Set;

final class AddressMethods implements ApiMethodProvider {
  private final ApiRegistry registry;

  AddressMethods(ApiRegistry registry) {
    this.registry = registry;
  }

  @Override
  public void register() {
    Map<String, Object> addressSelector = ApiRegistry.addressSelector();
    registry.read(
        "address.resolve",
        ApiSchemaCatalog.selectorInput(addressSelector),
        Set.of(
            ApiVocabulary.ADDRESS,
            "valid",
            "in_memory",
            "memory_block",
            ApiVocabulary.FUNCTION,
            "symbol"),
        List.of(ApiVocabulary.ADDRESS),
        request ->
            registry
                .services()
                .addressService()
                .resolveAddress(text(selector(request), ApiVocabulary.ADDRESS)));
  }
}
