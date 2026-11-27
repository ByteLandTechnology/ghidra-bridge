package app.byteland.ghidra.api;

import static app.byteland.ghidra.api.ApiRegistry.MAX_LIMIT;
import static app.byteland.ghidra.api.ApiRegistry.addressScan;
import static app.byteland.ghidra.api.ApiRegistry.filter;
import static app.byteland.ghidra.api.ApiRegistry.flowOverrides;
import static app.byteland.ghidra.api.ApiRegistry.flowScope;
import static app.byteland.ghidra.api.ApiRegistry.integer;
import static app.byteland.ghidra.api.ApiRegistry.object;
import static app.byteland.ghidra.api.ApiRegistry.patch;
import static app.byteland.ghidra.api.ApiRegistry.selector;
import static app.byteland.ghidra.api.ApiRegistry.text;

import app.byteland.ghidra.api.ApiMethod.MethodEffects;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.listing.BasicBlockResource;
import app.byteland.ghidra.service.listing.FlowOverrideScope;
import app.byteland.ghidra.service.listing.FlowOverrideValue;
import java.util.List;
import java.util.Map;

final class InstructionMethods implements ApiMethodProvider {
  private final ApiRegistry registry;

  InstructionMethods(ApiRegistry registry) {
    this.registry = registry;
  }

  @Override
  public void register() {
    Map<String, Object> addressSelector = ApiRegistry.addressSelector();
    registry.read(
        "instruction.get",
        ApiSchemaCatalog.selectorInput(addressSelector),
        ApiSchemaCatalog.instructionFields(),
        List.of(ApiVocabulary.ADDRESS),
        request ->
            registry
                .services()
                .listingService()
                .getInstruction(text(selector(request), ApiVocabulary.ADDRESS)));
    registry.scanList(
        "instruction.list",
        ApiSchemaCatalog.scanListInput(WireSchema.object(Map.of())),
        ApiSchemaCatalog.instructionFields(),
        List.of(ApiVocabulary.ADDRESS),
        (request, page) ->
            registry
                .services()
                .listingService()
                .listInstructions(
                    addressScan(request),
                    page.limit(),
                    page.cursor()));
    Map<String, Object> flowSelector = ApiSchemaCatalog.flowSelector();
    Map<String, Object> flowFilter =
        WireSchema.object(
            ApiSchemaCatalog.props(
                ApiVocabulary.SELECTOR,
                flowSelector,
                "flow_overrides",
                WireSchema.withDefault(
                    WireSchema.array(ApiSchemaCatalog.flowOverride(), 1, 5),
                    List.of("branch", "call", "call_return", "return"))),
            ApiVocabulary.SELECTOR);
    registry.scanList(
        "flow_override.list",
        "List stored flow overrides. Select an address, function, or range."
            + " Use next_cursor to get the next page.",
        ApiSchemaCatalog.requiredScanListInput(flowFilter),
        ApiSchemaCatalog.instructionFields(),
        List.of(ApiVocabulary.ADDRESS),
        (request, page) -> {
          Map<String, Object> selected = object(filter(request), ApiVocabulary.SELECTOR);
          return registry
              .services()
              .listingService()
              .getFlowOverrides(
                  flowScope(selected, "/filter/selector"),
                  flowOverrides(
                      filter(request).get("flow_overrides"),
                      List.of("branch", "call", "call_return", "return")),
                  addressScan(request),
                  page.limit(),
                  page.cursor());
        });
    registry.writeListResult(
        "flow_override.patch",
        MethodEffects.mutation(true, true),
        "Set or clear flow overrides. Select an address, function, or range.",
        ApiSchemaCatalog.input(
            ApiSchemaCatalog.props(
                ApiVocabulary.SELECTOR,
                flowSelector,
                ApiVocabulary.PATCH,
                WireSchema.object(
                    ApiSchemaCatalog.props(
                        ApiVocabulary.FLOW_OVERRIDE,
                        ApiSchemaCatalog.flowOverride(),
                        "expected_flow_overrides",
                        WireSchema.withDefault(
                            WireSchema.array(ApiSchemaCatalog.flowOverride(), 1, 5),
                            List.of("none", "branch", "call", "call_return", "return"))),
                    ApiVocabulary.FLOW_OVERRIDE)),
            ApiVocabulary.SELECTOR,
            ApiVocabulary.PATCH),
        ApiSchemaCatalog.instructionFields(),
        List.of(ApiVocabulary.ADDRESS),
        request -> {
          Map<String, Object> selected = selector(request);
          Map<String, Object> change = patch(request);
          FlowOverrideScope scope = flowScope(selected, "/selector");
          registry
              .services()
              .listingService()
              .setFlowOverrides(
                  scope,
                  flowOverrides(
                      change.get("expected_flow_overrides"),
                      List.of("none", "branch", "call", "call_return", "return")),
                  FlowOverrideValue.valueOf(
                      text(change, ApiVocabulary.FLOW_OVERRIDE)
                          .toUpperCase(java.util.Locale.ROOT)));
          return registry
              .services()
              .listingService()
              .getFlowOverrides(
                  scope,
                  flowOverrides(null, List.of("branch", "call", "call_return", "return")),
                  new AddressScanOptions(null, null, AddressScanOptions.DEFAULT_TIMEOUT_MS),
                  MAX_LIMIT,
                  null);
        });
    Map<String, Object> basicBlockFilter =
        WireSchema.object(
            ApiSchemaCatalog.props(
                ApiVocabulary.SELECTOR,
                flowSelector,
                "max_edges",
                ApiSchemaCatalog.integerWithDefault(
                    1, BasicBlockResource.MAX_EDGES, BasicBlockResource.DEFAULT_MAX_EDGES)),
            ApiVocabulary.SELECTOR);
    registry.scanList(
        "basic_block.list",
        "List basic blocks and flow edges. Select an address, function, or range."
            + " Use next_cursor to get the next page.",
        ApiSchemaCatalog.requiredScanListInput(basicBlockFilter),
        ApiSchemaCatalog.basicBlockFields(),
        List.of(ApiVocabulary.START, ApiVocabulary.END),
        (request, page) -> {
          Map<String, Object> blockFilter = filter(request);
          return registry
              .services()
              .listingService()
              .listBasicBlocks(
                  flowScope(object(blockFilter, ApiVocabulary.SELECTOR), "/filter/selector"),
                  addressScan(request),
                  integer(blockFilter, "max_edges", BasicBlockResource.DEFAULT_MAX_EDGES),
                  page.limit(),
                  page.cursor());
        });
  }
}
