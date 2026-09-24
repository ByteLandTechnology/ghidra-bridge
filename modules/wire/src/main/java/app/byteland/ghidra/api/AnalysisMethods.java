package app.byteland.ghidra.api;

import static app.byteland.ghidra.api.ApiRegistry.ANALYSIS_START_METHOD;
import static app.byteland.ghidra.api.ApiRegistry.stringList;

import app.byteland.ghidra.api.ApiMethod.MethodEffects;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class AnalysisMethods implements ApiMethodProvider {
  private final ApiRegistry registry;

  AnalysisMethods(ApiRegistry registry) {
    this.registry = registry;
  }

  @Override
  public void register() {
    Map<String, Object> fields = ApiRegistry.fieldsSchema();
    Set<String> analysisFields =
        Set.of(
            ApiVocabulary.KIND,
            "status",
            "analyzed",
            "task_id",
            "started_at",
            "finished_at",
            "progress");
    registry.read(
        "analysis.get",
        ApiSchemaCatalog.input(ApiSchemaCatalog.props(ApiVocabulary.FIELDS, fields)),
        analysisFields,
        List.of(ApiVocabulary.KIND),
        request -> registry.services().analysisService().getStatus());
    registry.writeResult(
        ANALYSIS_START_METHOD,
        MethodEffects.mutationWithoutTransaction(false, false),
        ApiSchemaCatalog.input(
            ApiSchemaCatalog.props(
                "analyzers",
                WireSchema.array(
                    WireSchema.nonBlankString(), 1, ApiSchemaCatalog.MAX_NESTED_ITEMS))),
        ApiSchemaCatalog.resourceSchema(analysisFields, List.of(ApiVocabulary.KIND)),
        request ->
            registry
                .services()
                .analysisService()
                .startAnalysis(stringList(request.get("analyzers"))));
  }
}
