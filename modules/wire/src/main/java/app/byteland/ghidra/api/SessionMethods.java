package app.byteland.ghidra.api;

import app.byteland.ghidra.api.ApiMethod.MethodEffects;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;

final class SessionMethods implements ApiMethodProvider {
  private final ApiRegistry registry;
  private final Supplier<Map<String, Object>> sessionSupplier;
  private final Runnable shutdownAction;

  SessionMethods(
      ApiRegistry registry,
      Supplier<Map<String, Object>> sessionSupplier,
      Runnable shutdownAction) {
    this.registry = registry;
    this.sessionSupplier = sessionSupplier;
    this.shutdownAction = shutdownAction;
  }

  @Override
  public void register() {
    Map<String, Object> empty = ApiSchemaCatalog.input(Map.of());
    Map<String, Object> fields = ApiRegistry.fieldsSchema();
    registry.read(
        "session.get",
        ApiSchemaCatalog.input(ApiSchemaCatalog.props(ApiVocabulary.FIELDS, fields)),
        Set.of("id", "status", "program_name"),
        List.of("id"),
        request -> sessionSupplier.get());
    registry.writeResult(
        "session.shutdown",
        MethodEffects.lifecycle(true, true),
        empty,
        ApiSchemaCatalog.SHUTDOWN_RECEIPT_SCHEMA,
        request -> {
          shutdownAction.run();
          return Map.of("shutdown", true);
        });
  }
}
