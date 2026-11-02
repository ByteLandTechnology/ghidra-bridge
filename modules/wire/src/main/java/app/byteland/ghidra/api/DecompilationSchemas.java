package app.byteland.ghidra.api;

import java.util.List;
import java.util.Map;

final class DecompilationSchemas {
  private DecompilationSchemas() {}

  static Map<String, Object> lines() {
    Map<String, Object> token = WireSchema.object(
        ApiSchemaCatalog.props(
            "kind", WireSchema.string(),
            "text", WireSchema.string(),
            "start", WireSchema.integer(0, Integer.MAX_VALUE),
            "end", WireSchema.integer(0, Integer.MAX_VALUE),
            "address", WireSchema.string(),
            "max_address", WireSchema.string(),
            "location_address", WireSchema.string(),
            "code_unit_address", WireSchema.string(),
            "symbol", ApiSchemaCatalog.resourceSchema(
                ApiSchemaCatalog.symbolFields(), List.of("id"))),
        "kind", "text", "start", "end", "location_address");
    return WireSchema.array(
        WireSchema.object(
            ApiSchemaCatalog.props(
                "number", WireSchema.integer(0, Integer.MAX_VALUE),
                "indent", WireSchema.integer(0, Integer.MAX_VALUE),
                "tokens", WireSchema.array(token, 0, Integer.MAX_VALUE)),
            "number", "indent", "tokens"),
        0, Integer.MAX_VALUE);
  }
}
