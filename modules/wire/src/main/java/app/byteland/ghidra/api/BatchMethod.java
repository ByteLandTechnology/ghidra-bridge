package app.byteland.ghidra.api;

import app.byteland.ghidra.api.ApiMethod.MethodEffects;
import app.byteland.ghidra.service.TransactionRunner;
import java.io.Serial;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

final class BatchMethod {
  static final String NAME = "batch.execute";
  static final int MAX_ITEMS = 1000;
  private static final String ITEMS_TARGET = "/" + ApiVocabulary.ITEMS;

  private final Map<String, ApiMethod<Map<String, Object>, Object>> methods;
  private final BatchRuntime runtime;
  private final Set<String> batchableMethods;
  private final Map<String, Object> requestSchema;

  BatchMethod(Map<String, ApiMethod<Map<String, Object>, Object>> methods, BatchRuntime runtime) {
    this.methods = Objects.requireNonNull(methods, "methods");
    this.runtime = Objects.requireNonNull(runtime, "runtime");

    Set<String> allowedMethods = new LinkedHashSet<>();
    methods.forEach((methodName, method) -> {
      if (method.effects().batchable()) allowedMethods.add(methodName);
    });
    batchableMethods = Collections.unmodifiableSet(allowedMethods);

    List<Map<String, Object>> itemAlternatives = new ArrayList<>();
    batchableMethods.forEach(methodName -> {
      ApiMethod<Map<String, Object>, Object> target = methods.get(methodName);
      itemAlternatives.add(
          WireSchema.object(
              ApiSchemaCatalog.props(
                  "id",
                  WireSchema.nonBlankString(),
                  ApiVocabulary.METHOD,
                  WireSchema.stringEnum(methodName),
                  ApiVocabulary.ARGUMENTS,
                  withoutDefinitions(target.requestCodec().schema())),
              "id",
              ApiVocabulary.METHOD,
              ApiVocabulary.ARGUMENTS));
    });
    requestSchema =
        ApiSchemaCatalog.input(
            ApiSchemaCatalog.props(
                ApiVocabulary.ITEMS,
                WireSchema.array(WireSchema.oneOf(itemAlternatives), 1, MAX_ITEMS),
                ApiVocabulary.TRANSACTION_MODE,
                WireSchema.stringEnum("per_item", "all_or_none")),
            ApiVocabulary.ITEMS);
  }

  Registration registration() {
    return new Registration(
        batchEffects(batchableMethods),
        batchCodec(requestSchema),
        batchResponseCodec(batchResultSchema()),
        this::executeBatch);
  }

  boolean isReadOnly(Map<String, Object> request) {
    if (request instanceof DecodedBatchRequest decoded) {
      return decoded.prepared().readOnly();
    }
    if (!(request.get(ApiVocabulary.ITEMS) instanceof List<?> items) || items.isEmpty()) {
      return false;
    }
    for (Object rawItem : items) {
      if (!(rawItem instanceof Map<?, ?> item)
          || !(item.get(ApiVocabulary.METHOD) instanceof String targetName)) {
        return false;
      }
      ApiMethod<Map<String, Object>, Object> target = methods.get(targetName);
      if (target == null || !target.effects().readOnly()) return false;
    }
    return true;
  }

  boolean allowedDuringAnalysis(Map<String, Object> request) {
    if (request instanceof DecodedBatchRequest decoded) {
      return decoded.prepared().allowedDuringAnalysis();
    }
    if (!(request.get(ApiVocabulary.ITEMS) instanceof List<?> items)) return false;
    for (Object rawItem : items) {
      if (!(rawItem instanceof Map<?, ?> item)
          || !(item.get(ApiVocabulary.METHOD) instanceof String targetName)) {
        return false;
      }
      ApiMethod<Map<String, Object>, Object> target = methods.get(targetName);
      if (target == null || !target.effects().allowedDuringAnalysis()) return false;
    }
    return true;
  }

  private static Map<String, Object> batchResultRowSchema() {
    Map<String, Object> success =
        WireSchema.object(
            Map.of("id", WireSchema.nonBlankString(), "result", WireSchema.any()), "id", "result");
    Map<String, Object> failure =
        WireSchema.object(
            Map.of("id", WireSchema.nonBlankString(), "error", WireSchema.bridgeError()),
            "id",
            "error");
    return WireSchema.oneOf(success, failure);
  }

  private JsonCodec<Map<String, Object>> batchCodec(Map<String, Object> schema) {
    Map<String, Object> publishedSchema = WireSchema.snapshot(schema);
    return new JsonCodec<>() {
      @Override
      public Map<String, Object> decode(Object value, String target) {
        if (!(value instanceof Map<?, ?> raw)) {
          throw ApiException.badRequest(
              ApiVocabulary.INVALID_TYPE, target + " must be an object", target);
        }
        Map<String, Object> request = stringMap(raw);
        PreparedBatch prepared = prepareBatch(request);
        return new DecodedBatchRequest(request, prepared);
      }

      @Override
      public Object encode(Map<String, Object> value) {
        WireSchema.validate(value, publishedSchema, "");
        return value;
      }

      @Override
      public Map<String, Object> schema() {
        return publishedSchema;
      }
    };
  }

  private static JsonCodec<Object> batchResponseCodec(Map<String, Object> schema) {
    Map<String, Object> publishedSchema = WireSchema.snapshot(schema);
    JsonValueCodec delegate = new JsonValueCodec(publishedSchema);
    return new JsonCodec<>() {
      @Override
      public Object decode(Object value, String target) {
        return delegate.decode(value, target);
      }

      @Override
      public Object encode(Object value) {
        Object encoded =
            value instanceof PendingBatchResponse pending ? pending.encodeRows() : value;
        return delegate.encode(encoded);
      }

      @Override
      public Map<String, Object> schema() {
        return publishedSchema;
      }
    };
  }

  private static Map<String, Object> batchResultSchema() {
    return WireSchema.withDefinitions(
        WireSchema.object(
            Map.of(ApiVocabulary.ITEMS, WireSchema.array(batchResultRowSchema(), 1, MAX_ITEMS)),
            ApiVocabulary.ITEMS));
  }

  private static Map<String, Object> withoutDefinitions(Map<String, Object> schema) {
    Map<String, Object> copy = new LinkedHashMap<>(schema);
    copy.remove("$defs");
    return copy;
  }

  private MethodEffects batchEffects(Set<String> methodNames) {
    List<MethodEffects> effects =
        methodNames.stream().map(methods::get).map(ApiMethod::effects).toList();
    boolean readOnly = effects.stream().allMatch(MethodEffects::readOnly);
    boolean mutatesProgram = effects.stream().anyMatch(MethodEffects::mutatesProgram);
    boolean allowedDuringAnalysis = effects.stream().allMatch(MethodEffects::allowedDuringAnalysis);
    boolean destructive = effects.stream().anyMatch(MethodEffects::destructive);
    boolean idempotent = effects.stream().allMatch(MethodEffects::idempotent);
    return new MethodEffects(
        readOnly, mutatesProgram, false, allowedDuringAnalysis, destructive, idempotent, false);
  }

  private Object executeBatch(Map<String, Object> request) {
    PreparedBatch batch =
        request instanceof DecodedBatchRequest decoded ? decoded.prepared() : prepareBatch(request);
    return "all_or_none".equals(batch.transactionMode())
        ? executeAllOrNone(batch.items())
        : executePerItem(batch.items());
  }

  private PreparedBatch prepareBatch(Map<String, Object> request) {
    List<PreparedItem> prepared = new ArrayList<>();
    List<Map<String, Object>> violations = new ArrayList<>();
    Set<String> seenIds = new LinkedHashSet<>();
    for (String key : request.keySet()) {
      if (!Set.of(ApiVocabulary.ITEMS, ApiVocabulary.TRANSACTION_MODE).contains(key)) {
        violations.add(violation("/" + key, "unknown_field", "field is not allowed"));
      }
    }
    Object rawMode = request.get(ApiVocabulary.TRANSACTION_MODE);
    if (request.containsKey(ApiVocabulary.TRANSACTION_MODE)
        && (!(rawMode instanceof String mode)
            || !Set.of("per_item", "all_or_none").contains(mode))) {
      violations.add(
          violation(
              "/transaction_mode",
              rawMode instanceof String ? "invalid_enum" : ApiVocabulary.INVALID_TYPE,
              "transaction_mode must be per_item or all_or_none"));
    }
    Object rawItems = request.get(ApiVocabulary.ITEMS);
    if (!(rawItems instanceof List<?> items)) {
      violations.add(
          violation(
              ITEMS_TARGET,
              request.containsKey(ApiVocabulary.ITEMS)
                  ? ApiVocabulary.INVALID_TYPE
                  : ApiVocabulary.MISSING_FIELD,
              "items must be an array"));
      throw batchValidationFailed(violations);
    }
    if (items.isEmpty() || items.size() > MAX_ITEMS) {
      violations.add(
          violation(
              ITEMS_TARGET, "invalid_count", "items must contain 1.." + MAX_ITEMS + " entries"));
    }
    int inspectedItems = Math.min(items.size(), MAX_ITEMS);
    for (int index = 0; index < inspectedItems; index++) {
      String itemTarget = ITEMS_TARGET + "/" + index;
      if (!(items.get(index) instanceof Map<?, ?> rawItem)) {
        violations.add(violation(itemTarget, ApiVocabulary.INVALID_TYPE, "item must be an object"));
        continue;
      }
      Map<String, Object> item = stringMap(rawItem);
      for (String key : item.keySet()) {
        if (!Set.of("id", ApiVocabulary.METHOD, ApiVocabulary.ARGUMENTS).contains(key)) {
          violations.add(
              violation(itemTarget + "/" + key, "unknown_field", "field is not allowed"));
        }
      }
      String id = null;
      if (item.containsKey("id")) {
        Object rawId = item.get("id");
        if (rawId instanceof String text && !text.isBlank()) id = text;
        else
          violations.add(
              violation(
                  itemTarget + "/id", ApiVocabulary.INVALID_TYPE, "id must be a non-empty string"));
      } else {
        violations.add(
            violation(itemTarget + "/id", ApiVocabulary.MISSING_FIELD, "id is required"));
      }
      if (id != null && !seenIds.add(id)) {
        violations.add(
            violation(itemTarget + "/id", "duplicate_id", "batch item id must be unique"));
      }
      Object rawMethod = item.get(ApiVocabulary.METHOD);
      String method = rawMethod instanceof String text ? text : null;
      if (!item.containsKey(ApiVocabulary.METHOD)) {
        violations.add(
            violation(itemTarget + "/method", ApiVocabulary.MISSING_FIELD, "method is required"));
      } else if (method == null) {
        violations.add(
            violation(
                itemTarget + "/method", ApiVocabulary.INVALID_TYPE, "method must be a string"));
      } else if (!batchableMethods.contains(method)) {
        violations.add(
            violation(itemTarget + "/method", "invalid_method", "method is not batchable"));
      }
      Object rawArguments = item.get(ApiVocabulary.ARGUMENTS);
      if (!(rawArguments instanceof Map<?, ?>)) {
        violations.add(
            violation(
                itemTarget + "/arguments",
                item.containsKey(ApiVocabulary.ARGUMENTS)
                    ? ApiVocabulary.INVALID_TYPE
                    : ApiVocabulary.MISSING_FIELD,
                "arguments must be an object"));
      }
      if (id == null
          || method == null
          || !batchableMethods.contains(method)
          || !(rawArguments instanceof Map<?, ?>)) {
        continue;
      }
      ApiMethod<Map<String, Object>, Object> target = methods.get(method);
      try {
        @SuppressWarnings("unchecked")
        Map<String, Object> arguments = (Map<String, Object>) rawArguments;
        Map<String, Object> decodedArguments = target.decodeRequest(arguments);
        target.validateProjection(decodedArguments);
        prepared.add(new PreparedItem(id, target, decodedArguments));
      } catch (ApiException error) {
        Map<String, Object> violation = new LinkedHashMap<>();
        String targetPath = error.error().target();
        String suffix = targetPath == null ? "" : targetPath;
        violation.put("target", ITEMS_TARGET + "/" + index + "/arguments" + suffix);
        violation.put("code", error.error().code());
        violation.put("message", error.error().message());
        violations.add(violation);
      }
    }
    if (!violations.isEmpty()) {
      throw batchValidationFailed(violations);
    }
    String mode =
        request.get(ApiVocabulary.TRANSACTION_MODE) instanceof String value ? value : "per_item";
    List<PreparedItem> immutableItems = List.copyOf(prepared);
    boolean readOnly =
        !immutableItems.isEmpty()
            && immutableItems.stream().allMatch(item -> item.method().effects().readOnly());
    boolean allowedDuringAnalysis =
        immutableItems.stream().allMatch(item -> item.method().effects().allowedDuringAnalysis());
    return new PreparedBatch(immutableItems, mode, readOnly, allowedDuringAnalysis);
  }

  private static ApiException batchValidationFailed(List<Map<String, Object>> violations) {
    return new ApiException(
        400,
        new BridgeError(
            400,
            "validation_failed",
            "batch structure validation failed",
            ITEMS_TARGET,
            Map.of("violations", List.copyOf(violations))));
  }

  private static Map<String, Object> stringMap(Map<?, ?> source) {
    Map<String, Object> result = new LinkedHashMap<>();
    for (Map.Entry<?, ?> entry : source.entrySet()) {
      result.put(String.valueOf(entry.getKey()), entry.getValue());
    }
    return result;
  }

  private static Map<String, Object> violation(String target, String code, String message) {
    Map<String, Object> violation = new LinkedHashMap<>();
    violation.put("target", target);
    violation.put("code", code);
    violation.put("message", message);
    return violation;
  }

  private PendingBatchResponse executePerItem(List<PreparedItem> items) {
    List<PendingRow> rows = new ArrayList<>();
    for (PreparedItem item : items) {
      try {
        Object rawResult = runtime.invokeHandler(item.method(), item.request(), true);
        rows.add(PendingRow.success(item, rawResult));
      } catch (Exception error) {
        rows.add(PendingRow.failure(item.id(), error));
      }
    }
    return new PendingBatchResponse(List.copyOf(rows), false);
  }

  private Object executeAllOrNone(List<PreparedItem> items) {
    try {
      boolean requiresTransaction =
          items.stream().anyMatch(item -> item.method().effects().requiresTransaction());
      if (requiresTransaction) {
        return runtime.inTransaction(() -> batchEnvelope(executeAllOrNoneTransactional(items)));
      }
      return new PendingBatchResponse(List.copyOf(executeAllOrNoneItems(items)), true);
    } catch (BatchRollback rollback) {
      throw translateBatchRollback(rollback.itemId(), rollback.getCause(), rollback);
    }
  }

  private List<Map<String, Object>> executeAllOrNoneTransactional(List<PreparedItem> items) {
    List<Map<String, Object>> encoded = new ArrayList<>(items.size());
    for (PreparedItem item : items) {
      try {
        Object rawResult = runtime.invokeHandler(item.method(), item.request(), false);
        encoded.add(successRow(item.id(), item.method().encodeResponse(item.request(), rawResult)));
      } catch (Exception error) {
        throw new BatchRollback(item.id(), error);
      }
    }
    return encoded;
  }

  private List<PendingRow> executeAllOrNoneItems(List<PreparedItem> items) {
    List<PendingRow> temporary = new ArrayList<>();
    for (PreparedItem item : items) {
      try {
        temporary.add(
            PendingRow.success(item, runtime.invokeHandler(item.method(), item.request(), false)));
      } catch (Exception error) {
        throw new BatchRollback(item.id(), error);
      }
    }
    return temporary;
  }

  private static ApiException translateBatchRollback(
      String failedItemId, Throwable rawCause, Throwable attachCause) {
    BridgeError cause = ApiFailures.normalize(rawCause).error();
    ApiException translated =
        new ApiException(
            409,
            new BridgeError(
                409,
                "batch_rolled_back",
                "all_or_none batch rolled back",
                ITEMS_TARGET,
                Map.of("failed_item", failedItemId, "cause", cause.toMap())));
    translated.initCause(attachCause);
    return translated;
  }

  private static Map<String, Object> successRow(String id, Object result) {
    Map<String, Object> row = new LinkedHashMap<>();
    row.put("id", id);
    row.put("result", result);
    return row;
  }

  private static Map<String, Object> errorRow(String id, Throwable failure) {
    BridgeError error = ApiFailures.normalize(failure).error();
    Map<String, Object> row = new LinkedHashMap<>();
    row.put("id", id);
    row.put("error", error.toMap());
    return row;
  }

  private static Map<String, Object> batchEnvelope(List<Map<String, Object>> rows) {
    return Map.of(ApiVocabulary.ITEMS, rows);
  }

  private record PreparedItem(
      String id, ApiMethod<Map<String, Object>, Object> method, Map<String, Object> request) {}

  private record PreparedBatch(
      List<PreparedItem> items,
      String transactionMode,
      boolean readOnly,
      boolean allowedDuringAnalysis) {}

  private static final class DecodedBatchRequest extends java.util.AbstractMap<String, Object> {
    private final Map<String, Object> fields;
    private final PreparedBatch prepared;

    DecodedBatchRequest(Map<String, Object> fields, PreparedBatch prepared) {
      this.fields = Collections.unmodifiableMap(new LinkedHashMap<>(fields));
      this.prepared = prepared;
    }

    PreparedBatch prepared() {
      return prepared;
    }

    @Override
    public Set<Entry<String, Object>> entrySet() {
      return fields.entrySet();
    }
  }

  private record PendingRow(String id, PreparedItem item, Object rawResult, Throwable failure) {
    static PendingRow success(PreparedItem item, Object rawResult) {
      return new PendingRow(item.id(), item, rawResult, null);
    }

    static PendingRow failure(String id, Throwable failure) {
      return new PendingRow(id, null, null, failure);
    }
  }

  private record PendingBatchResponse(List<PendingRow> rows, boolean allOrNone) {
    Map<String, Object> encodeRows() {
      List<Map<String, Object>> encoded = new ArrayList<>(rows.size());
      for (PendingRow row : rows) {
        if (row.failure() != null) {
          encoded.add(errorRow(row.id(), row.failure()));
          continue;
        }
        PreparedItem item = row.item();
        if (allOrNone) {
          try {
            encoded.add(
                successRow(
                    item.id(), item.method().encodeResponse(item.request(), row.rawResult())));
          } catch (Exception error) {
            throw translateBatchRollback(item.id(), error, error);
          }
        } else {
          try {
            encoded.add(
                successRow(
                    item.id(), item.method().encodeResponse(item.request(), row.rawResult())));
          } catch (Exception error) {
            encoded.add(errorRow(item.id(), error));
          }
        }
      }
      return batchEnvelope(encoded);
    }
  }

  private static final class BatchRollback extends RuntimeException {
    @Serial private static final long serialVersionUID = 1L;
    private final String failedItemId;

    BatchRollback(String itemId, Throwable cause) {
      super(cause);
      this.failedItemId = itemId;
    }

    String itemId() {
      return failedItemId;
    }
  }

  record Registration(
      MethodEffects effects,
      JsonCodec<Map<String, Object>> requestCodec,
      JsonCodec<Object> responseCodec,
      ApiMethod.Handler<Map<String, Object>, Object> handler) {}

  interface BatchRuntime {
    Object invokeHandler(
        ApiMethod<Map<String, Object>, Object> method,
        Map<String, Object> request,
        boolean ownTransaction)
        throws Exception;

    <T> T inTransaction(TransactionRunner.Operation<T> operation);
  }
}
