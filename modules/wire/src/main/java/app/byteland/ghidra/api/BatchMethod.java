package app.byteland.ghidra.api;

import app.byteland.ghidra.JsonUtil;
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
import java.util.function.LongSupplier;

final class BatchMethod {
  static final String NAME = "batch.execute";
  static final int MAX_ITEMS = 1000;
  static final int MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
  static final long MAX_DURATION_MS = 60_000L;

  private static final long NANOS_PER_MILLISECOND = 1_000_000L;
  private static final int EMPTY_ENVELOPE_BYTES = "{\"items\":[]}".length();
  private static final String ITEMS_TARGET = "/" + ApiVocabulary.ITEMS;
  private static final ThreadLocal<Deadline> ACTIVE_DEADLINE = new ThreadLocal<>();

  private final Map<String, ApiMethod<Map<String, Object>, Object>> methods;
  private final BatchRuntime runtime;
  private final LongSupplier nanoTime;
  private final int maxResponseBytes;
  private final long maxDurationMs;
  private final Set<String> batchableMethods;
  private final Map<String, Object> requestSchema;

  BatchMethod(Map<String, ApiMethod<Map<String, Object>, Object>> methods, BatchRuntime runtime) {
    this(methods, runtime, System::nanoTime, MAX_RESPONSE_BYTES, MAX_DURATION_MS);
  }

  BatchMethod(
      Map<String, ApiMethod<Map<String, Object>, Object>> methods,
      BatchRuntime runtime,
      LongSupplier nanoTime) {
    this(methods, runtime, nanoTime, MAX_RESPONSE_BYTES, MAX_DURATION_MS);
  }

  BatchMethod(
      Map<String, ApiMethod<Map<String, Object>, Object>> methods,
      BatchRuntime runtime,
      LongSupplier nanoTime,
      int maxResponseBytes,
      long maxDurationMs) {
    this.methods = Objects.requireNonNull(methods, "methods");
    this.runtime = Objects.requireNonNull(runtime, "runtime");
    this.nanoTime = Objects.requireNonNull(nanoTime, "nanoTime");
    if (maxResponseBytes <= EMPTY_ENVELOPE_BYTES) {
      throw new IllegalArgumentException("maxResponseBytes must exceed envelope overhead");
    }
    if (maxDurationMs <= 0L) {
      throw new IllegalArgumentException("maxDurationMs must be positive");
    }
    this.maxResponseBytes = maxResponseBytes;
    this.maxDurationMs = maxDurationMs;

    Set<String> allowedMethods = new LinkedHashSet<>();
    methods.forEach(
        (methodName, method) -> {
          if (method.effects().batchable()) allowedMethods.add(methodName);
        });
    batchableMethods = Collections.unmodifiableSet(allowedMethods);

    List<Map<String, Object>> itemAlternatives = new ArrayList<>();
    batchableMethods.forEach(
        methodName -> {
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
                WireSchema.array(
                    WireSchema.taggedOneOf(ApiVocabulary.METHOD, itemAlternatives), 1, MAX_ITEMS),
                ApiVocabulary.TRANSACTION_MODE,
                WireSchema.withDefault(WireSchema.stringEnum("per_item", "all_or_none"), "per_item")),
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
        request.putIfAbsent(ApiVocabulary.TRANSACTION_MODE, "per_item");
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
        Object encoded;
        try {
          encoded = value instanceof PendingBatchResponse pending ? pending.encodeRows() : value;
        } catch (BatchLimitException limitError) {
          throw limitError.apiException();
        }
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

  static int clampTimeoutMs(int requestedTimeoutMs) {
    Deadline deadline = ACTIVE_DEADLINE.get();
    if (deadline == null) {
      return requestedTimeoutMs;
    }
    int remainingMs = deadline.requireRemainingMillis();
    return Math.min(requestedTimeoutMs, remainingMs);
  }

  private Object executeBatch(Map<String, Object> request) {
    Deadline deadline = new Deadline(nanoTime, maxDurationMs);
    PreparedBatch batch =
        request instanceof DecodedBatchRequest decoded
            ? decoded.prepared()
            : prepareBatch(request);
    Deadline previous = ACTIVE_DEADLINE.get();
    ACTIVE_DEADLINE.set(deadline);
    try {
      return "all_or_none".equals(batch.transactionMode())
          ? executeAllOrNone(batch.items(), deadline)
          : executePerItem(batch.items(), deadline);
    } catch (BatchLimitException limitError) {
      throw limitError.apiException();
    } finally {
      if (previous == null) {
        ACTIVE_DEADLINE.remove();
      } else {
        ACTIVE_DEADLINE.set(previous);
      }
    }
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
        Set<String> selectedFields = target.selectProjection(decodedArguments);
        prepared.add(new PreparedItem(id, target, decodedArguments, selectedFields));
      } catch (ApiException error) {
        Map<String, Object> violation = new LinkedHashMap<>();
        String targetPath = error.error().target();
        String suffix = targetPath == null ? "" : targetPath;
        String rebasedTarget = ITEMS_TARGET + "/" + index + "/arguments" + suffix;
        String message = error.error().message();
        if (targetPath != null
            && !targetPath.isBlank()
            && message != null
            && message.startsWith(targetPath + " ")) {
          message = rebasedTarget + message.substring(targetPath.length());
        }
        violation.put("target", rebasedTarget);
        violation.put("code", error.error().code());
        violation.put("message", message);
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

  private PendingBatchResponse executePerItem(List<PreparedItem> items, Deadline deadline) {
    List<PendingRow> rows = new ArrayList<>();
    SizeTracker sizeTracker = new SizeTracker(maxResponseBytes);
    for (PreparedItem item : items) {
      deadline.checkBeforeItem(item.id());
      try {
        Object rawResult =
            runtime.invokeHandler(item.method(), item.request(), item.selectedFields(), true);
        if (Thread.currentThread().isInterrupted()) {
          throw new BatchLimitException(deadline.interrupted(item.id()));
        }
        Object projected = item.method().projectResponse(rawResult, item.selectedFields());
        sizeTracker.acceptRow(item.id(), successRow(item.id(), projected));
        rows.add(PendingRow.success(item, projected));
      } catch (BatchLimitException limitError) {
        throw limitError;
      } catch (Exception error) {
        if (Thread.currentThread().isInterrupted()) {
          throw new BatchLimitException(deadline.interrupted(item.id()));
        }
        Map<String, Object> failureRow = errorRow(item.id(), error);
        sizeTracker.acceptRow(item.id(), failureRow);
        rows.add(PendingRow.encodedFailure(item.id(), failureRow));
      }
    }
    return new PendingBatchResponse(List.copyOf(rows), false, maxResponseBytes);
  }

  private Object executeAllOrNone(List<PreparedItem> items, Deadline deadline) {
    try {
      boolean requiresTransaction =
          items.stream().anyMatch(item -> item.method().effects().requiresTransaction());
      if (requiresTransaction) {
        return runtime.inTransaction(
            () -> batchEnvelope(executeAllOrNoneTransactional(items, deadline)));
      }
      return new PendingBatchResponse(
          List.copyOf(executeAllOrNoneItems(items, deadline)), true, maxResponseBytes);
    } catch (BatchRollback rollback) {
      throw translateBatchRollback(rollback.itemId(), rollback.getCause(), rollback);
    }
  }

  private List<Map<String, Object>> executeAllOrNoneTransactional(
      List<PreparedItem> items, Deadline deadline) {
    List<Map<String, Object>> encoded = new ArrayList<>(items.size());
    SizeTracker sizeTracker = new SizeTracker(maxResponseBytes);
    for (PreparedItem item : items) {
      try {
        deadline.checkBeforeItem(item.id());
        Object rawResult =
            runtime.invokeHandler(item.method(), item.request(), item.selectedFields(), false);
        if (Thread.currentThread().isInterrupted()) {
          throw new BatchLimitException(deadline.interrupted(item.id()));
        }
        Map<String, Object> row =
            successRow(item.id(), item.method().encodeResponse(rawResult, item.selectedFields()));
        sizeTracker.acceptRow(item.id(), row);
        encoded.add(row);
      } catch (BatchLimitException limitError) {
        throw new BatchRollback(item.id(), limitError.apiException());
      } catch (Exception error) {
        if (Thread.currentThread().isInterrupted()) {
          throw new BatchRollback(item.id(), deadline.interrupted(item.id()));
        }
        throw new BatchRollback(item.id(), error);
      }
    }
    return encoded;
  }

  private List<PendingRow> executeAllOrNoneItems(List<PreparedItem> items, Deadline deadline) {
    List<PendingRow> temporary = new ArrayList<>();
    SizeTracker sizeTracker = new SizeTracker(maxResponseBytes);
    for (PreparedItem item : items) {
      try {
        deadline.checkBeforeItem(item.id());
        Object rawResult =
            runtime.invokeHandler(item.method(), item.request(), item.selectedFields(), false);
        if (Thread.currentThread().isInterrupted()) {
          throw new BatchLimitException(deadline.interrupted(item.id()));
        }
        Object projected = item.method().projectResponse(rawResult, item.selectedFields());
        sizeTracker.acceptRow(item.id(), successRow(item.id(), projected));
        temporary.add(PendingRow.success(item, projected));
      } catch (BatchLimitException limitError) {
        throw new BatchRollback(item.id(), limitError.apiException());
      } catch (Exception error) {
        if (Thread.currentThread().isInterrupted()) {
          throw new BatchRollback(item.id(), deadline.interrupted(item.id()));
        }
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
      String id,
      ApiMethod<Map<String, Object>, Object> method,
      Map<String, Object> request,
      Set<String> selectedFields) {}

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

  private record PendingRow(
      String id, PreparedItem item, Object projectedResult, Map<String, Object> failureRow) {
    static PendingRow success(PreparedItem item, Object projectedResult) {
      return new PendingRow(item.id(), item, projectedResult, null);
    }

    static PendingRow encodedFailure(String id, Map<String, Object> failureRow) {
      return new PendingRow(id, null, null, failureRow);
    }
  }

  private record PendingBatchResponse(
      List<PendingRow> rows, boolean allOrNone, int maxResponseBytes) {
    Map<String, Object> encodeRows() {
      List<Map<String, Object>> encoded = new ArrayList<>(rows.size());
      SizeTracker sizeTracker = new SizeTracker(maxResponseBytes);
      for (PendingRow row : rows) {
        if (row.failureRow() != null) {
          sizeTracker.acceptRow(row.id(), row.failureRow());
          encoded.add(row.failureRow());
          continue;
        }
        PreparedItem item = row.item();
        if (allOrNone) {
          Map<String, Object> encodedRow;
          try {
            encodedRow =
                successRow(
                    item.id(),
                    item.method()
                        .encodeProjectedResponse(row.projectedResult(), item.selectedFields()));
            sizeTracker.acceptRow(item.id(), encodedRow);
          } catch (BatchLimitException limitError) {
            throw translateBatchRollback(
                item.id(), limitError.apiException(), limitError.apiException());
          } catch (Exception error) {
            throw translateBatchRollback(item.id(), error, error);
          }
          encoded.add(encodedRow);
        } else {
          Map<String, Object> encodedRow;
          try {
            encodedRow =
                successRow(
                    item.id(),
                    item.method()
                        .encodeProjectedResponse(row.projectedResult(), item.selectedFields()));
          } catch (Exception error) {
            encodedRow = errorRow(item.id(), error);
          }
          sizeTracker.acceptRow(item.id(), encodedRow);
          encoded.add(encodedRow);
        }
      }
      return batchEnvelope(encoded);
    }
  }

  private static final class BatchRollback extends RuntimeException {
    @Serial
    private static final long serialVersionUID = 1L;
    private final String failedItemId;

    BatchRollback(String itemId, Throwable cause) {
      super(cause);
      this.failedItemId = itemId;
    }

    String itemId() {
      return failedItemId;
    }
  }

  private static final class BatchLimitException extends RuntimeException {
    @Serial
    private static final long serialVersionUID = 1L;
    private final ApiException apiException;

    BatchLimitException(ApiException apiException) {
      super(apiException.getMessage(), apiException);
      this.apiException = apiException;
    }

    ApiException apiException() {
      return apiException;
    }
  }

  private static final class SizeTracker {
    private final int maxResponseBytes;
    private int totalBytes = EMPTY_ENVELOPE_BYTES;
    private int rowCount;

    SizeTracker(int maxResponseBytes) {
      this.maxResponseBytes = maxResponseBytes;
    }

    void acceptRow(String itemId, Map<String, Object> row) {
      int separatorBytes = rowCount == 0 ? 0 : 1;
      int remainingBudget = maxResponseBytes - totalBytes - separatorBytes;
      if (remainingBudget <= 0) {
        throw new BatchLimitException(responseTooLarge(itemId, maxResponseBytes));
      }
      int rowBytes;
      try {
        rowBytes = JsonUtil.utf8ByteLength(row, remainingBudget);
      } catch (ApiException error) {
        if ("response_too_large".equals(error.error().code())) {
          throw new BatchLimitException(responseTooLarge(itemId, maxResponseBytes));
        }
        throw error;
      }
      totalBytes += separatorBytes + rowBytes;
      rowCount++;
    }

    private static ApiException responseTooLarge(String itemId, int maxResponseBytes) {
      Map<String, Object> details = new LinkedHashMap<>();
      if (itemId != null) {
        details.put("failed_item", itemId);
      }
      details.put("max_bytes", maxResponseBytes);
      return new ApiException(
          413,
          new BridgeError(
              413,
              "response_too_large",
              "batch response exceeds maximum size of " + maxResponseBytes + " bytes",
              ITEMS_TARGET,
              details));
    }
  }

  private static final class Deadline {
    private final LongSupplier nanoTime;
    private final long maxDurationMs;
    private final long durationNanos;
    private final long startedNanos;
    private String currentItemId;

    Deadline(LongSupplier nanoTime, long maxDurationMs) {
      this.nanoTime = nanoTime;
      this.maxDurationMs = maxDurationMs;
      this.durationNanos = Math.multiplyExact(maxDurationMs, NANOS_PER_MILLISECOND);
      this.startedNanos = nanoTime.getAsLong();
    }

    void checkBeforeItem(String itemId) {
      this.currentItemId = itemId;
      if (Thread.currentThread().isInterrupted()) {
        throw new BatchLimitException(interrupted(itemId));
      }
      if (remainingNanos() <= 0L) {
        throw new BatchLimitException(timedOut(itemId));
      }
    }

    int requireRemainingMillis() {
      String itemId = currentItemId;
      if (Thread.currentThread().isInterrupted()) {
        throw new BatchLimitException(interrupted(itemId));
      }
      long remaining = remainingNanos();
      if (remaining <= 0L) {
        throw new BatchLimitException(timedOut(itemId));
      }
      return (int) Math.min(Integer.MAX_VALUE, Math.ceilDiv(remaining, NANOS_PER_MILLISECOND));
    }

    private long remainingNanos() {
      long elapsed = Math.max(0L, nanoTime.getAsLong() - startedNanos);
      return durationNanos - elapsed;
    }

    ApiException interrupted(String itemId) {
      Map<String, Object> details = itemId == null ? Map.of() : Map.of("failed_item", itemId);
      return new ApiException(
          408,
          new BridgeError(
              408,
              "operation_timed_out",
              "batch execution was interrupted",
              ITEMS_TARGET,
              details));
    }

    ApiException timedOut(String itemId) {
      Map<String, Object> details = new LinkedHashMap<>();
      if (itemId != null) {
        details.put("failed_item", itemId);
      }
      details.put("timeout_ms", maxDurationMs);
      return new ApiException(
          408,
          new BridgeError(
              408,
              "operation_timed_out",
              "batch execution exceeded maximum duration of " + maxDurationMs + " ms",
              ITEMS_TARGET,
              details));
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
        Set<String> selectedFields,
        boolean ownTransaction)
        throws Exception;

    <T> T inTransaction(TransactionRunner.Operation<T> operation);
  }
}
