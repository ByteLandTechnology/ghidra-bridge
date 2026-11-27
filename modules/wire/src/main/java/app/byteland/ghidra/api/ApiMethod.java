package app.byteland.ghidra.api;

import app.byteland.ghidra.service.DomainException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Defines a typed API method with its schemas, codecs, and execution handler.
 *
 * @param <Request> typed request object type
 * @param <Response> typed response object type
 * @param name public dotted method name
 * @param description technical description of the operation
 * @param effects execution effects and transaction requirements
 * @param requestCodec codec that parses and validates requests
 * @param responseCodec codec that serializes responses
 * @param fields set of selectable field projection paths
 * @param identityFields minimum fields in all projections
 * @param handler execution delegate for the operation
 */
public record ApiMethod<Request, Response>(
    String name,
    String description,
    MethodEffects effects,
    JsonCodec<Request> requestCodec,
    JsonCodec<Response> responseCodec,
    Set<String> fields,
    List<String> identityFields,
    Handler<Request, Response> handler) {

  public ApiMethod {
    Objects.requireNonNull(name, "name");
    if (description == null || description.isBlank()) {
      throw new IllegalArgumentException("description must not be blank");
    }
    Objects.requireNonNull(effects, "effects");
    Objects.requireNonNull(requestCodec, "requestCodec");
    Objects.requireNonNull(responseCodec, "responseCodec");
    fields = Set.copyOf(fields);
    identityFields = List.copyOf(identityFields);
    Objects.requireNonNull(handler, "handler");
  }

  public Request decodeRequest(Object params) {
    return requestCodec.decode(params, "");
  }

  public void validateProjection(Request request) {
    FieldProjection.validate(request, fields, identityFields);
  }

  Set<String> selectProjection(Request request) {
    return FieldProjection.validate(request, fields, identityFields);
  }

  public Response invokeHandler(Request request) throws Exception {
    return invokeHandler(request, selectProjection(request));
  }

  Response invokeHandler(Request request, Set<String> selected) throws Exception {
    try {
      if (handler instanceof ProjectedHandler<Request, Response> projectedHandler) {
        return projectedHandler.handleProjected(request, selected);
      }
      return handler.handle(request);
    } catch (Exception error) {
      throw rebaseExecutionFailure(error, requestCodec.schema());
    }
  }

  public Object encodeResponse(Request request, Response response) {
    return encodeResponse(response, selectProjection(request));
  }

  Object encodeResponse(Response response, Set<String> selected) {
    if (selected == null) {
      return responseCodec.encode(response);
    }
    Object projectedResponse =
        handler instanceof ProjectedHandler<?, ?>
            ? response
            : FieldProjection.projectFallback(response, selected);
    if (responseCodec instanceof JsonValueCodec valueCodec) {
      return valueCodec.encode(projectedResponse, selected);
    }
    @SuppressWarnings("unchecked")
    Response typed = (Response) projectedResponse;
    return responseCodec.encode(typed);
  }

  public Object invokeDecoded(Request request) throws Exception {
    Set<String> selected = selectProjection(request);
    Response response = invokeHandler(request, selected);
    return encodeResponse(response, selected);
  }

  private static Exception rebaseExecutionFailure(
      Exception error, Map<String, Object> requestSchema) {
    if (!(error instanceof DomainException domain)) {
      return error;
    }
    ApiFailures.Failure normalized = ApiFailures.normalize(error);
    BridgeError bridgeError = normalized.error();
    String currentTarget = bridgeError.target();
    String rebasedTarget = WireSchema.rebasePointer(currentTarget, requestSchema);
    if (Objects.equals(currentTarget, rebasedTarget)) {
      return error;
    }
    String message = bridgeError.message();
    String rawTarget = domain.target();
    if (currentTarget != null
        && !currentTarget.isBlank()
        && message != null
        && message.startsWith(currentTarget + " ")) {
      message = rebasedTarget + message.substring(currentTarget.length());
    } else if (rawTarget != null
        && !rawTarget.isBlank()
        && message != null
        && message.startsWith(rawTarget + " ")) {
      message = rebasedTarget + message.substring(rawTarget.length());
    }
    ApiException rebased =
        new ApiException(
            normalized.status(),
            new BridgeError(
                bridgeError.status(),
                bridgeError.code(),
                message,
                rebasedTarget,
                bridgeError.details()));
    rebased.initCause(error);
    return rebased;
  }

  @FunctionalInterface
  public interface Handler<Request, Response> {
    Response handle(Request request) throws Exception;
  }

  /**
   * Defines runtime effects and concurrency limits for a method.
   *
   * @param readOnly true if method does not modify program state
   * @param mutatesProgram true if method alters the program database
   * @param requiresTransaction true if execution must wrap in a transaction
   * @param allowedDuringAnalysis true if method can run while analysis is active
   * @param destructive true if operation permanently removes data
   * @param idempotent true if repeated calls produce identical results
   * @param batchable true if method can nest inside batch operations
   */
  public record MethodEffects(
      boolean readOnly,
      boolean mutatesProgram,
      boolean requiresTransaction,
      boolean allowedDuringAnalysis,
      boolean destructive,
      boolean idempotent,
      boolean batchable) {

    public MethodEffects {
      if (readOnly && (mutatesProgram || requiresTransaction || destructive)) {
        throw new IllegalArgumentException("read-only methods cannot mutate or be destructive");
      }
      if (requiresTransaction && !mutatesProgram) {
        throw new IllegalArgumentException("transactional methods must mutate the program");
      }
    }

    public static MethodEffects readOnlyMethod() {
      return new MethodEffects(true, false, false, true, false, true, true);
    }

    public static MethodEffects metadata() {
      return new MethodEffects(true, false, false, true, false, true, false);
    }

    public static MethodEffects mutation(boolean destructive, boolean idempotent) {
      return new MethodEffects(false, true, true, false, destructive, idempotent, true);
    }

    public static MethodEffects mutationWithoutTransaction(
        boolean destructive, boolean idempotent) {
      return new MethodEffects(false, true, false, false, destructive, idempotent, false);
    }

    public static MethodEffects lifecycle(boolean destructive, boolean idempotent) {
      return new MethodEffects(false, false, false, true, destructive, idempotent, false);
    }
  }

  private static final class FieldProjection {
    private FieldProjection() {}

    static Set<String> validate(
        Object request, Set<String> knownFields, List<String> identityFields) {
      if (!(request instanceof Map<?, ?> params) || !params.containsKey("fields")) {
        return null;
      }
      Object rawFields = params.get("fields");
      if (!(rawFields instanceof List<?> requested)) {
        throw ApiException.badRequest(
            "invalid_fields", "/projection/fields must be an array", "/projection/fields");
      }
      int size = requested.size();
      if (knownFields.isEmpty() && size == 0) {
        throw ApiException.badRequest(
            "invalid_fields", "/projection/fields is not supported", "/projection/fields");
      }
      Set<String> selected = java.util.LinkedHashSet.newLinkedHashSet(identityFields.size() + size);
      selected.addAll(identityFields);
      Set<String> explicitlyRequested = java.util.LinkedHashSet.newLinkedHashSet(size);
      for (int index = 0; index < size; index++) {
        Object item = requested.get(index);
        String target = "/projection/fields/" + index;
        if (!(item instanceof String path)
            || path.isBlank()
            || path.contains("*")
            || hasNumericSegment(path)) {
          throw ApiException.badRequest("invalid_fields", target + " is invalid", target);
        }
        if (!explicitlyRequested.add(path)) {
          throw ApiException.badRequest("duplicate_field", path + " is duplicated", target);
        }
        if (!knownFields.contains(path)) {
          throw ApiException.badRequest("unknown_field", path + " is not selectable", target);
        }
        selected.add(path);
      }
      return java.util.Collections.unmodifiableSet(selected);
    }

    static Object projectFallback(Object response, Set<String> selected) {
      FieldSelection selection = FieldSelection.from(selected);
      if (response instanceof Map<?, ?> map
          && map.get(ApiVocabulary.ITEMS) instanceof List<?> items
          && !selection.containsKey(ApiVocabulary.ITEMS)) {
        Map<String, Object> copy = java.util.LinkedHashMap.newLinkedHashMap(map.size());
        for (Map.Entry<?, ?> entry : map.entrySet()) {
          copy.put(String.valueOf(entry.getKey()), entry.getValue());
        }
        copy.put(ApiVocabulary.ITEMS, WireValues.normalize(items, selection));
        return copy;
      }
      return WireValues.normalize(response, selection);
    }

    private static boolean hasNumericSegment(String path) {
      int start = 0;
      while (start <= path.length()) {
        int dot = path.indexOf('.', start);
        int end = dot < 0 ? path.length() : dot;
        if (end == start) {
          return true;
        }
        boolean allDigits = true;
        for (int index = start; index < end; index++) {
          if (!Character.isDigit(path.charAt(index))) {
            allDigits = false;
            break;
          }
        }
        if (allDigits) {
          return true;
        }
        if (dot < 0) {
          break;
        }
        start = dot + 1;
      }
      return false;
    }
  }
}
