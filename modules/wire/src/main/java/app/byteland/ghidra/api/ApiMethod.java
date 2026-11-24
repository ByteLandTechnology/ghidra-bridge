package app.byteland.ghidra.api;

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

  public Object invoke(Object params) throws Exception {
    return invokeDecoded(decodeRequest(params));
  }

  public Request decodeRequest(Object params) {
    return requestCodec.decode(params, "");
  }

  public Object invokeDecoded(Request request) throws Exception {
    Set<String> projectedFields = FieldProjection.validate(request, fields, identityFields);
    Response response =
        handler instanceof ProjectedHandler<Request, Response> projectedHandler
            ? projectedHandler.handle(request, projectedFields)
            : handler.handle(request);
    if (projectedFields == null) {
      return responseCodec.encode(response);
    }
    if (handler instanceof ProjectedHandler<?, ?>) {
      return responseCodec.encode(response, projectedFields);
    }
    Object encoded = responseCodec.encode(response);
    return ProjectionNode.fromFields(projectedFields).projectResponse(encoded);
  }

  @FunctionalInterface
  public interface Handler<Request, Response> {
    Response handle(Request request) throws Exception;
  }

  @FunctionalInterface
  interface ProjectedHandler<Request, Response> extends Handler<Request, Response> {
    Response handle(Request request, Set<String> projectedFields) throws Exception;

    @Override
    default Response handle(Request request) throws Exception {
      return handle(request, null);
    }
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
      Set<String> selected = new java.util.LinkedHashSet<>(identityFields);
      Set<String> explicitlyRequested = new java.util.LinkedHashSet<>();
      for (int index = 0; index < requested.size(); index++) {
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

    private static boolean hasNumericSegment(String path) {
      for (String segment : path.split("\\.", -1)) {
        if (segment.isEmpty() || segment.chars().allMatch(Character::isDigit)) return true;
      }
      return false;
    }
  }
}
