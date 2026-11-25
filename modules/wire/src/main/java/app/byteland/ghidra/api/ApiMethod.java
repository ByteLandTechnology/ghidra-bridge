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

  /** Validates method descriptor fields and copies field collections. */
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

  /**
   * Decodes raw request parameters with this method's request codec.
   *
   * @param params raw JSON request parameters
   * @return decoded request value
   */
  public Request decodeRequest(Object params) {
    return requestCodec.decode(params, "");
  }

  /**
   * Executes the handler on a decoded request and encodes the projected response.
   *
   * @param request decoded request value
   * @return encoded and projected response value
   * @throws Exception if field validation or handler execution fails
   */
  public Object invokeDecoded(Request request) throws Exception {
    FieldProjection.validate(request, fields, identityFields);
    Response response = handler.handle(request);
    Object encoded = responseCodec.encode(response);
    return FieldProjection.apply(encoded, request, fields, identityFields);
  }

  /**
   * Executes a decoded API request and returns a typed response.
   *
   * @param <Request> decoded request type
   * @param <Response> typed response type
   */
  @FunctionalInterface
  public interface Handler<Request, Response> {
    /**
     * Processes a decoded API request.
     *
     * @param request decoded request value
     * @return typed response value
     * @throws Exception if execution fails
     */
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

    /** Validates consistency across effect flags. */
    public MethodEffects {
      if (readOnly && (mutatesProgram || requiresTransaction || destructive)) {
        throw new IllegalArgumentException("read-only methods cannot mutate or be destructive");
      }
      if (requiresTransaction && !mutatesProgram) {
        throw new IllegalArgumentException("transactional methods must mutate the program");
      }
    }

    /**
     * Returns effect metadata for a batchable read-only query method.
     *
     * @return read-only method effects
     */
    public static MethodEffects readOnlyMethod() {
      return new MethodEffects(true, false, false, true, false, true, true);
    }

    /**
     * Returns effect metadata for a non-batchable metadata inspection method.
     *
     * @return metadata method effects
     */
    public static MethodEffects metadata() {
      return new MethodEffects(true, false, false, true, false, true, false);
    }

    /**
     * Returns effect metadata for a transactional program mutation method.
     *
     * @param destructive {@code true} if the mutation deletes or overwrites data
     * @param idempotent {@code true} if repeated calls produce the same program state
     * @return transactional mutation method effects
     */
    public static MethodEffects mutation(boolean destructive, boolean idempotent) {
      return new MethodEffects(false, true, true, false, destructive, idempotent, true);
    }

    /**
     * Returns effect metadata for a program mutation that manages its own concurrency outside a
     * single transaction.
     *
     * @param destructive {@code true} if the mutation deletes or overwrites data
     * @param idempotent {@code true} if repeated calls produce the same program state
     * @return non-transactional mutation method effects
     */
    public static MethodEffects mutationWithoutTransaction(
        boolean destructive, boolean idempotent) {
      return new MethodEffects(false, true, false, false, destructive, idempotent, false);
    }

    /**
     * Returns effect metadata for a session lifecycle control method.
     *
     * @param destructive {@code true} if the call terminates session state
     * @param idempotent {@code true} if repeated calls have the same effect
     * @return lifecycle method effects
     */
    public static MethodEffects lifecycle(boolean destructive, boolean idempotent) {
      return new MethodEffects(false, false, false, true, destructive, idempotent, false);
    }
  }

  private static final class FieldProjection {
    private FieldProjection() {}

    static Object apply(
        Object response, Object request, Set<String> knownFields, List<String> identityFields) {
      if (!(request instanceof Map<?, ?> params) || !params.containsKey("fields")) {
        return response;
      }
      Set<String> selected = validate(request, knownFields, identityFields);
      return projectResponse(response, selected);
    }

    static Set<String> validate(
        Object request, Set<String> knownFields, List<String> identityFields) {
      if (!(request instanceof Map<?, ?> params) || !params.containsKey("fields")) {
        return new java.util.LinkedHashSet<>(identityFields);
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
      return selected;
    }

    private static Object projectResponse(Object response, Set<String> selected) {
      if (!(response instanceof Map<?, ?> map)) {
        return response;
      }
      if (map.get("items") instanceof List<?> items) {
        Map<String, Object> result = copyStringMap(map);
        result.put(
            "items",
            items.stream()
                .map(item -> item instanceof Map<?, ?> row ? projectMap(row, selected) : item)
                .toList());
        return result;
      }
      return projectMap(map, selected);
    }

    private static Map<String, Object> projectMap(Map<?, ?> source, Set<String> selected) {
      Map<String, Object> result = new java.util.LinkedHashMap<>();
      for (String path : selected) {
        copyPath(source, result, path, 0);
      }
      return result;
    }

    @SuppressWarnings("unchecked")
    private static void copyPath(
        Map<?, ?> source, Map<String, Object> target, String path, int start) {
      int separator = path.indexOf('.', start);
      int end = separator < 0 ? path.length() : separator;
      String segment = path.substring(start, end);
      Object value = source.get(segment);
      if (value == null) {
        return;
      }
      if (separator < 0) {
        target.put(segment, value);
        return;
      }
      if (value instanceof Map<?, ?> child) {
        Map<String, Object> targetChild =
            (Map<String, Object>)
                target.computeIfAbsent(segment, ignored -> new java.util.LinkedHashMap<>());
        copyPath(child, targetChild, path, separator + 1);
      } else if (value instanceof List<?> list) {
        @SuppressWarnings("unchecked")
        List<Object> projected =
            target.get(segment) instanceof List<?> existing
                ? (List<Object>) existing
                : new java.util.ArrayList<>();
        int childIndex = 0;
        for (Object item : list) {
          if (item instanceof Map<?, ?> child) {
            Map<String, Object> targetChild;
            if (childIndex < projected.size()
                && projected.get(childIndex) instanceof Map<?, ?> existingChild) {
              targetChild = (Map<String, Object>) existingChild;
            } else {
              targetChild = new java.util.LinkedHashMap<>();
              projected.add(targetChild);
            }
            copyPath(child, targetChild, path, separator + 1);
            childIndex++;
          }
        }
        target.put(segment, projected);
      }
    }

    private static boolean hasNumericSegment(String path) {
      for (String segment : path.split("\\.", -1)) {
        if (segment.isEmpty() || segment.chars().allMatch(Character::isDigit)) return true;
      }
      return false;
    }

    private static Map<String, Object> copyStringMap(Map<?, ?> source) {
      Map<String, Object> copy = new java.util.LinkedHashMap<>();
      for (Map.Entry<?, ?> entry : source.entrySet()) {
        copy.put(String.valueOf(entry.getKey()), entry.getValue());
      }
      return copy;
    }
  }
}
