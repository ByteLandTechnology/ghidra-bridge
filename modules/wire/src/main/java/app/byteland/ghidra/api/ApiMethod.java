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
 * @param requestCodec codec for parsing and validating requests
 * @param responseCodec codec for serializing responses
 * @param fields set of selectable field projection paths
 * @param identityFields minimum fields always included in projections
 * @param handler execution delegate for the operation
 * @param mcpAnnotations per-method hint metadata recorded in the catalog; grouped MCP tools do not
 *     publish it
 */
public record ApiMethod<Request, Response>(
    String name,
    String description,
    MethodEffects effects,
    JsonCodec<Request> requestCodec,
    JsonCodec<Response> responseCodec,
    Set<String> fields,
    List<String> identityFields,
    Handler<Request, Response> handler,
    McpAnnotations mcpAnnotations) {

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
    Objects.requireNonNull(mcpAnnotations, "mcpAnnotations");
  }

  public Object invoke(Object params) throws Exception {
    return invokeDecoded(decodeRequest(params));
  }

  public Request decodeRequest(Object params) {
    return requestCodec.decode(params, "");
  }

  public Object invokeDecoded(Request request) throws Exception {
    FieldProjection.validate(request, fields, identityFields);
    Response response = handler.handle(request);
    Object encoded = responseCodec.encode(response);
    return FieldProjection.apply(encoded, request, fields, identityFields);
  }

  @FunctionalInterface
  public interface Handler<Request, Response> {
    Response handle(Request request) throws Exception;
  }

  /**
   * Defines runtime effects and concurrency constraints for a method.
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

  /**
   * Metadata annotations for Model Context Protocol discovery.
   *
   * @param title human-readable tool title
   * @param readOnlyHint hint indicating operation is read-only
   * @param destructiveHint hint indicating operation is destructive
   * @param idempotentHint hint indicating operation is idempotent
   */
  public record McpAnnotations(
      String title, boolean readOnlyHint, boolean destructiveHint, boolean idempotentHint) {
    public static McpAnnotations forMethod(String name, MethodEffects effects) {
      return new McpAnnotations(
          name, effects.readOnly(), effects.destructive(), effects.idempotent());
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
