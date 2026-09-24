package app.byteland.ghidra.api;

import app.byteland.ghidra.api.ApiMethod.MethodEffects;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.FunctionSignature;
import app.byteland.ghidra.service.function.VariableStorageReference;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Central registry that defines and dispatches all 53 public API methods.
 */
public final class ApiRegistry {
  public static final String INTERFACE_VERSION = "0.2.0";
  public static final int DEFAULT_LIMIT = 100;
  public static final int MAX_LIMIT = app.byteland.ghidra.service.Page.MAX_LIMIT;
  public static final int MAX_BATCH_ITEMS = BatchMethod.MAX_ITEMS;

  static final int NOT_FOUND_STATUS = 404;
  static final String ANALYSIS_START_METHOD = "analysis.start";
  static final String PATCH_DATA_TYPE_TARGET = "/patch/data_type";

  private final BridgeServices bridgeServices;
  private final String sessionId;
  private final Supplier<Map<String, Object>> sessionSupplier;
  private final Runnable shutdownAction;
  private final Map<String, ApiMethod<Map<String, Object>, Object>> methodsByName =
      new LinkedHashMap<>();
  private final ApiCatalog catalogSnapshot;
  private BatchMethod batchMethod;

  public ApiRegistry(
      BridgeServices services,
      String sessionId,
      Supplier<Map<String, Object>> sessionSupplier,
      Runnable shutdownAction) {
    this.bridgeServices = java.util.Objects.requireNonNull(services, "services");
    this.sessionId = sessionId;
    this.sessionSupplier = sessionSupplier;
    this.shutdownAction = shutdownAction;
    registerAll();
    registerInterface();
    catalogSnapshot = ApiCatalog.from(INTERFACE_VERSION, methodsByName.values());
  }

  /** Builds the method catalog without an open Ghidra program. */
  public static ApiCatalog catalog() {
    return new ApiRegistry(metadataServices(), "schema", Map::of, () -> {}).methodCatalog();
  }

  private static BridgeServices metadataServices() {
    return new BridgeServices(
        inertService(app.byteland.ghidra.service.program.ProgramService.class),
        inertService(app.byteland.ghidra.service.address.AddressService.class),
        inertService(app.byteland.ghidra.service.comment.CommentService.class),
        inertService(app.byteland.ghidra.service.reference.ReferenceService.class),
        inertService(app.byteland.ghidra.service.memory.MemoryService.class),
        inertService(app.byteland.ghidra.service.listing.ListingService.class),
        inertService(app.byteland.ghidra.service.function.FunctionService.class),
        inertService(app.byteland.ghidra.service.globalvariable.GlobalVariableService.class),
        inertService(app.byteland.ghidra.service.analysis.AnalysisService.class),
        inertService(app.byteland.ghidra.service.decompilation.DecompilationService.class),
        inertService(app.byteland.ghidra.service.symbol.SymbolService.class),
        inertService(app.byteland.ghidra.service.datatype.DataTypeService.class),
        inertService(app.byteland.ghidra.service.TransactionRunner.class),
        "metadata");
  }

  @SuppressWarnings({
    ApiVocabulary.UNCHECKED,
    "PMD.UseProperClassLoader",
    "PMD.CompareObjectsWithEquals"
  })
  private static <T> T inertService(Class<T> type) {
    return (T)
        java.lang.reflect.Proxy.newProxyInstance(
            ApiRegistry.class.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> {
              if (method.getDeclaringClass() == Object.class) {
                return switch (method.getName()) {
                  case "toString" -> "metadata-only " + type.getSimpleName();
                  case "hashCode" -> System.identityHashCode(proxy);
                  case "equals" -> proxy == args[0];
                  default -> null;
                };
              }
              throw new UnsupportedOperationException(
                  "metadata-only API catalog cannot invoke " + type.getSimpleName());
            });
  }

  static Map<String, Object> fieldsSchema() {
    return WireSchema.array(WireSchema.nonBlankString(), 1, 256);
  }

  static Map<String, Object> limitSchema() {
    return WireSchema.integer(1, MAX_LIMIT);
  }

  static Map<String, Object> cursorSchema() {
    return WireSchema.nonBlankString();
  }

  static Map<String, Object> addressSelector() {
    return selectorSchema(ApiVocabulary.ADDRESS);
  }

  static Map<String, Object> selectorSchema(String key) {
    return WireSchema.object(Map.of(key, WireSchema.nonBlankString()), key);
  }

  BridgeServices services() {
    return bridgeServices;
  }

  public ApiCatalog methodCatalog() {
    return catalogSnapshot;
  }

  public List<ApiMethod<Map<String, Object>, Object>> methods() {
    return List.copyOf(methodsByName.values());
  }

  public Set<String> methodNames() {
    return Collections.unmodifiableSet(methodsByName.keySet());
  }

  public ApiMethod<Map<String, Object>, Object> method(String name) {
    return methodsByName.get(name);
  }

  public Object dispatch(String name, Map<String, Object> params) throws Exception {
    ApiMethod<Map<String, Object>, Object> method = methodsByName.get(name);
    if (method == null) {
      throw new ApiException(404, "unknown_method", "No such method: " + name, "/method");
    }
    Map<String, Object> decoded = method.decodeRequest(params);
    return invokeDecoded(method, decoded, true);
  }

  Object dispatchWithoutTransaction(String name, Map<String, Object> params) throws Exception {
    ApiMethod<Map<String, Object>, Object> method = methodsByName.get(name);
    if (method == null) {
      throw new ApiException(404, "unknown_operation", "No such operation: " + name, "/operation");
    }
    return invokeDecoded(method, method.decodeRequest(params), false);
  }

  <T> T inTransaction(app.byteland.ghidra.service.TransactionRunner.Operation<T> operation) {
    return bridgeServices.transactionRunner().run(operation);
  }

  private Object invokeDecoded(
      ApiMethod<Map<String, Object>, Object> method,
      Map<String, Object> decoded,
      boolean ownTransaction)
      throws Exception {
    if (!allowedDuringAnalysis(method, decoded) && analysisRunning()) {
      if (ANALYSIS_START_METHOD.equals(method.name())) {
        throw new ApiException(
            409, "analysis_already_running", "analysis is already running", "/method");
      }
      throw new ApiException(
          409,
          "analysis_in_progress",
          "writes are unavailable while analysis is running",
          "/method");
    }
    if (method.effects().requiresTransaction() && ownTransaction) {
      return bridgeServices.transactionRunner().run(() -> method.invokeDecoded(decoded));
    }
    return method.invokeDecoded(decoded);
  }

  private void registerInterface() {
    register(
        "interface.get",
        MethodEffects.metadata(),
        null,
        ApiSchemaCatalog.input(Map.of()),
        interfaceSchema(methodsByName.size() + 1),
        Set.of(),
        List.of(),
        request -> interfaceDescription());
    ApiMethod<Map<String, Object>, Object> interfaceMethod = methodsByName.remove("interface.get");
    Map<String, ApiMethod<Map<String, Object>, Object>> reordered = new LinkedHashMap<>();
    reordered.put("interface.get", interfaceMethod);
    reordered.putAll(methodsByName);
    methodsByName.clear();
    methodsByName.putAll(reordered);
  }

  private void registerAll() {
    List<ApiMethodProvider> providers =
        List.of(
            new SessionMethods(this, sessionSupplier, shutdownAction),
            new ProgramMethods(this),
            new AddressMethods(this),
            new MemoryMethods(this),
            new CodeUnitMethods(this),
            new GlobalVariableMethods(this),
            new InstructionMethods(this),
            new FunctionMethods(this),
            new AnalysisMethods(this),
            new DecompilationMethods(this),
            new SymbolMethods(this),
            new ReferenceMethods(this),
            new CommentMethods(this),
            new DataTypeMethods(this));
    for (ApiMethodProvider provider : providers) {
      provider.register();
    }
    registerBatch();
  }

  record PageRequest(int limit, String cursor, String queryFingerprint) {}

  @FunctionalInterface
  interface PagedHandler {
    Object handle(Map<String, Object> request, PageRequest page) throws Exception;
  }

  void read(
      String name,
      Map<String, Object> input,
      Set<String> fields,
      List<String> identityFields,
      ApiMethod.Handler<Map<String, Object>, Object> handler) {
    read(name, null, input, fields, identityFields, handler);
  }

  void read(
      String name,
      String description,
      Map<String, Object> input,
      Set<String> fields,
      List<String> identityFields,
      ApiMethod.Handler<Map<String, Object>, Object> handler) {
    register(
        name,
        MethodEffects.readOnlyMethod(),
        description,
        input,
        ApiSchemaCatalog.resourceSchema(fields, identityFields),
        fields,
        identityFields,
        request -> WireValues.restrict(WireValues.resource(handler.handle(request)), fields));
  }

  private static Map<String, Object> interfaceSchema(int methodCount) {
    Map<String, Object> descriptor =
        WireSchema.object(
            ApiSchemaCatalog.props(
                ApiVocabulary.NAME,
                WireSchema.nonBlankString(),
                "description",
                WireSchema.nonBlankString(),
                "input_schema",
                WireSchema.openObject(),
                "output_schema",
                WireSchema.openObject(),
                "effects",
                WireSchema.openObject()),
            ApiVocabulary.NAME,
            "description",
            "input_schema",
            "output_schema",
            "effects");
    return WireSchema.object(
        ApiSchemaCatalog.props(
            "interface_version", WireSchema.nonBlankString(),
            "methods", WireSchema.array(descriptor, methodCount, methodCount)),
        "interface_version",
        "methods");
  }

  private Map<String, Object> interfaceDescription() {
    return catalogSnapshot.interfaceDescription();
  }

  void readWith(
      String name,
      Map<String, Object> input,
      Map<String, Object> output,
      Set<String> fields,
      List<String> identityFields,
      ApiMethod.Handler<Map<String, Object>, Object> handler) {
    register(
        name, MethodEffects.readOnlyMethod(), null, input, output, fields, identityFields, handler);
  }

  void list(
      String name,
      Map<String, Object> input,
      Set<String> fields,
      List<String> identityFields,
      PagedHandler handler) {
    list(name, null, input, fields, identityFields, handler);
  }

  void list(
      String name,
      String description,
      Map<String, Object> input,
      Set<String> fields,
      List<String> identityFields,
      PagedHandler handler) {
    register(
        name,
        MethodEffects.readOnlyMethod(),
        description,
        input,
        ApiSchemaCatalog.listSchema(fields, identityFields),
        fields,
        identityFields,
        request -> {
          String resource = name.substring(0, name.indexOf('.'));
          PageRequest page = decodePage(request, resource);
          return canonicalList(
              resource, request, handler.handle(request, page), page, fields, identityFields);
        });
  }

  void scanList(
      String name,
      Map<String, Object> input,
      Set<String> fields,
      List<String> identityFields,
      PagedHandler handler) {
    scanList(name, scanDescription(name), input, fields, identityFields, handler);
  }

  private static String scanDescription(String name) {
    return "List "
        + name.substring(0, name.indexOf('.')).replace('_', ' ')
        + " in address order. Set a range or time limit if necessary."
        + " Use next_cursor to get the next page.";
  }

  void scanList(
      String name,
      String description,
      Map<String, Object> input,
      Set<String> fields,
      List<String> identityFields,
      PagedHandler handler) {
    register(
        name,
        MethodEffects.readOnlyMethod(),
        description,
        input,
        ApiSchemaCatalog.scanListSchema(fields, identityFields),
        fields,
        identityFields,
        request -> {
          String resource = name.substring(0, name.indexOf('.'));
          PageRequest page = decodePage(request, resource);
          return canonicalList(
              resource, request, handler.handle(request, page), page, fields, identityFields);
        });
  }

  void writeResult(
      String name,
      MethodEffects effects,
      Map<String, Object> input,
      Map<String, Object> output,
      ApiMethod.Handler<Map<String, Object>, Object> handler) {
    writeResult(name, effects, null, input, output, handler);
  }

  void writeResult(
      String name,
      MethodEffects effects,
      String description,
      Map<String, Object> input,
      Map<String, Object> output,
      ApiMethod.Handler<Map<String, Object>, Object> handler) {
    register(
        name,
        effects,
        description,
        input,
        output,
        Set.of(),
        List.of(),
        request -> WireValues.resource(handler.handle(request)));
  }

  void writeResource(
      String name,
      MethodEffects effects,
      Map<String, Object> input,
      Set<String> fields,
      List<String> identityFields,
      ApiMethod.Handler<Map<String, Object>, Object> handler) {
    writeResource(name, effects, null, input, fields, identityFields, handler);
  }

  void writeResource(
      String name,
      MethodEffects effects,
      String description,
      Map<String, Object> input,
      Set<String> fields,
      List<String> identityFields,
      ApiMethod.Handler<Map<String, Object>, Object> handler) {
    register(
        name,
        effects,
        description,
        input,
        ApiSchemaCatalog.resourceSchema(fields, identityFields),
        fields,
        identityFields,
        request -> WireValues.restrict(WireValues.resource(handler.handle(request)), fields));
  }

  void writeListResult(
      String name,
      MethodEffects effects,
      String description,
      Map<String, Object> input,
      Set<String> fields,
      List<String> identityFields,
      ApiMethod.Handler<Map<String, Object>, Object> handler) {
    register(
        name,
        effects,
        description,
        input,
        WireSchema.withDefinitions(
            WireSchema.object(
                Map.of(
                    ApiVocabulary.ITEMS,
                    WireSchema.array(
                        ApiSchemaCatalog.resourceSchema(fields, identityFields),
                        0,
                        Integer.MAX_VALUE)),
                ApiVocabulary.ITEMS)),
        fields,
        identityFields,
        request -> {
          Map<String, Object> normalizedList = WireValues.list(handler.handle(request), MAX_LIMIT);
          return Map.of(
              ApiVocabulary.ITEMS, restrictAndSortItems(normalizedList, fields, identityFields));
        });
  }

  private void registerBatch() {
    batchMethod =
        new BatchMethod(
            methodsByName,
            new BatchMethod.BatchRuntime() {
              @Override
              public Object invokeDecoded(
                  ApiMethod<Map<String, Object>, Object> method,
                  Map<String, Object> request,
                  boolean ownTransaction)
                  throws Exception {
                return ApiRegistry.this.invokeDecoded(method, request, ownTransaction);
              }

              @Override
              public <T> T inTransaction(
                  app.byteland.ghidra.service.TransactionRunner.Operation<T> operation) {
                return ApiRegistry.this.inTransaction(operation);
              }
            });
    BatchMethod.Registration registration = batchMethod.registration();
    registerWithCodec(
        BatchMethod.NAME,
        registration.effects(),
        "Check and run a batch in order. Use per_item to keep item errors."
            + " Use all_or_none to roll back the batch after an error.",
        registration.requestCodec(),
        registration.responseSchema(),
        Set.of(),
        List.of(),
        registration.handler());
  }

  private void register(
      String name,
      MethodEffects effects,
      String description,
      Map<String, Object> input,
      Map<String, Object> output,
      Set<String> fields,
      List<String> identityFields,
      ApiMethod.Handler<Map<String, Object>, Object> handler) {
    Map<String, Object> selectableInput = withSelectableFields(input, fields);
    Map<String, Object> publishedInput = StrictObjectCodec.canonicalSchema(selectableInput);
    registerWithCodec(
        name,
        effects,
        description,
        new StrictObjectCodec(publishedInput, input),
        output,
        fields,
        identityFields,
        handler);
  }

  @SuppressWarnings(ApiVocabulary.UNCHECKED)
  private static Map<String, Object> withSelectableFields(
      Map<String, Object> input, Set<String> selectableFields) {
    if (selectableFields.isEmpty()) return input;
    Object rawProperties = input.get("properties");
    if (!(rawProperties instanceof Map<?, ?> properties)
        || !properties.containsKey(ApiVocabulary.FIELDS)) {
      return input;
    }
    Map<String, Object> fieldsSchema =
        new LinkedHashMap<>((Map<String, Object>) properties.get(ApiVocabulary.FIELDS));
    List<String> orderedFields = selectableFields.stream().sorted().toList();
    fieldsSchema.put(
        ApiVocabulary.ITEMS, WireSchema.stringEnum(orderedFields.toArray(String[]::new)));
    fieldsSchema.put("uniqueItems", true);
    Map<String, Object> publishedProperties = new LinkedHashMap<>((Map<String, Object>) properties);
    publishedProperties.put(ApiVocabulary.FIELDS, fieldsSchema);
    Map<String, Object> publishedInput = new LinkedHashMap<>(input);
    publishedInput.put("properties", publishedProperties);
    return Collections.unmodifiableMap(publishedInput);
  }

  private void registerWithCodec(
      String name,
      MethodEffects effects,
      String description,
      JsonCodec<Map<String, Object>> requestCodec,
      Map<String, Object> output,
      Set<String> fields,
      List<String> identityFields,
      ApiMethod.Handler<Map<String, Object>, Object> handler) {

    ApiMethod<Map<String, Object>, Object> method =
        new ApiMethod<>(
            name,
            description != null ? description : defaultDescription(name),
            effects,
            requestCodec,
            new JsonValueCodec(output),
            fields,
            identityFields,
            handler,
            ApiMethod.McpAnnotations.forMethod(name, effects));
    if (methodsByName.putIfAbsent(name, method) != null) {
      throw new IllegalStateException("duplicate API method: " + name);
    }
  }

  private boolean allowedDuringAnalysis(
      ApiMethod<Map<String, Object>, Object> method, Map<String, Object> request) {
    if (method.effects().allowedDuringAnalysis()) return true;
    return BatchMethod.NAME.equals(method.name())
        && batchMethod != null
        && batchMethod.allowedDuringAnalysis(request);
  }

  private static String defaultDescription(String name) {
    switch (name) {
      case "interface.get" -> {
        return "Describe all API methods, their schemas, and their effects.";
      }
      case "session.get" -> {
        return "Get the bridge session id, status, and program name.";
      }
      case "memory.read" -> {
        return "Read up to 65536 bytes at an address as hex or base64."
            + " The default length is 256 and the default encoding is hex.";
      }
      case "memory.write" -> {
        return "Write hex or base64 bytes at an address.";
      }
      case "address.resolve" -> {
        return "Resolve an address and report its memory block, containing function,"
            + " and primary symbol.";
      }
      case "function_call.list" -> {
        return "List the callers or callees of a function. The default direction is callees.";
      }
      default -> {
        // Use the generic description below.
      }
    }
    int separator = name.indexOf('.');
    String resource = name.substring(0, separator).replace('_', ' ');
    String operation = name.substring(separator + 1);
    return switch (operation) {
      case "get" -> "Get " + resource + " data from the active program.";
      case "list" -> "List " + resource + " data in the active program.";
      case "create" -> "Create " + resource + " data in the active program.";
      case ApiVocabulary.PATCH -> "Change " + resource + " data in the active program.";
      case "upsert" -> "Create or replace " + resource + " data in the active program.";
      case "delete" -> "Delete " + resource + " data from the active program.";
      case "save" -> "Save the active program to its project file.";
      case ApiVocabulary.START -> "Start automatic analysis of the active program.";
      case "shutdown" -> "Stop the current Ghidra Bridge session.";
      case "execute" -> "Run a batch of methods in order.";
      default -> "Run the " + name + " method.";
    };
  }

  private Map<String, Object> canonicalList(
      String resource,
      Map<String, Object> request,
      Object raw,
      PageRequest page,
      Set<String> fields,
      List<String> identityFields) {
    Map<String, Object> result = WireValues.list(raw, page.limit());
    List<Map<String, Object>> normalizedItems =
        restrictAndSortItems(result, fields, identityFields);
    Optional<Object> next = Optional.ofNullable(result.get("next_cursor"));
    result.put(ApiVocabulary.ITEMS, normalizedItems);
    result.remove("next_cursor");
    if (next.isPresent()) {
      String fingerprint =
          page.queryFingerprint() != null
              ? page.queryFingerprint()
              : CursorTokens.queryFingerprint(request);
      result.put(
          "next_cursor",
          CursorTokens.encode(
              resource, sessionId, fingerprint, String.valueOf(next.orElseThrow())));
    }
    return result;
  }

  @SuppressWarnings(ApiVocabulary.UNCHECKED)
  private static List<Map<String, Object>> restrictAndSortItems(
      Map<String, Object> normalizedList, Set<String> fields, List<String> identityFields) {
    List<Map<String, Object>> items =
        (List<Map<String, Object>>) (List<?>) normalizedList.get(ApiVocabulary.ITEMS);
    return items.stream()
        .map(item -> WireValues.restrict(item, fields))
        .sorted((left, right) -> compareIdentity(left, right, identityFields))
        .toList();
  }

  private static int compareIdentity(
      Map<String, Object> left, Map<String, Object> right, List<String> identityFields) {
    for (String field : identityFields) {
      Object leftValue = left.get(field);
      Object rightValue = right.get(field);
      int compared;
      if (sameReference(leftValue, rightValue)) {
        compared = 0;
      } else if (leftValue == null) {
        compared = -1;
      } else if (rightValue == null) {
        compared = 1;
      } else if (leftValue instanceof Number leftNumber
          && rightValue instanceof Number rightNumber) {
        compared = Long.compare(leftNumber.longValue(), rightNumber.longValue());
      } else {
        compared = String.valueOf(leftValue).compareTo(String.valueOf(rightValue));
      }
      if (compared != 0) return compared;
    }
    return 0;
  }

  @SuppressWarnings("PMD.CompareObjectsWithEquals")
  private static boolean sameReference(Object left, Object right) {
    return left == right;
  }

  private boolean analysisRunning() {
    return bridgeServices.analysisService().getStatus().status()
        == app.byteland.ghidra.service.analysis.AnalysisResource.Status.RUNNING;
  }

  private PageRequest decodePage(Map<String, Object> request, String resource) {
    String token = optionalText(request, "cursor");
    if (token == null) {
      return new PageRequest(pageLimit(request), null, null);
    }
    String fingerprint = CursorTokens.queryFingerprint(request);
    String cursor = CursorTokens.decode(token, resource, sessionId, fingerprint, "/page/cursor");
    return new PageRequest(pageLimit(request), cursor, fingerprint);
  }

  static AddressScanOptions addressScan(
      Map<String, Object> request, String legacyStartField, String legacyEndField) {
    Map<String, Object> range =
        request.get("range") instanceof Map<?, ?> ? object(request, "range") : Map.of();
    Map<String, Object> legacy = filter(request);
    String rangeStart = optionalText(range, ApiVocabulary.START);
    String rangeEnd = optionalText(range, ApiVocabulary.END);
    String legacyStart = legacyStartField == null ? null : optionalText(legacy, legacyStartField);
    String legacyEnd = legacyEndField == null ? null : optionalText(legacy, legacyEndField);
    rejectRangeConflict(rangeStart, legacyStart, ApiVocabulary.START, legacyStartField);
    rejectRangeConflict(rangeEnd, legacyEnd, ApiVocabulary.END, legacyEndField);
    return new AddressScanOptions(
        rangeStart == null ? legacyStart : rangeStart,
        rangeEnd == null ? legacyEnd : rangeEnd,
        integer(request, "timeout_ms", AddressScanOptions.DEFAULT_TIMEOUT_MS));
  }

  private static void rejectRangeConflict(
      String rangeValue, String legacyValue, String rangeField, String legacyField) {
    if (rangeValue != null && legacyValue != null && !rangeValue.equals(legacyValue)) {
      throw ApiException.badRequest(
          "conflicting_range",
          "range." + rangeField + " conflicts with filter." + legacyField,
          "/scan/range/" + rangeField);
    }
  }

  static void validateByteLength(Map<String, Object> bytes, String target) {
    String encoding = text(bytes, ApiVocabulary.ENCODING);
    String data = text(bytes, ApiVocabulary.DATA);
    int expected = integer(bytes, ApiVocabulary.LENGTH, -1);
    int actual;
    try {
      actual =
          ApiVocabulary.HEX.equals(encoding)
              ? java.util.HexFormat.of().parseHex(data).length
              : java.util.Base64.getDecoder().decode(data).length;
    } catch (IllegalArgumentException invalid) {
      ApiException translated =
          ApiException.badRequest(
              "invalid_byte_data", "byte sequence data is not valid " + encoding, target + "/data");
      translated.initCause(invalid);
      throw translated;
    }
    if (actual != expected) {
      throw ApiException.badRequest(
          "length_mismatch", "byte sequence length does not match data", target + "/length");
    }
  }

  @SuppressWarnings(ApiVocabulary.UNCHECKED)
  static Map<String, Object> object(Map<String, Object> parent, String key) {
    return (Map<String, Object>) parent.getOrDefault(key, Map.of());
  }

  static Map<String, Object> selector(Map<String, Object> request) {
    return object(request, ApiVocabulary.SELECTOR);
  }

  static Map<String, Object> filter(Map<String, Object> request) {
    return object(request, "filter");
  }

  static Map<String, Object> patch(Map<String, Object> request) {
    return object(request, ApiVocabulary.PATCH);
  }

  static Map<String, Object> resource(Map<String, Object> request) {
    return object(request, ApiVocabulary.RESOURCE);
  }

  @SuppressWarnings(ApiVocabulary.UNCHECKED)
  static Map<String, Object> objectAt(Object value, String target) {
    if (!(value instanceof Map<?, ?> map)) {
      throw ApiException.badRequest("invalid_type", target + " must be an object", target);
    }
    return (Map<String, Object>) map;
  }

  static String text(Map<String, Object> value, String key) {
    return (String) value.get(key);
  }

  static String optionalText(Map<String, Object> value, String key) {
    return optionalText(value, key, null);
  }

  static String optionalText(Map<String, Object> value, String key, String fallback) {
    Object raw = value.get(key);
    return raw instanceof String text ? text : fallback;
  }

  static String nullableText(Map<String, Object> value, String key) {
    return value.containsKey(key) ? (String) value.get(key) : null;
  }

  static int integer(Map<String, Object> value, String key, int fallback) {
    Object raw = value.get(key);
    return raw instanceof Number number ? number.intValue() : fallback;
  }

  static Integer optionalInteger(Map<String, Object> value, String key) {
    Object raw = value.get(key);
    return raw instanceof Number number ? number.intValue() : null;
  }

  static Optional<Boolean> bool(Map<String, Object> value, String key) {
    Object raw = value.get(key);
    return raw instanceof Boolean booleanValue ? Optional.of(booleanValue) : Optional.empty();
  }

  static app.byteland.ghidra.service.ByteSequence.Encoding byteEncoding(String value) {
    return "base64".equals(value)
        ? app.byteland.ghidra.service.ByteSequence.Encoding.BASE64
        : app.byteland.ghidra.service.ByteSequence.Encoding.HEX;
  }

  static app.byteland.ghidra.service.comment.CommentResource.Type commentType(String value) {
    return value == null
        ? null
        : app.byteland.ghidra.service.comment.CommentResource.Type.valueOf(
            value.toUpperCase(java.util.Locale.ROOT));
  }

  private static int pageLimit(Map<String, Object> request) {
    return integer(request, "limit", DEFAULT_LIMIT);
  }

  static long longId(Map<String, Object> value, String key) {
    try {
      return Long.parseLong(text(value, key));
    } catch (NumberFormatException error) {
      ApiException translated =
          ApiException.badRequest(
              "invalid_id", "/selector/" + key + " must be a decimal id", "/selector/" + key);
      translated.initCause(error);
      throw translated;
    }
  }

  static app.byteland.ghidra.service.listing.FlowOverrideScope flowScope(
      Map<String, Object> selector) {
    return switch (text(selector, ApiVocabulary.KIND)) {
      case ApiVocabulary.ADDRESS ->
          new app.byteland.ghidra.service.listing.FlowOverrideScope.AddressScope(
              text(selector, ApiVocabulary.ADDRESS));
      case ApiVocabulary.FUNCTION ->
          new app.byteland.ghidra.service.listing.FlowOverrideScope.FunctionScope(
              text(selector, ApiVocabulary.ENTRY));
      case "range" ->
          new app.byteland.ghidra.service.listing.FlowOverrideScope.RangeScope(
              text(selector, ApiVocabulary.START), text(selector, ApiVocabulary.END));
      default -> throw new AssertionError(selector.get(ApiVocabulary.KIND));
    };
  }

  static List<app.byteland.ghidra.service.listing.FlowOverrideValue> flowOverrides(
      Object raw, List<String> defaults) {
    List<?> values = raw instanceof List<?> list ? list : defaults;
    return values.stream()
        .map(String::valueOf)
        .map(value -> value.toUpperCase(java.util.Locale.ROOT))
        .map(app.byteland.ghidra.service.listing.FlowOverrideValue::valueOf)
        .toList();
  }

  @SuppressWarnings("PMD.ReturnEmptyCollectionRatherThanNull")
  static List<String> stringList(Object value) {
    if (!(value instanceof List<?> list)) return null;
    return list.stream().map(String.class::cast).toList();
  }

  static Set<String> requestedIncludes(Map<String, Object> request) {
    Object raw = request.get(ApiVocabulary.FIELDS);
    if (!(raw instanceof List<?> fields))
      return Set.of(ApiVocabulary.PARAMETERS, ApiVocabulary.LOCALS);
    Set<String> includes = new LinkedHashSet<>();
    for (Object field : fields) {
      String path = String.valueOf(field);
      if (path.startsWith(ApiVocabulary.PARAMETERS)) includes.add(ApiVocabulary.PARAMETERS);
      if (path.startsWith("local_variables")) includes.add(ApiVocabulary.LOCALS);
      if (path.startsWith("calls")) includes.add("calls");
    }
    return includes;
  }

  static VariableStorageReference storage(Object raw) {
    if (!(raw instanceof Map<?, ?> storage)) return null;
    return "register".equals(storage.get(ApiVocabulary.KIND))
        ? new VariableStorageReference.Register(String.valueOf(storage.get("register")))
        : new VariableStorageReference.Serialization(String.valueOf(storage.get("serialization")));
  }

  static DataTypeReference dataType(Object raw, String target) {
    if (raw == null) return null;
    Map<String, Object> value = objectAt(raw, target);
    String kind = text(value, ApiVocabulary.KIND);
    return switch (kind) {
      case "named" -> DataTypeReference.named(text(value, ApiVocabulary.NAME));
      case "pointer" ->
          DataTypeReference.pointerTo(dataType(value.get("target"), target + "/target"));
      case "array" ->
          DataTypeReference.arrayOf(
              dataType(value.get("element"), target + "/element"), integer(value, "count", -1));
      case "untyped_pointer" -> DataTypeReference.untypedPointer();
      default ->
          throw ApiException.badRequest(
              "invalid_data_type_reference", "unsupported data type kind", target + "/kind");
    };
  }

  static FunctionSignature functionSignature(Object raw, String target) {
    Map<String, Object> value = objectAt(raw, target);
    Object rawParameters = value.get(ApiVocabulary.PARAMETERS);
    if (!(rawParameters instanceof List<?> parameters)) {
      throw ApiException.badRequest(
          "invalid_function_signature", "parameters must be an array", target + "/parameters");
    }
    List<FunctionSignature.Parameter> typedParameters = new ArrayList<>();
    for (int index = 0; index < parameters.size(); index++) {
      Map<String, Object> parameter =
          objectAt(parameters.get(index), target + "/parameters/" + index);
      typedParameters.add(
          new FunctionSignature.Parameter(
              optionalText(parameter, ApiVocabulary.NAME),
              dataType(
                  parameter.get(ApiVocabulary.DATA_TYPE),
                  target + "/parameters/" + index + "/data_type")));
    }
    return new FunctionSignature(
        dataType(value.get("return_type"), target + "/return_type"),
        typedParameters,
        text(value, "calling_convention"),
        Boolean.TRUE.equals(bool(value, "has_var_args").orElse(null)),
        Boolean.TRUE.equals(bool(value, "has_no_return").orElse(null)));
  }

  static String dataTypePath(Map<String, Object> resource) {
    String category = optionalText(resource, ApiVocabulary.CATEGORY_PATH, "/");
    return (category.endsWith("/") ? category : category + "/")
        + text(resource, ApiVocabulary.NAME);
  }
}
