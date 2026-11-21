package app.byteland.ghidra.adapter.ghidra;

import app.byteland.ghidra.service.datatype.DataTypeReference;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.program.model.data.ArchiveType;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.VoidDataType;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class GhidraDataTypeReferences {
  private static final int UNAMBIGUOUS_MATCH_COUNT = 1;
  private static final int MAX_NESTING_DEPTH = 32;
  private static final String CATEGORY_ALIAS_PREFIX = "__ghidra_cat_type_";
  private static final Pattern CATEGORY_PATH_TOKEN_PATTERN =
      Pattern.compile("(?<![A-Za-z0-9_$/])(/[A-Za-z0-9_./+-]+)");
  private static final Set<String> VOID_EXPRESSIONS =
      Set.of(
          "void",
          "const void",
          "volatile void",
          "const volatile void",
          "volatile const void",
          "void const",
          "void volatile");

  private GhidraDataTypeReferences() {}

  public static DataType resolve(
      DataTypeManager programDataTypeManager, DataTypeReference reference) {
    if (programDataTypeManager == null) {
      throw new IllegalArgumentException("program data type manager is required");
    }
    if (reference == null) {
      throw new IllegalArgumentException("data type reference is required");
    }
    return resolve(programDataTypeManager, reference, 0);
  }

  public static DataTypeReference toReference(DataType dataType) {
    if (dataType == null) throw new IllegalArgumentException("data type is required");
    return toReference(dataType, 0, new IdentityHashMap<>());
  }

  private static DataType resolve(
      DataTypeManager programDataTypeManager, DataTypeReference reference, int depth) {
    return switch (reference) {
      case DataTypeReference.Named named -> resolveNamed(programDataTypeManager, named.name());
      case DataTypeReference.UntypedPointer ignored ->
          resolveUntypedPointer(programDataTypeManager);
      case DataTypeReference.Pointer pointer -> {
        requireCanDescend(depth);
        DataType referencedType = resolve(programDataTypeManager, pointer.target(), depth + 1);
        Pointer resolved = programDataTypeManager.getPointer(referencedType);
        requirePointerIdentityCanBePreserved(programDataTypeManager, resolved);
        yield resolved;
      }
      case DataTypeReference.Array array -> {
        requireCanDescend(depth);
        DataType elementType = resolve(programDataTypeManager, array.element(), depth + 1);
        yield buildArrayDataType(elementType, array.count(), programDataTypeManager);
      }
      case DataTypeReference.CExpression cExpression ->
          resolveCExpression(programDataTypeManager, cExpression.expression(), depth);
    };
  }

  public static DataType materializeParsedDataType(
      DataTypeManager programDataTypeManager, DataType parsedType) {
    return materializeParsedDataType(programDataTypeManager, parsedType, Map.of(), 0);
  }

  private static DataType resolveCExpression(
      DataTypeManager programDataTypeManager, String rawExpression, int depth) {
    requireCanDescend(depth);
    String trimmed = rawExpression == null ? "" : rawExpression.trim();
    if (trimmed.isEmpty()) {
      throw new IllegalArgumentException("C data type expression must not be blank");
    }
    if (trimmed.getBytes(StandardCharsets.UTF_8).length
        > GhidraCParserSupport.MAX_TYPE_EXPRESSION_BYTES) {
      throw new IllegalArgumentException(
          "C data type expression exceeds maximum size of "
              + GhidraCParserSupport.MAX_TYPE_EXPRESSION_BYTES
              + " UTF-8 bytes");
    }
    if (trimmed.indexOf(';') >= 0 || trimmed.indexOf('{') >= 0 || trimmed.indexOf('}') >= 0) {
      throw new IllegalArgumentException(
          "C data type expression must not contain statements or composite bodies: " + trimmed);
    }
    if ("pointer".equals(trimmed)) {
      return resolveUntypedPointer(programDataTypeManager);
    }
    String collapsed = trimmed.replaceAll("\\s+", " ");
    if (VOID_EXPRESSIONS.contains(collapsed)) {
      return VoidDataType.dataType.clone(programDataTypeManager);
    }
    if (trimmed.startsWith("/") && !containsCDeclaratorOrWhitespace(trimmed)) {
      return resolveNamed(programDataTypeManager, trimmed);
    }

    try (StandAloneDataTypeManager scratch =
            GhidraCParserSupport.createScratchManager(programDataTypeManager);
        StandAloneDataTypeManager stdintFallback =
            GhidraCParserSupport.createStdintFallbackManager(programDataTypeManager)) {
      Map<String, DataType> categoryAliases = new HashMap<>();
      String rewritten =
          rewriteCategoryPaths(programDataTypeManager, scratch, trimmed, categoryAliases);
      String prototype = "void __ghidra_bridge_type(" + rewritten + ")";
      FunctionDefinitionDataType parsed;
      try {
        parsed =
            GhidraCParserSupport.parseSignatureWithCParserUtils(
                scratch,
                GhidraCParserSupport.lookupManagers(programDataTypeManager, stdintFallback),
                prototype);
      } catch (ParseException error) {
        throw new IllegalArgumentException(
            "invalid C data type '"
                + trimmed
                + "': "
                + GhidraCParserSupport.cleanParseMessage(error, null),
            error);
      }
      if (parsed == null || parsed.hasVarArgs() || parsed.getArguments().length != 1) {
        throw new IllegalArgumentException("invalid C data type expression: " + trimmed);
      }
      ParameterDefinition parameter = parsed.getArguments()[0];
      if (parameter.getName() != null && !parameter.getName().isBlank()) {
        throw new IllegalArgumentException(
            "C data type expression must not declare a variable name: " + trimmed);
      }
      DataType parsedType = parameter.getDataType();
      if (parsedType == null) {
        throw new IllegalArgumentException("invalid C data type expression: " + trimmed);
      }
      return materializeParsedDataType(
          programDataTypeManager, parsedType, categoryAliases, depth);
    }
  }

  private static boolean containsCDeclaratorOrWhitespace(String text) {
    for (int index = 0; index < text.length(); index++) {
      char ch = text.charAt(index);
      if (Character.isWhitespace(ch)
          || ch == '*'
          || ch == '['
          || ch == ']'
          || ch == '('
          || ch == ')') {
        return true;
      }
    }
    return false;
  }

  private static String rewriteCategoryPaths(
      DataTypeManager programDataTypeManager,
      StandAloneDataTypeManager scratch,
      String expression,
      Map<String, DataType> categoryAliases) {
    Matcher matcher = CATEGORY_PATH_TOKEN_PATTERN.matcher(expression);
    if (!matcher.find()) {
      return expression;
    }
    matcher.reset();
    StringBuilder rewritten = new StringBuilder();
    int txId = scratch.startTransaction("Register category aliases");
    boolean committed = false;
    try {
      int aliasIndex = 0;
      while (matcher.find()) {
        String path = matcher.group(1);
        DataType target = resolveNamed(programDataTypeManager, path);
        String alias = CATEGORY_ALIAS_PREFIX + aliasIndex++;
        scratch.addDataType(
            new TypedefDataType(CategoryPath.ROOT, alias, target.clone(scratch), scratch),
            DataTypeConflictHandler.REPLACE_HANDLER);
        categoryAliases.put(alias, target);
        matcher.appendReplacement(rewritten, Matcher.quoteReplacement(alias));
      }
      matcher.appendTail(rewritten);
      committed = true;
    } finally {
      scratch.endTransaction(txId, committed);
    }
    return rewritten.toString();
  }

  private static DataType materializeParsedDataType(
      DataTypeManager programDataTypeManager,
      DataType parsedType,
      Map<String, DataType> categoryAliases,
      int depth) {
    if (parsedType == null) {
      throw new IllegalArgumentException("data type is required");
    }
    if (parsedType instanceof TypeDef typeDef
        && categoryAliases.containsKey(typeDef.getName())) {
      return categoryAliases.get(typeDef.getName());
    }
    if (parsedType instanceof Pointer pointer) {
      requireCanDescend(depth);
      DataType pointee = pointer.getDataType();
      if (pointee == null) {
        return resolveUntypedPointer(programDataTypeManager);
      }
      DataType materializedPointee =
          materializeParsedDataType(programDataTypeManager, pointee, categoryAliases, depth + 1);
      Pointer resolved = programDataTypeManager.getPointer(materializedPointee);
      requirePointerIdentityCanBePreserved(programDataTypeManager, resolved);
      return resolved;
    }
    if (parsedType instanceof Array array) {
      requireCanDescend(depth);
      DataType element =
          materializeParsedDataType(
              programDataTypeManager, array.getDataType(), categoryAliases, depth + 1);
      return buildArrayDataType(element, array.getNumElements(), programDataTypeManager);
    }
    DataType existing = findByPath(programDataTypeManager, absolutePath(parsedType));
    if (existing != null && existing.getClass().equals(parsedType.getClass())) {
      return existing;
    }
    List<DataType> namedMatches = findNamed(programDataTypeManager, parsedType.getName());
    if (namedMatches.size() == UNAMBIGUOUS_MATCH_COUNT) {
      return namedMatches.getFirst();
    }
    if (parsedType instanceof FunctionDefinition functionDef) {
      requireCanDescend(depth);
      FunctionDefinitionDataType copy =
          new FunctionDefinitionDataType(
              parsedType.getCategoryPath(), parsedType.getName(), programDataTypeManager);
      if (functionDef.getReturnType() != null) {
        copy.setReturnType(
            materializeParsedDataType(
                programDataTypeManager,
                functionDef.getReturnType(),
                categoryAliases,
                depth + 1));
      }
      ParameterDefinition[] originalArgs = functionDef.getArguments();
      ParameterDefinition[] copiedArgs = new ParameterDefinition[originalArgs.length];
      for (int index = 0; index < originalArgs.length; index++) {
        ParameterDefinition arg = originalArgs[index];
        copiedArgs[index] =
            new ghidra.program.model.data.ParameterDefinitionImpl(
                arg.getName(),
                materializeParsedDataType(
                    programDataTypeManager, arg.getDataType(), categoryAliases, depth + 1),
                arg.getComment());
      }
      copy.setArguments(copiedArgs);
      copy.setVarArgs(functionDef.hasVarArgs());
      copy.setNoReturn(functionDef.hasNoReturn());
      return copy;
    }
    if (parsedType instanceof TypeDef typeDef) {
      requireCanDescend(depth);
      DataType materializedBase =
          materializeParsedDataType(
              programDataTypeManager, typeDef.getDataType(), categoryAliases, depth + 1);
      return new TypedefDataType(
          typeDef.getCategoryPath(), typeDef.getName(), materializedBase, programDataTypeManager);
    }
    return parsedType.clone(programDataTypeManager);
  }

  private static DataType buildArrayDataType(
      DataType elementType, int count, DataTypeManager manager) {
    if (isBareFunctionDefinition(elementType)) {
      throw new IllegalArgumentException(
          "array element data_type must use kind=pointer for a function definition");
    }
    if (count <= 0) {
      throw new IllegalArgumentException("array count must be positive: " + count);
    }
    DataType clonedElement = elementType.clone(manager);
    int elementLength = clonedElement.getAlignedLength();
    if (elementLength <= 0) {
      throw new IllegalArgumentException(
          "element type '" + clonedElement.getName() + "' has zero length, cannot form array");
    }
    long byteLength = (long) count * elementLength;
    if (byteLength > Integer.MAX_VALUE) {
      throw new IllegalArgumentException("array byte length exceeds integer range: " + byteLength);
    }
    ArrayDataType array = new ArrayDataType(clonedElement, count, elementLength, manager);
    if (array.getElementLength() != array.getDataType().getAlignedLength()
        || array.getLength() != (int) byteLength) {
      throw new IllegalArgumentException("array geometry is inconsistent");
    }
    requireArrayIdentityCanBePreserved(manager, array);
    return array;
  }

  private static Pointer resolveUntypedPointer(DataTypeManager programDataTypeManager) {
    Pointer pointer = new PointerDataType(programDataTypeManager);
    if (pointer.getDataType() != null) {
      throw new IllegalArgumentException("Ghidra generic pointer unexpectedly has a pointee");
    }
    requireLanguageDependentPointerWidth(pointer);
    if (!sameIdentity(pointer.getDataTypeManager(), programDataTypeManager)) {
      throw new IllegalArgumentException(
          "Ghidra generic pointer is not bound to the target program data type manager");
    }
    requirePointerIdentityCanBePreserved(programDataTypeManager, pointer);
    return pointer;
  }

  public static DataType findByPath(DataTypeManager programDataTypeManager, String path) {
    DataType selected = programDataTypeManager.getDataType(path);
    return selected != null
        ? selected
        : BuiltInDataTypeManager.getDataTypeManager().getDataType(path);
  }

  public static List<DataType> findNamed(DataTypeManager programDataTypeManager, String name) {
    List<DataType> matches = new ArrayList<>();
    programDataTypeManager.findDataTypes(name, matches);
    if (matches.isEmpty()) {
      BuiltInDataTypeManager.getDataTypeManager().findDataTypes(name, matches);
    }
    return matches;
  }

  private static DataType resolveNamed(DataTypeManager programDataTypeManager, String typeName) {
    String normalized = typeName.trim();
    DataType selected;
    if (normalized.startsWith("/")) {
      selected = findByPath(programDataTypeManager, normalized);
      if (selected == null) {
        throw new IllegalArgumentException("unknown data type: " + normalized);
      }
    } else {
      List<DataType> matches = findNamed(programDataTypeManager, normalized);
      if (matches.isEmpty()) {
        throw new IllegalArgumentException("unknown data type: " + normalized);
      }
      if (matches.size() > UNAMBIGUOUS_MATCH_COUNT) {
        throw new IllegalArgumentException(
            "ambiguous data type name: " + normalized + "; use an absolute path");
      }
      selected = matches.getFirst();
    }

    if (selected instanceof Pointer && !(selected instanceof TypeDef)) {
      throw new IllegalArgumentException(
          "named data type must not reference a pointer; use kind=pointer: " + normalized);
    }
    if (selected instanceof Array && !(selected instanceof TypeDef)) {
      throw new IllegalArgumentException(
          "named data type must not reference an array; use kind=array with element and count: "
              + normalized);
    }
    return selected;
  }

  private static DataTypeReference toReference(
      DataType dataType, int depth, Map<DataType, Boolean> active) {
    if (dataType instanceof TypeDef) {
      return DataTypeReference.named(absolutePath(dataType));
    }
    if (dataType instanceof FunctionDefinition) {
      return DataTypeReference.named(absolutePath(dataType));
    }
    requireCanDescendIfWrapper(dataType, depth);
    if (active.put(dataType, Boolean.TRUE) != null) {
      throw new IllegalArgumentException(
          "recursive data type graph cannot be represented: " + dataType.getPathName());
    }
    try {
      if (dataType instanceof Pointer pointer) {
        requireLanguageDependentPointerWidth(pointer);
        DataType referencedType = pointer.getDataType();
        if (referencedType == null) {
          return DataTypeReference.untypedPointer();
        }
        return DataTypeReference.pointerTo(toReference(referencedType, depth + 1, active));
      }
      if (dataType instanceof Array array) {
        validateArrayGeometry(array);
        DataType elementType = array.getDataType();
        if (elementType == null) {
          throw new IllegalArgumentException("array has no element data type");
        }
        return DataTypeReference.arrayOf(
            toReference(elementType, depth + 1, active), array.getNumElements());
      }
      return DataTypeReference.named(absolutePath(dataType));
    } finally {
      active.remove(dataType);
    }
  }

  private static void requireCanDescendIfWrapper(DataType dataType, int depth) {
    boolean recursiveWrapper =
        dataType instanceof Array
            || (dataType instanceof Pointer pointer && pointer.getDataType() != null);
    if (recursiveWrapper && depth >= MAX_NESTING_DEPTH) {
      throw new IllegalArgumentException(
          "data type exceeds the maximum nesting depth of " + MAX_NESTING_DEPTH);
    }
  }

  private static void requireCanDescend(int depth) {
    if (depth >= MAX_NESTING_DEPTH) {
      throw new IllegalArgumentException(
          "data type reference exceeds the maximum nesting depth of " + MAX_NESTING_DEPTH);
    }
  }

  private static void requireLanguageDependentPointerWidth(Pointer pointer) {
    if (!pointer.hasLanguageDependantLength()) {
      throw new IllegalArgumentException(
          "explicit-width pointer cannot be represented; only language-dependent default-width"
              + " pointers are supported");
    }
  }

  private static void validateArrayGeometry(Array array) {
    int count = array.getNumElements();
    if (count <= 0) {
      throw new IllegalArgumentException("array count must be positive: " + count);
    }
    int elementLength = array.getElementLength();
    if (elementLength <= 0) {
      throw new IllegalArgumentException("array element length must be positive: " + elementLength);
    }
    DataType elementType = array.getDataType();
    if (elementType == null) {
      throw new IllegalArgumentException("array has no element data type");
    }
    if (elementLength != elementType.getAlignedLength()) {
      throw new IllegalArgumentException(
          "array element length cannot be represented exactly; canonical aligned element length is "
              + elementType.getAlignedLength()
              + " but array element length is "
              + elementLength);
    }
    long expectedLength = (long) count * elementLength;
    if (expectedLength > Integer.MAX_VALUE) {
      throw new IllegalArgumentException(
          "array byte length exceeds Ghidra's supported integer range: " + expectedLength);
    }
    if (array.getLength() != (int) expectedLength) {
      throw new IllegalArgumentException(
          "array byte length is inconsistent; expected "
              + expectedLength
              + " but was "
              + array.getLength());
    }
  }

  public static boolean isBareFunctionDefinition(DataType dataType) {
    if (dataType == null) {
      throw new IllegalArgumentException("data type is required");
    }
    DataType current = dataType;
    while (current instanceof TypeDef typeDef) {
      current = typeDef.getBaseDataType();
    }
    return current instanceof FunctionDefinition;
  }

  private static void requirePointerIdentityCanBePreserved(
      DataTypeManager programDataTypeManager, Pointer requestedPointer) {
    Category category = programDataTypeManager.getCategory(requestedPointer.getCategoryPath());
    if (category == null) {
      return;
    }
    DataTypeReference requested = toReference(requestedPointer);
    DataType exact = category.getDataType(requestedPointer.getName());
    if (exact instanceof Pointer exactPointer
        && !(exact instanceof TypeDef)
        && exactPointer.isEquivalent(requestedPointer)) {
      requireSamePointerIdentity(requested, exactPointer);
      return;
    }
    for (DataType candidate : relatedDecoratedTypes(category, requestedPointer)) {
      if (sameIdentity(candidate, exact)
          || !(candidate instanceof Pointer existingPointer)
          || candidate instanceof TypeDef) {
        continue;
      }
      if (!existingPointer.isEquivalent(requestedPointer)) {
        continue;
      }
      requireSamePointerIdentity(requested, existingPointer);
    }
  }

  private static void requireArrayIdentityCanBePreserved(
      DataTypeManager manager, Array requestedArray) {
    Category category = manager.getCategory(requestedArray.getCategoryPath());
    if (category == null) {
      return;
    }
    DataTypeReference requested = toReference(requestedArray);
    DataType exact = category.getDataType(requestedArray.getName());
    if (exact instanceof Array exactArray && exactArray.isEquivalent(requestedArray)) {
      requireSameArrayIdentity(requested, exactArray);
      return;
    }
    for (DataType candidate : relatedDecoratedTypes(category, requestedArray)) {
      if (sameIdentity(candidate, exact)
          || !(candidate instanceof Array existingArray)
          || !existingArray.isEquivalent(requestedArray)) {
        continue;
      }
      requireSameArrayIdentity(requested, existingArray);
    }
  }

  private static List<DataType> relatedDecoratedTypes(Category category, DataType requestedType) {
    DataType baseDataType = requestedType;
    while (true) {
      if (baseDataType instanceof Pointer pointer) {
        baseDataType = pointer.getDataType();
      } else if (baseDataType instanceof Array array) {
        baseDataType = array.getDataType();
      } else {
        break;
      }
    }
    if (baseDataType == null
        || (baseDataType.getSourceArchive() != null
            && baseDataType.getSourceArchive().getArchiveType() == ArchiveType.BUILT_IN)) {
      return List.of();
    }

    String baseTypeName = baseDataType.getName();
    String requestedName = requestedType.getName();
    if (!requestedName.startsWith(baseTypeName)) {
      return List.of();
    }
    String decorations = requestedName.substring(baseTypeName.length());
    List<DataType> candidates = new ArrayList<>();
    for (DataType relatedBase : category.getDataTypesByBaseName(baseTypeName)) {
      DataType candidate = category.getDataType(relatedBase.getName() + decorations);
      if (candidate != null) {
        candidates.add(candidate);
      }
    }
    return candidates;
  }

  private static void requireSamePointerIdentity(
      DataTypeReference requested, Pointer existingPointer) {
    DataTypeReference existing = toReference(existingPointer);
    if (!requested.equals(existing)) {
      throw new IllegalArgumentException(
          "pointer data type cannot preserve requested identity; Ghidra would canonicalize "
              + requested
              + " to "
              + existing);
    }
  }

  private static void requireSameArrayIdentity(DataTypeReference requested, Array existingArray) {
    DataTypeReference existing = toReference(existingArray);
    if (!requested.equals(existing)) {
      throw new IllegalArgumentException(
          "array data type cannot preserve requested identity; Ghidra would canonicalize "
              + requested
              + " to "
              + existing);
    }
  }

  @SuppressWarnings("PMD.CompareObjectsWithEquals")
  private static boolean sameIdentity(Object left, Object right) {
    return left == right;
  }

  private static String absolutePath(DataType dataType) {
    String path = dataType.getPathName();
    if (path == null || path.isBlank()) {
      throw new IllegalArgumentException("data type has no resolvable path: " + dataType.getName());
    }
    return path.startsWith("/") ? path : "/" + path;
  }
}
