package app.byteland.ghidra.adapter.ghidra;

import ghidra.app.services.DataTypeManagerService;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.cparser.C.TokenMgrError;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataOrganization;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ProgramBasedDataTypeManager;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.listing.Program;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Shared Ghidra C parser helpers for C type expressions, headers, and function prototypes.
 */
public final class GhidraCParserSupport {
  public static final int MAX_TYPE_EXPRESSION_BYTES = 4_096;
  public static final int MAX_SIGNATURE_BYTES = 8_192;

  private static final Pattern ARRAY_BOUNDS_SUFFIX_PATTERN =
      Pattern.compile("^(\\[\\s*\\d+\\s*\\])+$");
  private static final Set<String> POINTER_QUALIFIERS =
      Set.of("const", "volatile", "restrict", "__restrict", "__restrict__", "_Restrict");

  private GhidraCParserSupport() {}

  public static StandAloneDataTypeManager createScratchManager(
      DataTypeManager programDataTypeManager) {
    return new StandAloneDataTypeManager(
        "bridge-c-scratch", programDataTypeManager.getDataOrganization());
  }

  public static StandAloneDataTypeManager createStdintFallbackManager(
      DataTypeManager programDataTypeManager) {
    DataOrganization organization = programDataTypeManager.getDataOrganization();
    StandAloneDataTypeManager fallback =
        new StandAloneDataTypeManager("bridge-c-stdint", organization);
    int txId = fallback.startTransaction("Populate standard C integer typedefs");
    boolean committed = false;
    try {
      addFixedWidthTypedefs(fallback, organization);
      committed = true;
    } finally {
      fallback.endTransaction(txId, committed);
    }
    return fallback;
  }

  public static DataTypeManager[] lookupManagers(
      DataTypeManager programDataTypeManager, StandAloneDataTypeManager stdintFallback) {
    return new DataTypeManager[] {
      programDataTypeManager, BuiltInDataTypeManager.getDataTypeManager(), stdintFallback
    };
  }

  public static List<DataType> allLookupDataTypes(
      DataTypeManager programDataTypeManager, StandAloneDataTypeManager stdintFallback) {
    List<DataType> all = new ArrayList<>();
    appendDataTypes(programDataTypeManager.getAllDataTypes(), all);
    appendDataTypes(BuiltInDataTypeManager.getDataTypeManager().getAllDataTypes(), all);
    appendDataTypes(stdintFallback.getAllDataTypes(), all);
    return all;
  }

  public static FunctionDefinitionDataType parseSignatureWithCParserUtils(
      StandAloneDataTypeManager scratch, DataTypeManager[] lookupManagers, String prototype)
      throws ParseException {
    String normalized =
        normalizePointerBeforeFunctionName(normalizeCSource(prototype).trim());
    if (normalized.endsWith(";")) {
      normalized = normalized.substring(0, normalized.length() - 1).trim();
    }
    RewrittenPrototype rewritten =
        rewritePointerToArrayParameters(scratch, lookupManagers, normalized);
    FunctionDefinitionDataType parsed =
        parseSignatureDirect(scratch, lookupManagers, rewritten.prototype(), prototype);
    if (!rewritingsEmpty(rewritten)) {
      ParameterDefinition[] arguments = parsed.getArguments();
      for (Map.Entry<Integer, DataType> entry : rewritten.parameterTypes().entrySet()) {
        int index = entry.getKey();
        if (index < arguments.length) {
          arguments[index].setDataType(entry.getValue());
        }
      }
      parsed.setArguments(arguments);
    }
    return parsed;
  }

  private static boolean rewritingsEmpty(RewrittenPrototype rewritten) {
    return rewritten.parameterTypes().isEmpty();
  }

  private static FunctionDefinitionDataType parseSignatureDirect(
      StandAloneDataTypeManager scratch,
      DataTypeManager[] lookupManagers,
      String normalized,
      String originalPrototype)
      throws ParseException {
    DataTypeManagerService managerService = dataTypeManagerService(lookupManagers);
    Program scratchProgram = scratchProgram(scratch);
    try {
      FunctionDefinitionDataType parsed =
          CParserUtils.parseSignature(managerService, scratchProgram, normalized, false);
      if (parsed != null) {
        return parsed;
      }
    } catch (TokenMgrError tokenError) {
      throw new ParseException(cleanParseMessage(tokenError, null));
    }
    CParser parser = new CParser(scratch, false, lookupManagers);
    try {
      DataType direct = parser.parse(normalized + ";");
      if (direct instanceof FunctionDefinitionDataType functionDef && parser.didParseSucceed()) {
        return functionDef;
      }
      String messages = parser.getParseMessages();
      throw new ParseException(
          messages == null || messages.isBlank()
              ? "invalid C function signature: " + originalPrototype
              : cleanWhitespace(messages));
    } catch (TokenMgrError tokenError) {
      throw new ParseException(cleanParseMessage(tokenError, parser.getParseMessages()));
    }
  }

  private static RewrittenPrototype rewritePointerToArrayParameters(
      StandAloneDataTypeManager scratch, DataTypeManager[] lookupManagers, String normalized)
      throws ParseException {
    if (!normalized.endsWith(")")) {
      return new RewrittenPrototype(normalized, Map.of());
    }
    int openParamList = findMatchingOpenParen(normalized, normalized.length() - 1);
    if (openParamList <= 0) {
      return new RewrittenPrototype(normalized, Map.of());
    }
    String beforeParams = normalized.substring(0, openParamList).trim();
    if (beforeParams.isEmpty() || beforeParams.endsWith(")")) {
      return new RewrittenPrototype(normalized, Map.of());
    }
    String rawParamList = normalized.substring(openParamList + 1, normalized.length() - 1);
    if (rawParamList.indexOf('(') < 0 || rawParamList.indexOf('[') < 0) {
      return new RewrittenPrototype(normalized, Map.of());
    }
    List<String> params = splitTopLevelComma(rawParamList);
    Map<Integer, DataType> overriddenTypes = new HashMap<>();
    List<String> updatedParams = new ArrayList<>(params.size());
    for (int index = 0; index < params.size(); index++) {
      String param = params.get(index).trim();
      PointerToArrayDecl decl = parsePointerToArrayDeclarator(param);
      if (decl == null) {
        updatedParams.add(param);
        continue;
      }
      String arrayPrototype =
          "void __ghidra_bridge_array_elem(" + decl.baseSpec() + decl.arraySuffix() + ")";
      FunctionDefinitionDataType arrayHolder =
          parseSignatureDirect(scratch, lookupManagers, arrayPrototype, param);
      if (arrayHolder.getArguments().length != 1
          || arrayHolder.getArguments()[0].getDataType() == null) {
        throw new ParseException("invalid pointer-to-array parameter: " + param);
      }
      DataType target = arrayHolder.getArguments()[0].getDataType();
      for (int ptr = 0; ptr < decl.pointerCount(); ptr++) {
        target = new PointerDataType(target, scratch);
      }
      overriddenTypes.put(index, target);
      updatedParams.add(decl.parameterName() == null ? "int" : "int " + decl.parameterName());
    }
    if (overriddenTypes.isEmpty()) {
      return new RewrittenPrototype(normalized, Map.of());
    }
    String rebuilt =
        normalized.substring(0, openParamList + 1)
            + String.join(", ", updatedParams)
            + ")";
    return new RewrittenPrototype(rebuilt, overriddenTypes);
  }

  private static PointerToArrayDecl parsePointerToArrayDeclarator(String param) {
    int openParen = -1;
    for (int index = 0; index < param.length(); index++) {
      char ch = param.charAt(index);
      if (ch == '[') {
        return null;
      }
      if (ch == '(') {
        openParen = index;
        break;
      }
    }
    if (openParen <= 0) {
      return null;
    }
    int closeParen = findMatchingCloseParen(param, openParen);
    if (closeParen < 0) {
      return null;
    }
    String baseSpec = param.substring(0, openParen).trim();
    String insideParen = param.substring(openParen + 1, closeParen).trim();
    String arraySuffix = param.substring(closeParen + 1).trim();
    if (baseSpec.isEmpty() || !ARRAY_BOUNDS_SUFFIX_PATTERN.matcher(arraySuffix).matches()) {
      return null;
    }
    int cursor = 0;
    int pointerCount = 0;
    String parameterName = null;
    while (cursor < insideParen.length()) {
      char ch = insideParen.charAt(cursor);
      if (Character.isWhitespace(ch)) {
        cursor++;
      } else if (ch == '*') {
        if (parameterName != null) {
          return null;
        }
        pointerCount++;
        cursor++;
      } else if (isIdentifierStart(ch)) {
        int start = cursor++;
        while (cursor < insideParen.length() && isIdentifierChar(insideParen.charAt(cursor))) {
          cursor++;
        }
        String token = insideParen.substring(start, cursor);
        if (POINTER_QUALIFIERS.contains(token)) {
          if (pointerCount == 0 || parameterName != null) {
            return null;
          }
        } else if (parameterName == null && pointerCount > 0) {
          parameterName = token;
        } else {
          return null;
        }
      } else {
        return null;
      }
    }
    return pointerCount > 0
        ? new PointerToArrayDecl(baseSpec, pointerCount, parameterName, arraySuffix)
        : null;
  }

  private static int findMatchingOpenParen(String text, int closeIndex) {
    int depth = 0;
    for (int index = closeIndex; index >= 0; index--) {
      char ch = text.charAt(index);
      if (ch == ')') {
        depth++;
      } else if (ch == '(') {
        depth--;
        if (depth == 0) {
          return index;
        }
      }
    }
    return -1;
  }

  private static int findMatchingCloseParen(String text, int openIndex) {
    int depth = 0;
    for (int index = openIndex; index < text.length(); index++) {
      char ch = text.charAt(index);
      if (ch == '(') {
        depth++;
      } else if (ch == ')') {
        depth--;
        if (depth == 0) {
          return index;
        }
      }
    }
    return -1;
  }

  private static List<String> splitTopLevelComma(String text) {
    List<String> parts = new ArrayList<>();
    int parenDepth = 0;
    int bracketDepth = 0;
    int start = 0;
    for (int index = 0; index < text.length(); index++) {
      char ch = text.charAt(index);
      if (ch == '(') {
        parenDepth++;
      } else if (ch == ')') {
        parenDepth--;
      } else if (ch == '[') {
        bracketDepth++;
      } else if (ch == ']') {
        bracketDepth--;
      } else if (ch == ',' && parenDepth == 0 && bracketDepth == 0) {
        parts.add(text.substring(start, index));
        start = index + 1;
      }
    }
    parts.add(text.substring(start));
    return parts;
  }

  private record RewrittenPrototype(String prototype, Map<Integer, DataType> parameterTypes) {}

  private record PointerToArrayDecl(
      String baseSpec, int pointerCount, String parameterName, String arraySuffix) {}

  public static void resolveReferencedStdintTypedefs(
      DataType type,
      DataTypeManager programDataTypeManager,
      StandAloneDataTypeManager stdintFallback) {
    if (type == null) {
      return;
    }
    Iterator<DataType> stdintTypes = stdintFallback.getAllDataTypes();
    while (stdintTypes.hasNext()) {
      DataType candidate = stdintTypes.next();
      if (candidate instanceof ghidra.program.model.data.TypeDef typeDef
          && referencesTypeName(type, candidate.getName(), 0)
          && programDataTypeManager.getDataType(CategoryPath.ROOT, candidate.getName()) == null
          && GhidraDataTypeReferences.findNamed(programDataTypeManager, candidate.getName())
              .isEmpty()) {
        programDataTypeManager.addDataType(
            new TypedefDataType(
                CategoryPath.ROOT,
                typeDef.getName(),
                typeDef.getDataType().clone(programDataTypeManager),
                programDataTypeManager),
            DataTypeConflictHandler.KEEP_HANDLER);
      }
    }
  }

  public static String cleanParseMessage(Throwable failure, String parserMessages) {
    String primary = failure == null ? null : failure.getMessage();
    String cleanedPrimary = primary == null ? "" : cleanWhitespace(primary);
    String cleanedParser = parserMessages == null ? "" : cleanWhitespace(parserMessages);
    if (!cleanedPrimary.isEmpty() && !cleanedParser.isEmpty()) {
      return cleanedPrimary.contains(cleanedParser)
          ? cleanedPrimary
          : cleanedPrimary + " (" + cleanedParser + ")";
    }
    if (!cleanedPrimary.isEmpty()) {
      return cleanedPrimary;
    }
    if (!cleanedParser.isEmpty()) {
      return cleanedParser;
    }
    return "C parser rejected the input";
  }

  public static String cleanWhitespace(String value) {
    return value.replace('\r', ' ').replace('\n', ' ').replaceAll("\\s+", " ").trim();
  }

  /**
   * Rewrites C99 and GNU restrict qualifiers to Ghidra CParser's {@code __restrict} keyword and
   * keeps comments, string literals, and character literals intact.
   */
  public static String normalizeCSource(String source) {
    if (source == null || source.isEmpty()) {
      return source;
    }
    StringBuilder out = new StringBuilder(source.length());
    int length = source.length();
    int index = 0;
    while (index < length) {
      char ch = source.charAt(index);
      if (ch == '/' && index + 1 < length && source.charAt(index + 1) == '/') {
        int lineEnd = source.indexOf('\n', index + 2);
        if (lineEnd < 0) {
          out.append(source, index, length);
          break;
        }
        out.append(source, index, lineEnd + 1);
        index = lineEnd + 1;
        continue;
      }
      if (ch == '/' && index + 1 < length && source.charAt(index + 1) == '*') {
        int commentEnd = source.indexOf("*/", index + 2);
        if (commentEnd < 0) {
          out.append(source, index, length);
          break;
        }
        out.append(source, index, commentEnd + 2);
        index = commentEnd + 2;
        continue;
      }
      if (ch == '"' || ch == '\'') {
        char quote = ch;
        out.append(ch);
        index++;
        while (index < length) {
          char inner = source.charAt(index++);
          out.append(inner);
          if (inner == '\\' && index < length) {
            out.append(source.charAt(index++));
          } else if (inner == quote) {
            break;
          }
        }
        continue;
      }
      if (isIdentifierStart(ch)) {
        int start = index++;
        while (index < length && isIdentifierChar(source.charAt(index))) {
          index++;
        }
        String token = source.substring(start, index);
        if ("restrict".equals(token) || "__restrict__".equals(token) || "_Restrict".equals(token)) {
          out.append("__restrict");
        } else {
          out.append(token);
        }
        continue;
      }
      out.append(ch);
      index++;
    }
    return out.toString();
  }

  private static boolean isIdentifierStart(char ch) {
    return Character.isLetter(ch) || ch == '_' || ch == '$';
  }

  static String normalizePointerBeforeFunctionName(String prototype) {
    int firstOpenParen = prototype.indexOf('(');
    if (firstOpenParen <= 0) {
      return prototype;
    }
    int nameEnd = firstOpenParen;
    while (nameEnd > 0 && Character.isWhitespace(prototype.charAt(nameEnd - 1))) {
      nameEnd--;
    }
    int nameStart = nameEnd;
    while (nameStart > 0 && isIdentifierChar(prototype.charAt(nameStart - 1))) {
      nameStart--;
    }
    if (nameStart > 0 && nameStart < nameEnd && prototype.charAt(nameStart - 1) == '*') {
      return prototype.substring(0, nameStart) + " " + prototype.substring(nameStart);
    }
    return prototype;
  }

  private static boolean isIdentifierChar(char ch) {
    return Character.isLetterOrDigit(ch) || ch == '_' || ch == '$';
  }

  private static boolean referencesTypeName(DataType type, String name, int depth) {
    if (type == null || depth > 32) {
      return false;
    }
    if (name.equals(type.getName())) {
      return true;
    }
    if (type instanceof ghidra.program.model.data.Pointer pointer) {
      return referencesTypeName(pointer.getDataType(), name, depth + 1);
    }
    if (type instanceof ghidra.program.model.data.Array array) {
      return referencesTypeName(array.getDataType(), name, depth + 1);
    }
    if (type instanceof ghidra.program.model.data.TypeDef typeDef) {
      return referencesTypeName(typeDef.getBaseDataType(), name, depth + 1);
    }
    if (type instanceof ghidra.program.model.data.FunctionDefinition functionDef) {
      if (referencesTypeName(functionDef.getReturnType(), name, depth + 1)) {
        return true;
      }
      for (ghidra.program.model.data.ParameterDefinition argument : functionDef.getArguments()) {
        if (referencesTypeName(argument.getDataType(), name, depth + 1)) {
          return true;
        }
      }
    }
    return false;
  }

  private static void addFixedWidthTypedefs(
      StandAloneDataTypeManager manager, DataOrganization organization) {
    addTypedef(manager, "int8_t", AbstractIntegerDataType.getSignedDataType(1, manager));
    addTypedef(manager, "uint8_t", AbstractIntegerDataType.getUnsignedDataType(1, manager));
    addTypedef(manager, "int16_t", AbstractIntegerDataType.getSignedDataType(2, manager));
    addTypedef(manager, "uint16_t", AbstractIntegerDataType.getUnsignedDataType(2, manager));
    addTypedef(manager, "int32_t", AbstractIntegerDataType.getSignedDataType(4, manager));
    addTypedef(manager, "uint32_t", AbstractIntegerDataType.getUnsignedDataType(4, manager));
    addTypedef(manager, "int64_t", AbstractIntegerDataType.getSignedDataType(8, manager));
    addTypedef(manager, "uint64_t", AbstractIntegerDataType.getUnsignedDataType(8, manager));
    int pointerSize = Math.max(1, organization.getPointerSize());
    DataType signedSize = AbstractIntegerDataType.getSignedDataType(pointerSize, manager);
    DataType unsignedSize = AbstractIntegerDataType.getUnsignedDataType(pointerSize, manager);
    addTypedef(manager, "size_t", unsignedSize);
    addTypedef(manager, "ssize_t", signedSize);
    addTypedef(manager, "uintptr_t", unsignedSize);
    addTypedef(manager, "intptr_t", signedSize);
    addTypedef(manager, "ptrdiff_t", signedSize);
    addTypedef(manager, "bool", BooleanDataType.dataType);
  }

  private static void addTypedef(
      StandAloneDataTypeManager manager, String name, DataType baseType) {
    manager.addDataType(
        new TypedefDataType(CategoryPath.ROOT, name, baseType, manager),
        DataTypeConflictHandler.KEEP_HANDLER);
  }

  private static void appendDataTypes(Iterator<DataType> source, List<DataType> sink) {
    while (source.hasNext()) {
      sink.add(source.next());
    }
  }

  @SuppressWarnings({"PMD.UseProperClassLoader", "PMD.CompareObjectsWithEquals"})
  private static DataTypeManagerService dataTypeManagerService(DataTypeManager[] managers) {
    return (DataTypeManagerService)
        Proxy.newProxyInstance(
            GhidraCParserSupport.class.getClassLoader(),
            new Class<?>[] {DataTypeManagerService.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getDataTypeManagers" -> managers.clone();
                  case "getBuiltInDataTypesManager" -> BuiltInDataTypeManager.getDataTypeManager();
                  case "toString" -> "bridge-c-dtm-service";
                  case "hashCode" -> System.identityHashCode(proxy);
                  case "equals" -> proxy == args[0];
                  default -> null;
                });
  }

  @SuppressWarnings({"PMD.UseProperClassLoader", "PMD.CompareObjectsWithEquals"})
  private static Program scratchProgram(StandAloneDataTypeManager scratch) {
    ProgramBasedDataTypeManager dtmProxy =
        (ProgramBasedDataTypeManager)
            Proxy.newProxyInstance(
                GhidraCParserSupport.class.getClassLoader(),
                new Class<?>[] {ProgramBasedDataTypeManager.class},
                (proxy, method, args) -> {
                  if (method.getDeclaringClass().isAssignableFrom(StandAloneDataTypeManager.class)) {
                    try {
                      return method.invoke(scratch, args);
                    } catch (InvocationTargetException ex) {
                      throw ex.getTargetException();
                    }
                  }
                  return switch (method.getName()) {
                    case "toString" -> "bridge-scratch-program-dtm";
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == args[0];
                    default -> null;
                  };
                });
    return (Program)
        Proxy.newProxyInstance(
            GhidraCParserSupport.class.getClassLoader(),
            new Class<?>[] {Program.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getDataTypeManager" -> dtmProxy;
                  case "toString" -> "bridge-scratch-program";
                  case "hashCode" -> System.identityHashCode(proxy);
                  case "equals" -> proxy == args[0];
                  default -> null;
                });
  }
}
