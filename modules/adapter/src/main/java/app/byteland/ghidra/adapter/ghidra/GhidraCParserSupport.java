package app.byteland.ghidra.adapter.ghidra;

import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.function.FunctionService;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.VoidDataType;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;

/**
 * Shared lexical utilities and type-detachment helpers for C parsers.
 */
public final class GhidraCParserSupport {
  public static final int MAX_TYPE_EXPRESSION_BYTES = DataTypeReference.MAX_C_TYPE_BYTES;
  public static final int MAX_DECLARATIONS_BYTES = DataTypeService.MAX_DECLARATIONS_BYTES;
  public static final int MAX_SIGNATURE_BYTES = FunctionService.MAX_SIGNATURE_BYTES;

  static final String SYNTHETIC_TYPEDEF_NAME = "__ghidra_bridge_ctype";

  private static final Set<String> CVR_QUALIFIERS =
      Set.of(
          "const",
          "volatile",
          "restrict",
          "_Restrict",
          "__const",
          "__const__",
          "__volatile",
          "__volatile__",
          "__restrict",
          "__restrict__");

  private static final Set<String> RESTRICT_QUALIFIERS =
      Set.of("restrict", "_Restrict", "__restrict", "__restrict__");

  private GhidraCParserSupport() {}

  /**
   * Removes C {@code const}, {@code volatile}, and {@code restrict} qualifiers and keeps
   * identifiers, string literals, comments, and Ghidra category paths intact.
   */
  public static String stripQualifiers(String declaration) {
    if (declaration == null) {
      throw new IllegalArgumentException("declaration is required");
    }
    return stripTokens(declaration, CVR_QUALIFIERS, true).trim();
  }

  /**
   * Removes C {@code restrict} qualifiers and keeps {@code const}, {@code volatile}, comments, and
   * string literals intact.
   */
  public static String stripRestrictQualifiers(String source) {
    if (source == null) {
      throw new IllegalArgumentException("source is required");
    }
    return stripTokens(source, RESTRICT_QUALIFIERS, false);
  }

  public static String maskCommentsAndStrings(String input) {
    StringBuilder out = new StringBuilder(input.length());
    int index = 0;
    while (index < input.length()) {
      char ch = input.charAt(index);
      if (ch == '/' && index + 1 < input.length() && input.charAt(index + 1) == '/') {
        int lineEnd = input.indexOf('\n', index + 2);
        int stop = lineEnd < 0 ? input.length() : lineEnd;
        out.append(' ');
        index = stop;
      } else if (ch == '/' && index + 1 < input.length() && input.charAt(index + 1) == '*') {
        int blockEnd = input.indexOf("*/", index + 2);
        int stop = blockEnd < 0 ? input.length() : blockEnd + 2;
        for (int i = index; i < stop; i++) {
          out.append(input.charAt(i) == '\n' ? '\n' : ' ');
        }
        index = stop;
      } else if (ch == '"' || ch == '\'') {
        int stop = skipQuotedLiteral(input, index, ch);
        out.append("\"\"");
        index = stop;
      } else {
        out.append(ch);
        index++;
      }
    }
    return out.toString();
  }

  public static DataType matchExplicitTagType(DataTypeManager programManager, String specifiers) {
    String[] parts = specifiers.split("\\s+");
    if (parts.length != 2) {
      return null;
    }
    String keyword = parts[0];
    String name = parts[1];
    if (!"struct".equals(keyword) && !"union".equals(keyword) && !"enum".equals(keyword)) {
      return null;
    }
    List<DataType> matches = GhidraDataTypeReferences.findNamed(programManager, name);
    List<DataType> filtered = new ArrayList<>();
    for (DataType candidate : matches) {
      if ("struct".equals(keyword) && candidate instanceof Structure) {
        filtered.add(candidate);
      } else if ("union".equals(keyword) && candidate instanceof Union) {
        filtered.add(candidate);
      } else if ("enum".equals(keyword) && candidate instanceof ghidra.program.model.data.Enum) {
        filtered.add(candidate);
      }
    }
    if (filtered.isEmpty()) {
      throw new IllegalArgumentException("unknown " + keyword + " data type: " + name);
    }
    if (filtered.size() > 1) {
      throw new IllegalArgumentException(
          "ambiguous " + keyword + " data type: " + name + "; use an absolute path");
    }
    return filtered.getFirst();
  }

  public static String normalizeTagKeywords(DataTypeManager programManager, String signature) {
    StringBuilder out = new StringBuilder(signature.length());
    int index = 0;
    while (index < signature.length()) {
      if (isIdentifierStart(signature.charAt(index))) {
        int end = index + 1;
        while (end < signature.length() && isIdentifierPart(signature.charAt(end))) {
          end++;
        }
        String word = signature.substring(index, end);
        if ("struct".equals(word) || "union".equals(word) || "enum".equals(word)) {
          int nextStart = end;
          while (nextStart < signature.length()
              && Character.isWhitespace(signature.charAt(nextStart))) {
            nextStart++;
          }
          if (nextStart < signature.length() && isIdentifierStart(signature.charAt(nextStart))) {
            int nextEnd = nextStart + 1;
            while (nextEnd < signature.length() && isIdentifierPart(signature.charAt(nextEnd))) {
              nextEnd++;
            }
            String tagName = signature.substring(nextStart, nextEnd);
            DataType matched = matchExplicitTagType(programManager, word + " " + tagName);
            out.append(matched.getName());
            index = nextEnd;
            continue;
          }
        }
        out.append(word);
        index = end;
      } else {
        out.append(signature.charAt(index));
        index++;
      }
    }
    return out.toString();
  }

  public static DataType detachFromScratch(DataTypeManager programManager, DataType dataType) {
    if (dataType == null) {
      return null;
    }
    DataTypeManager owner = dataType.getDataTypeManager();
    if (owner == programManager || owner == BuiltInDataTypeManager.getDataTypeManager()) {
      return dataType.clone(programManager);
    }
    if (dataType instanceof Pointer pointer) {
      DataType pointee = detachFromScratch(programManager, pointer.getDataType());
      return pointee == null
          ? new PointerDataType(programManager)
          : programManager.getPointer(pointee);
    }
    if (dataType instanceof Array array) {
      DataType element = detachFromScratch(programManager, array.getDataType());
      return GhidraDataTypeReferences.buildArrayDataType(
          element, array.getNumElements(), programManager);
    }
    if (dataType instanceof TypeDef typeDef) {
      DataType existing =
          GhidraDataTypeReferences.findByPath(programManager, typeDef.getPathName());
      if (existing != null) {
        return existing;
      }
      List<DataType> byName = GhidraDataTypeReferences.findNamed(programManager, typeDef.getName());
      if (byName.size() == 1 && byName.getFirst() instanceof TypeDef) {
        return byName.getFirst();
      }
      return new TypedefDataType(
          typeDef.getCategoryPath(),
          typeDef.getName(),
          detachFromScratch(programManager, typeDef.getDataType()),
          programManager);
    }
    if (dataType instanceof FunctionDefinition functionDefinition) {
      FunctionDefinitionDataType detached =
          cloneFunctionDefinition(programManager, functionDefinition);
      if (!CategoryPath.ROOT.equals(functionDefinition.getCategoryPath())) {
        detached.setCategoryPath(functionDefinition.getCategoryPath());
      }
      return detached;
    }
    DataType byPath = GhidraDataTypeReferences.findByPath(programManager, dataType.getPathName());
    if (byPath != null) {
      return byPath;
    }
    List<DataType> byName = GhidraDataTypeReferences.findNamed(programManager, dataType.getName());
    if (byName.size() == 1) {
      return byName.getFirst();
    }
    return dataType.copy(programManager);
  }

  public static FunctionDefinitionDataType cloneFunctionDefinition(
      DataTypeManager programManager, FunctionDefinition source) {
    normalizeAnonymousFunctionPointers(source);
    FunctionDefinitionDataType copy =
        new FunctionDefinitionDataType(CategoryPath.ROOT, source.getName(), programManager);
    DataType returnType =
        source.getReturnType() == null
            ? VoidDataType.dataType.clone(programManager)
            : detachFromScratch(programManager, source.getReturnType());
    copy.setReturnType(returnType);
    ParameterDefinition[] sourceArgs = source.getArguments();
    ParameterDefinition[] clonedArgs = new ParameterDefinition[sourceArgs.length];
    for (int index = 0; index < sourceArgs.length; index++) {
      ParameterDefinition arg = sourceArgs[index];
      clonedArgs[index] =
          new ParameterDefinitionImpl(
              arg.getName(),
              detachFromScratch(programManager, arg.getDataType()),
              arg.getComment());
    }
    copy.setArguments(clonedArgs);
    copy.setVarArgs(source.hasVarArgs());
    copy.setNoReturn(source.hasNoReturn());
    String cc = source.getCallingConventionName();
    if (cc != null
        && !cc.isBlank()
        && !"unknown".equalsIgnoreCase(cc)
        && !"default".equalsIgnoreCase(cc)) {
      try {
        copy.setCallingConvention(cc);
      } catch (InvalidInputException error) {
        throw new IllegalArgumentException("invalid calling convention: " + cc, error);
      }
    }
    return copy;
  }

  public static void normalizeAnonymousFunctionPointers(DataType dataType) {
    if (dataType instanceof Pointer pointer && pointer.getDataType() != null) {
      normalizeAnonymousFunctionPointers(pointer.getDataType());
    } else if (dataType instanceof Array array && array.getDataType() != null) {
      normalizeAnonymousFunctionPointers(array.getDataType());
    } else if (dataType instanceof TypeDef typeDef && typeDef.getDataType() != null) {
      normalizeAnonymousFunctionPointers(typeDef.getDataType());
    } else if (dataType instanceof FunctionDefinition functionDefinition) {
      if (functionDefinition.getName().startsWith(SYNTHETIC_TYPEDEF_NAME)
          || functionDefinition.getName().startsWith("_func")) {
        assignDeterministicAnonymousName(functionDefinition);
      }
      if (functionDefinition.getReturnType() != null) {
        normalizeAnonymousFunctionPointers(functionDefinition.getReturnType());
      }
      for (ParameterDefinition parameter : functionDefinition.getArguments()) {
        if (parameter.getDataType() != null) {
          normalizeAnonymousFunctionPointers(parameter.getDataType());
        }
      }
    }
  }

  public static void assignDeterministicAnonymousName(FunctionDefinition definition) {
    String prototype = definition.getPrototypeString();
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(prototype.getBytes(StandardCharsets.UTF_8));
      String suffix = HexFormat.of().formatHex(hash, 0, 4);
      definition.setName("anon_fn_" + suffix);
    } catch (NoSuchAlgorithmException | DuplicateNameException | InvalidNameException ignored) {
      // Keep the current scratch function definition name if rename is rejected.
    }
  }

  public static int findFirstDeclaratorIndex(String cleaned) {
    int start = 0;
    if (cleaned.startsWith("/")) {
      int lastSlash = -1;
      for (int i = 0; i < cleaned.length(); i++) {
        char ch = cleaned.charAt(i);
        if (ch == '*' || ch == '[' || ch == '(') {
          break;
        }
        if (ch == '/') {
          lastSlash = i;
        }
      }
      start = lastSlash + 1;
    }
    for (int i = start; i < cleaned.length(); i++) {
      char ch = cleaned.charAt(i);
      if (ch == '*' || ch == '[' || ch == '(') {
        return i;
      }
    }
    return -1;
  }

  public static int findMatchingParen(String text, int openIndex) {
    if (openIndex < 0 || openIndex >= text.length() || text.charAt(openIndex) != '(') {
      return -1;
    }
    int depth = 0;
    for (int i = openIndex; i < text.length(); i++) {
      char ch = text.charAt(i);
      if (ch == '(') {
        depth++;
      } else if (ch == ')') {
        depth--;
        if (depth == 0) {
          return i;
        }
      }
    }
    return -1;
  }

  public static int findMatchingBrace(String text, int openIndex) {
    if (openIndex < 0 || openIndex >= text.length() || text.charAt(openIndex) != '{') {
      return -1;
    }
    int depth = 0;
    for (int i = openIndex; i < text.length(); i++) {
      char ch = text.charAt(i);
      if (ch == '{') {
        depth++;
      } else if (ch == '}') {
        depth--;
        if (depth == 0) {
          return i;
        }
      }
    }
    return -1;
  }

  public static int findTopLevelParameterListOpen(String signature) {
    int depth = 0;
    int lastTopLevelOpen = -1;
    for (int i = 0; i < signature.length(); i++) {
      char ch = signature.charAt(i);
      if (ch == '(') {
        if (depth == 0) {
          lastTopLevelOpen = i;
        }
        depth++;
      } else if (ch == ')') {
        depth--;
      }
    }
    return lastTopLevelOpen;
  }

  public static List<String> splitTopLevelCommaList(String body) {
    List<String> items = new ArrayList<>();
    int depthParen = 0;
    int depthBracket = 0;
    int start = 0;
    for (int i = 0; i < body.length(); i++) {
      char ch = body.charAt(i);
      if (ch == '(') depthParen++;
      else if (ch == ')') depthParen--;
      else if (ch == '[') depthBracket++;
      else if (ch == ']') depthBracket--;
      else if (ch == ',' && depthParen == 0 && depthBracket == 0) {
        items.add(body.substring(start, i));
        start = i + 1;
      }
    }
    items.add(body.substring(start));
    return items;
  }

  public static List<String> splitTopLevelStatements(String source) {
    List<String> statements = new ArrayList<>();
    int braceDepth = 0;
    int parenDepth = 0;
    int start = 0;
    for (int i = 0; i < source.length(); i++) {
      char ch = source.charAt(i);
      if (ch == '{') {
        braceDepth++;
      } else if (ch == '}') {
        braceDepth = Math.max(0, braceDepth - 1);
      } else if (ch == '(') {
        parenDepth++;
      } else if (ch == ')') {
        parenDepth = Math.max(0, parenDepth - 1);
      } else if (ch == ';' && braceDepth == 0 && parenDepth == 0) {
        statements.add(source.substring(start, i));
        start = i + 1;
      }
    }
    return statements;
  }

  public static boolean containsPointerToArrayDeclarator(String text) {
    for (int i = 0; i < text.length(); i++) {
      if (text.charAt(i) == '(') {
        int close = findMatchingParen(text, i);
        if (close > i) {
          String inside = text.substring(i + 1, close).trim();
          int after = close + 1;
          while (after < text.length() && Character.isWhitespace(text.charAt(after))) {
            after++;
          }
          if (inside.startsWith("*") && after < text.length() && text.charAt(after) == '[') {
            return true;
          }
        }
      }
    }
    return false;
  }

  public static String extractTopLevelFunctionName(String signature) {
    int openParen = findTopLevelParameterListOpen(signature);
    if (openParen <= 0) {
      return null;
    }
    String header = signature.substring(0, openParen).trim();
    int start = header.length();
    while (start > 0 && isIdentifierPart(header.charAt(start - 1))) {
      start--;
    }
    return start < header.length() ? header.substring(start) : null;
  }

  public static boolean isSingleIdentifier(String text) {
    if (text.isEmpty() || !isIdentifierStart(text.charAt(0))) {
      return false;
    }
    for (int i = 1; i < text.length(); i++) {
      if (!isIdentifierPart(text.charAt(i))) {
        return false;
      }
    }
    return true;
  }

  public static boolean isIdentifierStart(char ch) {
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_' || ch == '$';
  }

  public static boolean isIdentifierPart(char ch) {
    return isIdentifierStart(ch) || (ch >= '0' && ch <= '9');
  }

  public static String detailMessage(Throwable error, String parseMessages) {
    String parseText = parseMessages == null ? "" : parseMessages.trim();
    if (!parseText.isEmpty()) {
      return parseText;
    }
    String message = error.getMessage();
    return message == null || message.isBlank() ? error.getClass().getSimpleName() : message;
  }

  public static String nonBlankOr(String candidate, String fallback) {
    return candidate == null || candidate.isBlank() ? fallback : candidate.trim();
  }

  private static String stripTokens(
      String input, Set<String> tokensToStrip, boolean preserveLeadingCategoryPath) {
    StringBuilder out = new StringBuilder(input.length());
    int index = 0;
    boolean pathAllowedHere = preserveLeadingCategoryPath;

    while (index < input.length()) {
      char ch = input.charAt(index);
      if (ch == '/' && index + 1 < input.length() && input.charAt(index + 1) == '/') {
        int lineEnd = input.indexOf('\n', index + 2);
        int stop = lineEnd < 0 ? input.length() : lineEnd + 1;
        out.append(input, index, stop);
        index = stop;
        continue;
      }
      if (ch == '/' && index + 1 < input.length() && input.charAt(index + 1) == '*') {
        int blockEnd = input.indexOf("*/", index + 2);
        int stop = blockEnd < 0 ? input.length() : blockEnd + 2;
        out.append(input, index, stop);
        index = stop;
        continue;
      }
      if (ch == '"' || ch == '\'') {
        int stop = skipQuotedLiteral(input, index, ch);
        out.append(input, index, stop);
        index = stop;
        pathAllowedHere = false;
        continue;
      }
      if (pathAllowedHere && ch == '/') {
        int pathStop = scanCategoryPathSpan(input, index);
        out.append(input, index, pathStop);
        index = pathStop;
        pathAllowedHere = false;
        continue;
      }
      if (isIdentifierStart(ch)) {
        int end = index + 1;
        while (end < input.length() && isIdentifierPart(input.charAt(end))) {
          end++;
        }
        String token = input.substring(index, end);
        if (tokensToStrip.contains(token)) {
          index = end;
          while (index < input.length() && input.charAt(index) == ' ') {
            if (!out.isEmpty() && out.charAt(out.length() - 1) == ' ') {
              index++;
            } else {
              break;
            }
          }
          continue;
        }
        out.append(token);
        index = end;
        pathAllowedHere = false;
        continue;
      }
      if (Character.isWhitespace(ch)) {
        out.append(ch);
        index++;
        continue;
      }
      out.append(ch);
      pathAllowedHere = preserveLeadingCategoryPath && (ch == '(' || ch == ',' || ch == ';');
      index++;
    }
    return out.toString();
  }

  private static int skipQuotedLiteral(String input, int start, char quote) {
    int index = start + 1;
    while (index < input.length()) {
      char ch = input.charAt(index);
      if (ch == '\\' && index + 1 < input.length()) {
        index += 2;
      } else if (ch == quote) {
        return index + 1;
      } else {
        index++;
      }
    }
    return input.length();
  }

  private static int scanCategoryPathSpan(String input, int start) {
    int lastSlash = start;
    int limit = start;
    while (limit < input.length()) {
      char ch = input.charAt(limit);
      if (ch == '*' || ch == '[' || ch == '(' || ch == ')' || ch == ',' || ch == ';') {
        break;
      }
      if (ch == '/') {
        lastSlash = limit;
      }
      limit++;
    }
    int nameEnd = lastSlash + 1;
    while (nameEnd < limit && !Character.isWhitespace(input.charAt(nameEnd))) {
      nameEnd++;
    }
    return nameEnd;
  }
}
