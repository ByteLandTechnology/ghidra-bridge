package app.byteland.ghidra.adapter.ghidra;

import app.byteland.ghidra.service.datatype.DataTypeReference;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.data.TypeDef;
import ghidra.util.data.DataTypeParser;
import ghidra.util.exception.CancelledException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Resolves single C type expressions and parameter declarations in an isolated scratch manager.
 */
public final class CTypeExpressionResolver {
  private static final int MAX_DECLARATOR_DEPTH = 32;

  private CTypeExpressionResolver() {}

  /**
   * Parsed C parameter or field declaration with an optional identifier name.
   *
   * @param name optional parameter or field name
   * @param dataType resolved Ghidra data type
   */
  public record ParsedParameter(String name, DataType dataType) {}

  /**
   * Resolves a C type expression in {@code programDataTypeManager} and creates no orphan types on
   * failure.
   */
  public static DataType resolveCType(DataTypeManager programDataTypeManager, String declaration) {
    if (programDataTypeManager == null) {
      throw new IllegalArgumentException("program data type manager is required");
    }
    if (declaration == null || declaration.isBlank()) {
      throw new IllegalArgumentException("data type declaration must not be blank");
    }
    if (declaration.getBytes(StandardCharsets.UTF_8).length
        > GhidraCParserSupport.MAX_TYPE_EXPRESSION_BYTES) {
      throw new IllegalArgumentException(
          "data type declaration exceeds maximum size of "
              + GhidraCParserSupport.MAX_TYPE_EXPRESSION_BYTES
              + " UTF-8 bytes");
    }
    String trimmed = declaration.trim();
    if ("pointer".equals(trimmed)) {
      return GhidraDataTypeReferences.resolve(
          programDataTypeManager, DataTypeReference.untypedPointer());
    }
    if (trimmed.indexOf(';') >= 0 || trimmed.indexOf('{') >= 0 || trimmed.indexOf('}') >= 0) {
      throw new IllegalArgumentException(
          "C type reference must be a single type expression without inline definitions: "
              + declaration);
    }

    String cleaned = GhidraCParserSupport.stripQualifiers(trimmed);
    if (cleaned.isBlank()) {
      throw new IllegalArgumentException("data type declaration has no base type: " + declaration);
    }

    if (cleaned.startsWith("/") && GhidraCParserSupport.findFirstDeclaratorIndex(cleaned) < 0) {
      DataType byPath = GhidraDataTypeReferences.findByPath(programDataTypeManager, cleaned);
      if (byPath == null) {
        throw new IllegalArgumentException("unknown data type: " + cleaned);
      }
      return byPath;
    }

    int splitIndex = GhidraCParserSupport.findFirstDeclaratorIndex(cleaned);
    String rawSpecifiers = splitIndex < 0 ? cleaned : cleaned.substring(0, splitIndex).trim();
    String abstractDeclarator = splitIndex < 0 ? "" : cleaned.substring(splitIndex).trim();
    if (rawSpecifiers.isBlank()) {
      throw new IllegalArgumentException("missing base type in declaration: " + declaration);
    }

    try (CParserScratchEnvironment env = CParserScratchEnvironment.open(programDataTypeManager)) {
      try {
        DataType baseType = resolveBaseSpecifier(env, rawSpecifiers);
        if (abstractDeclarator.isEmpty()) {
          return baseType;
        }
        return applyAbstractDeclarator(programDataTypeManager, baseType, abstractDeclarator, 0);
      } catch (IllegalArgumentException primaryError) {
        if (containsFunctionParameterSuffix(abstractDeclarator) && !rawSpecifiers.startsWith("/")) {
          DataType fallback =
              tryResolveFunctionPointerWithCParser(env, rawSpecifiers, abstractDeclarator);
          if (fallback != null) {
            return fallback;
          }
        }
        throw primaryError;
      }
    }
  }

  /**
   * Parses one named or unnamed C parameter or field declaration against {@code manager}.
   */
  public static ParsedParameter parseParameterDeclaration(
      DataTypeManager manager, String rawDeclaration, int index) {
    String cleaned = GhidraCParserSupport.stripQualifiers(rawDeclaration.trim());
    if (cleaned.isEmpty()) {
      throw new IllegalArgumentException("empty parameter at index " + index);
    }
    try {
      DataType direct = resolveCType(manager, cleaned);
      return new ParsedParameter(null, direct);
    } catch (IllegalArgumentException ignored) {
      // Try named declarator extraction when direct abstract type resolution fails.
    }

    ExtractedDeclaratorName extracted = stripParameterIdentifier(cleaned);
    if (extracted == null) {
      throw new IllegalArgumentException("invalid C parameter declaration: " + rawDeclaration);
    }
    DataType resolved = resolveCType(manager, extracted.abstractType());
    return new ParsedParameter(extracted.name(), resolved);
  }

  private static DataType resolveBaseSpecifier(
      CParserScratchEnvironment env, String rawSpecifiers) {
    DataTypeManager programManager = env.programManager();
    String trimmed = rawSpecifiers.trim();
    if (trimmed.startsWith("/")) {
      DataType byPath = GhidraDataTypeReferences.findByPath(programManager, trimmed);
      if (byPath == null) {
        throw new IllegalArgumentException("unknown data type: " + trimmed);
      }
      return byPath;
    }

    DataType tagMatch = GhidraCParserSupport.matchExplicitTagType(programManager, trimmed);
    if (tagMatch != null) {
      return tagMatch;
    }

    if (GhidraCParserSupport.isSingleIdentifier(trimmed)) {
      List<DataType> programMatches = new ArrayList<>();
      programManager.findDataTypes(trimmed, programMatches);
      if (programMatches.size() > 1) {
        throw new IllegalArgumentException(
            "ambiguous data type name: " + trimmed + "; use an absolute path");
      }
      if (programMatches.size() == 1) {
        return programMatches.getFirst();
      }
    }

    DataTypeParser parser =
        new DataTypeParser(
            env.scratch(), env.scratch(), env.queryService(), DataTypeParser.AllowedDataTypes.ALL);
    try {
      DataType parsed = parser.parse(trimmed);
      if (parsed == null) {
        throw new IllegalArgumentException("unknown data type: " + trimmed);
      }
      return GhidraCParserSupport.detachFromScratch(programManager, parsed);
    } catch (InvalidDataTypeException | CancelledException error) {
      if (GhidraCParserSupport.isSingleIdentifier(trimmed)) {
        DataType stdintMatch = env.stdintType(trimmed);
        if (stdintMatch != null) {
          return GhidraCParserSupport.detachFromScratch(programManager, stdintMatch);
        }
      }
      throw new IllegalArgumentException("unknown C data type: " + trimmed, error);
    }
  }

  private static DataType tryResolveFunctionPointerWithCParser(
      CParserScratchEnvironment env, String rawSpecifiers, String abstractDeclarator) {
    DataType matchedTag =
        GhidraCParserSupport.matchExplicitTagType(env.programManager(), rawSpecifiers.trim());
    String normalizedSpecs = matchedTag == null ? rawSpecifiers : matchedTag.getName();
    String namedDeclarator =
        insertDeclaratorIdentifier(
            abstractDeclarator, GhidraCParserSupport.SYNTHETIC_TYPEDEF_NAME);
    String statement = "typedef " + normalizedSpecs + " " + namedDeclarator + ";";
    Set<String> priorComposites = collectCompositeNames(env.scratch());
    CParser parser = new CParser(env.scratch(), true, env.cParserSubArchives());
    try {
      parser.parse(statement);
    } catch (ParseException error) {
      return null;
    }
    if (!parser.didParseSucceed()) {
      return null;
    }
    for (String compositeName : collectCompositeNames(env.scratch())) {
      if (!priorComposites.contains(compositeName)) {
        throw new IllegalArgumentException("unknown composite data type: " + compositeName);
      }
    }
    DataType typedefCandidate =
        parser.getTypes().get(GhidraCParserSupport.SYNTHETIC_TYPEDEF_NAME);
    if (!(typedefCandidate instanceof TypeDef)) {
      typedefCandidate =
          env.scratch()
              .getDataType(CategoryPath.ROOT, GhidraCParserSupport.SYNTHETIC_TYPEDEF_NAME);
    }
    if (!(typedefCandidate instanceof TypeDef resolvedTypeDef)) {
      return null;
    }
    DataType unwrapped = resolvedTypeDef.getDataType();
    if (containsImplicitUndefinedParameter(unwrapped, abstractDeclarator)) {
      return null;
    }
    GhidraCParserSupport.normalizeAnonymousFunctionPointers(unwrapped);
    DataType cloned = GhidraCParserSupport.detachFromScratch(env.programManager(), unwrapped);
    if (cloned instanceof Pointer pointer) {
      GhidraDataTypeReferences.requirePointerIdentityCanBePreserved(env.programManager(), pointer);
    }
    return cloned;
  }

  private static DataType applyAbstractDeclarator(
      DataTypeManager manager, DataType baseType, String declarator, int depth) {
    if (depth > MAX_DECLARATOR_DEPTH) {
      throw new IllegalArgumentException("C declarator exceeds maximum nesting depth");
    }
    String text = declarator.trim();
    if (text.isEmpty()) {
      return baseType;
    }

    int index = 0;
    int pointerCount = 0;
    while (index < text.length()) {
      char ch = text.charAt(index);
      if (ch == '*') {
        pointerCount++;
        index++;
      } else if (Character.isWhitespace(ch)) {
        index++;
      } else {
        break;
      }
    }

    String innerDeclarator = null;
    if (index < text.length() && text.charAt(index) == '(') {
      int closeParen = GhidraCParserSupport.findMatchingParen(text, index);
      if (closeParen < 0) {
        throw new IllegalArgumentException("unbalanced parentheses in C declarator: " + declarator);
      }
      String inside = text.substring(index + 1, closeParen).trim();
      if (isGroupedAbstractDeclarator(inside)) {
        innerDeclarator = inside;
        index = closeParen + 1;
      }
    }

    List<DeclaratorSuffix> suffixes = new ArrayList<>();
    while (index < text.length()) {
      while (index < text.length() && Character.isWhitespace(text.charAt(index))) {
        index++;
      }
      if (index >= text.length()) {
        break;
      }
      char ch = text.charAt(index);
      if (ch == '[') {
        int closeBracket = text.indexOf(']', index + 1);
        if (closeBracket < 0) {
          throw new IllegalArgumentException("unclosed '[' in C declarator: " + declarator);
        }
        String countText = text.substring(index + 1, closeBracket).trim();
        suffixes.add(new DeclaratorSuffix.ArraySuffix(parsePositiveArrayCount(countText, declarator)));
        index = closeBracket + 1;
      } else if (ch == '(') {
        int closeParen = GhidraCParserSupport.findMatchingParen(text, index);
        if (closeParen < 0) {
          throw new IllegalArgumentException("unclosed '(' in C declarator: " + declarator);
        }
        suffixes.add(new DeclaratorSuffix.FunctionSuffix(text.substring(index + 1, closeParen).trim()));
        index = closeParen + 1;
      } else {
        throw new IllegalArgumentException("unexpected token in C declarator: " + declarator);
      }
    }

    DataType current = baseType;
    for (int p = 0; p < pointerCount; p++) {
      Pointer pointer = manager.getPointer(current);
      GhidraDataTypeReferences.requirePointerIdentityCanBePreserved(manager, pointer);
      current = pointer;
    }
    for (int s = suffixes.size() - 1; s >= 0; s--) {
      switch (suffixes.get(s)) {
        case DeclaratorSuffix.ArraySuffix arraySuffix ->
            current =
                GhidraDataTypeReferences.buildArrayDataType(current, arraySuffix.count(), manager);
        case DeclaratorSuffix.FunctionSuffix functionSuffix ->
            current = buildFunctionDefinitionFromSuffix(manager, current, functionSuffix.params());
      }
    }
    if (innerDeclarator != null) {
      return applyAbstractDeclarator(manager, current, innerDeclarator, depth + 1);
    }
    return current;
  }

  private static DataType buildFunctionDefinitionFromSuffix(
      DataTypeManager manager, DataType returnType, String paramsText) {
    List<ParameterDefinition> arguments = new ArrayList<>();
    boolean varArgs = false;
    if (!paramsText.isEmpty() && !"void".equals(paramsText)) {
      List<String> items = GhidraCParserSupport.splitTopLevelCommaList(paramsText);
      for (int index = 0; index < items.size(); index++) {
        String rawItem = items.get(index).trim();
        if ("...".equals(rawItem) && index == items.size() - 1) {
          varArgs = true;
          continue;
        }
        ParsedParameter param = parseParameterDeclaration(manager, rawItem, index);
        arguments.add(new ParameterDefinitionImpl(param.name(), param.dataType(), null));
      }
    }
    FunctionDefinitionDataType definition =
        new FunctionDefinitionDataType(CategoryPath.ROOT, "anon_fn", manager);
    definition.setReturnType(returnType.clone(manager));
    definition.setArguments(arguments.toArray(ParameterDefinition[]::new));
    definition.setVarArgs(varArgs);
    GhidraCParserSupport.assignDeterministicAnonymousName(definition);
    return definition;
  }

  private static ExtractedDeclaratorName stripParameterIdentifier(String cleaned) {
    int firstDecl = GhidraCParserSupport.findFirstDeclaratorIndex(cleaned);
    if (firstDecl >= 0) {
      int open = cleaned.indexOf('(', firstDecl);
      if (open >= 0) {
        int close = GhidraCParserSupport.findMatchingParen(cleaned, open);
        if (close > open) {
          String inside = cleaned.substring(open + 1, close);
          int starPos = inside.lastIndexOf('*');
          if (starPos >= 0) {
            int idStart = starPos + 1;
            while (idStart < inside.length() && Character.isWhitespace(inside.charAt(idStart))) {
              idStart++;
            }
            int idEnd = idStart;
            while (idEnd < inside.length()
                && GhidraCParserSupport.isIdentifierPart(inside.charAt(idEnd))) {
              idEnd++;
            }
            if (idEnd > idStart && GhidraCParserSupport.isIdentifierStart(inside.charAt(idStart))) {
              String name = inside.substring(idStart, idEnd);
              String newInside = inside.substring(0, idStart) + inside.substring(idEnd);
              String abstractType =
                  cleaned.substring(0, open + 1) + newInside + cleaned.substring(close);
              return new ExtractedDeclaratorName(name, abstractType);
            }
          }
        }
      }
    }

    int scanEnd = cleaned.length();
    while (scanEnd > 0) {
      int trimmedEnd = scanEnd;
      while (trimmedEnd > 0 && Character.isWhitespace(cleaned.charAt(trimmedEnd - 1))) {
        trimmedEnd--;
      }
      if (trimmedEnd > 0 && cleaned.charAt(trimmedEnd - 1) == ']') {
        int openBracket = cleaned.lastIndexOf('[', trimmedEnd - 1);
        if (openBracket < 0) {
          break;
        }
        scanEnd = openBracket;
      } else {
        scanEnd = trimmedEnd;
        break;
      }
    }
    int nameStart = scanEnd;
    while (nameStart > 0 && GhidraCParserSupport.isIdentifierPart(cleaned.charAt(nameStart - 1))) {
      nameStart--;
    }
    if (nameStart < scanEnd
        && nameStart > 0
        && GhidraCParserSupport.isIdentifierStart(cleaned.charAt(nameStart))) {
      String name = cleaned.substring(nameStart, scanEnd);
      String prefix = cleaned.substring(0, nameStart).trim();
      String suffix = cleaned.substring(scanEnd).trim();
      if (!prefix.isEmpty()) {
        String abstractType = suffix.isEmpty() ? prefix : prefix + " " + suffix;
        return new ExtractedDeclaratorName(name, abstractType);
      }
    }
    return null;
  }

  private static int parsePositiveArrayCount(String countText, String declarator) {
    if (countText.isEmpty()) {
      throw new IllegalArgumentException(
          "unsized C array declarator is not supported: " + declarator);
    }
    try {
      int count =
          countText.startsWith("0x") || countText.startsWith("0X")
              ? Integer.parseInt(countText.substring(2), 16)
              : Integer.parseInt(countText);
      if (count <= 0) {
        throw new IllegalArgumentException("array count must be positive: " + count);
      }
      return count;
    } catch (NumberFormatException error) {
      throw new IllegalArgumentException("invalid array length in declarator: " + declarator, error);
    }
  }

  private static boolean isGroupedAbstractDeclarator(String inside) {
    if (inside.isEmpty()) {
      return false;
    }
    char first = inside.charAt(0);
    return first == '*' || first == '(' || first == '[';
  }

  private static boolean containsFunctionParameterSuffix(String abstractDeclarator) {
    int index = 0;
    while (index < abstractDeclarator.length()) {
      if (abstractDeclarator.charAt(index) == '(') {
        int close = GhidraCParserSupport.findMatchingParen(abstractDeclarator, index);
        if (close < 0) {
          return false;
        }
        String inside = abstractDeclarator.substring(index + 1, close).trim();
        if (!isGroupedAbstractDeclarator(inside) || containsFunctionParameterSuffix(inside)) {
          return true;
        }
        index = close + 1;
      } else {
        index++;
      }
    }
    return false;
  }

  private static String insertDeclaratorIdentifier(String abstractDeclarator, String identifier) {
    int open = abstractDeclarator.indexOf('(');
    if (open >= 0) {
      int close = GhidraCParserSupport.findMatchingParen(abstractDeclarator, open);
      if (close > open) {
        String inside = abstractDeclarator.substring(open + 1, close).trim();
        if (isGroupedAbstractDeclarator(inside)) {
          return abstractDeclarator.substring(0, open + 1)
              + insertDeclaratorIdentifier(inside, identifier)
              + abstractDeclarator.substring(close);
        }
      }
    }
    int index = 0;
    while (index < abstractDeclarator.length()
        && (abstractDeclarator.charAt(index) == '*'
            || Character.isWhitespace(abstractDeclarator.charAt(index)))) {
      index++;
    }
    return abstractDeclarator.substring(0, index)
        + identifier
        + abstractDeclarator.substring(index);
  }

  private static boolean containsImplicitUndefinedParameter(
      DataType dataType, String abstractDeclarator) {
    if (abstractDeclarator.contains("undefined")) {
      return false;
    }
    if (dataType instanceof Pointer pointer && pointer.getDataType() != null) {
      return containsImplicitUndefinedParameter(pointer.getDataType(), abstractDeclarator);
    }
    if (dataType instanceof FunctionDefinition functionDefinition) {
      for (ParameterDefinition parameter : functionDefinition.getArguments()) {
        DataType argType = parameter.getDataType();
        if (argType != null && "undefined".equals(argType.getName())) {
          return true;
        }
        if (containsImplicitUndefinedParameter(argType, abstractDeclarator)) {
          return true;
        }
      }
      return containsImplicitUndefinedParameter(
          functionDefinition.getReturnType(), abstractDeclarator);
    }
    return false;
  }

  private static Set<String> collectCompositeNames(StandAloneDataTypeManager scratch) {
    Set<String> names = new LinkedHashSet<>();
    Iterator<Composite> composites = scratch.getAllComposites();
    while (composites.hasNext()) {
      names.add(composites.next().getName());
    }
    return names;
  }

  private record ExtractedDeclaratorName(String name, String abstractType) {}

  private sealed interface DeclaratorSuffix {
    record ArraySuffix(int count) implements DeclaratorSuffix {}

    record FunctionSuffix(String params) implements DeclaratorSuffix {}
  }
}
