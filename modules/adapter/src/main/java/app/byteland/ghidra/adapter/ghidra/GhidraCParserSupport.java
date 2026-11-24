package app.byteland.ghidra.adapter.ghidra;

import ghidra.app.services.DataTypeQueryService;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataOrganization;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeDependencyException;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.util.InvalidNameException;
import ghidra.util.data.DataTypeParser;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.task.TaskMonitor;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Resolves C type declarations, multi-type C headers, and C function signatures in isolated
 * temporary {@link StandAloneDataTypeManager} instances before it writes to a program.
 */
public final class GhidraCParserSupport {
  private static final Set<String> CVR_QUALIFIERS =
      Set.of(
          "const",
          "volatile",
          "restrict",
          "__const",
          "__const__",
          "__volatile",
          "__volatile__",
          "__restrict",
          "__restrict__");

  private static final Set<String> RESTRICT_QUALIFIERS =
      Set.of("restrict", "__restrict", "__restrict__");

  private static final Set<String> COMMON_CALLING_CONVENTIONS =
      Set.of("__cdecl", "__stdcall", "__fastcall", "__thiscall", "__vectorcall", "cdecl", "stdcall");

  private static final String SYNTHETIC_TYPEDEF_NAME = "__ghidra_bridge_ctype";
  private static final Pattern INCLUDE_DIRECTIVE =
      Pattern.compile("(?m)^\\s*#\\s*include\\b");

  private GhidraCParserSupport() {}

  /**
   * Parsed C function signature ready for {@code ApplyFunctionSignatureCmd}.
   *
   * @param definition parsed function definition cloned for the target program manager
   * @param explicitCallingConvention true if the signature text contains an explicit convention name
   */
  public record ParsedFunctionSignature(
      FunctionDefinitionDataType definition, boolean explicitCallingConvention) {
    public ParsedFunctionSignature {
      Objects.requireNonNull(definition, "definition");
    }
  }

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
   * Resolves a C type string in {@code programDataTypeManager} and creates no orphan types on
   * failure.
   */
  public static DataType resolveCType(DataTypeManager programDataTypeManager, String declaration) {
    if (programDataTypeManager == null) {
      throw new IllegalArgumentException("program data type manager is required");
    }
    if (declaration == null || declaration.isBlank()) {
      throw new IllegalArgumentException("data type declaration must not be blank");
    }
    String trimmed = declaration.trim();
    if ("pointer".equals(trimmed)) {
      return GhidraDataTypeReferences.resolve(
          programDataTypeManager, app.byteland.ghidra.service.datatype.DataTypeReference.untypedPointer());
    }
    if (trimmed.indexOf(';') >= 0 || trimmed.indexOf('{') >= 0 || trimmed.indexOf('}') >= 0) {
      throw new IllegalArgumentException(
          "C type reference must be a single type expression without inline definitions: "
              + declaration);
    }

    String cleaned = stripQualifiers(trimmed);
    if (cleaned.isBlank()) {
      throw new IllegalArgumentException("data type declaration has no base type: " + declaration);
    }

    // Fast path for an undecorated absolute Ghidra data type path.
    if (cleaned.startsWith("/") && findFirstDeclaratorIndex(cleaned) < 0) {
      DataType byPath = GhidraDataTypeReferences.findByPath(programDataTypeManager, cleaned);
      if (byPath == null) {
        throw new IllegalArgumentException("unknown data type: " + cleaned);
      }
      return byPath;
    }

    int splitIndex = findFirstDeclaratorIndex(cleaned);
    String rawSpecifiers =
        splitIndex < 0 ? cleaned : cleaned.substring(0, splitIndex).trim();
    String abstractDeclarator =
        splitIndex < 0 ? "" : cleaned.substring(splitIndex).trim();
    if (rawSpecifiers.isBlank()) {
      throw new IllegalArgumentException("missing base type in declaration: " + declaration);
    }

    try (ScratchEnvironment env = ScratchEnvironment.open(programDataTypeManager)) {
      try {
        DataType baseType = resolveBaseSpecifier(env, rawSpecifiers);
        if (abstractDeclarator.isEmpty()) {
          return baseType;
        }
        return applyAbstractDeclarator(programDataTypeManager, baseType, abstractDeclarator, 0);
      } catch (IllegalArgumentException primaryError) {
        if (containsFunctionParameterSuffix(abstractDeclarator) && !rawSpecifiers.startsWith("/")) {
          DataType parsedViaCParser =
              tryResolveFunctionPointerViaCParser(env, rawSpecifiers, abstractDeclarator);
          if (parsedViaCParser != null) {
            return parsedViaCParser;
          }
        }
        throw primaryError;
      }
    }
  }

  /**
   * Parses a multi-declaration C header atomically and resolves all declared types into {@code
   * programDataTypeManager} under {@code categoryPath}.
   */
  public static List<DataType> parseCHeader(
      DataTypeManager programDataTypeManager, String source, String categoryPath) {
    if (programDataTypeManager == null) {
      throw new IllegalArgumentException("program data type manager is required");
    }
    if (source == null || source.isBlank()) {
      throw new IllegalArgumentException("C source must not be blank");
    }
    String withoutComments = maskCommentsAndStrings(source);
    if (INCLUDE_DIRECTIVE.matcher(withoutComments).find()) {
      throw new IllegalArgumentException(
          "C #include directives are not supported; provide self-contained declarations");
    }

    String normalizedCategory =
        categoryPath == null || categoryPath.isBlank() ? "/" : categoryPath.trim();
    if (!normalizedCategory.startsWith("/")) {
      normalizedCategory = "/" + normalizedCategory;
    }
    CategoryPath targetCategory = new CategoryPath(normalizedCategory);
    String sanitizedSource = stripTokens(source, RESTRICT_QUALIFIERS, false);

    try (ScratchEnvironment env = ScratchEnvironment.open(programDataTypeManager)) {
      CParser parser = new CParser(env.scratch(), true, env.cParserSubArchives());
      try {
        parser.parse(sanitizedSource);
      } catch (ParseException error) {
        throw new IllegalArgumentException(
            "C header parse failed: " + detailMessage(error, parser.getParseMessages()), error);
      }
      if (!parser.didParseSucceed()) {
        throw new IllegalArgumentException(
            "C header parse failed: " + nonBlankOr(parser.getParseMessages(), "syntax error"));
      }

      List<DataType> localTypes = collectDeclaredTypes(env.scratch(), parser, withoutComments);
      if (localTypes.isEmpty()) {
        throw new IllegalArgumentException("C source did not declare any data types");
      }

      localTypes = relocateScratchTypes(env.scratch(), localTypes, targetCategory);
      if (!CategoryPath.ROOT.equals(targetCategory)) {
        programDataTypeManager.createCategory(targetCategory);
      }

      List<DataType> resolved = new ArrayList<>(localTypes.size());
      Set<String> seenPaths = new LinkedHashSet<>();
      for (DataType candidate : localTypes) {
        normalizeAnonymousFunctionPointers(candidate);
        DataType committed =
            programDataTypeManager.resolve(candidate, DataTypeConflictHandler.REPLACE_HANDLER);
        if (seenPaths.add(committed.getPathName())) {
          resolved.add(committed);
        }
      }
      if (containsPointerToArrayDeclarator(withoutComments)) {
        resolved =
            repairHeaderPointerToArrayDeclarators(
                programDataTypeManager, targetCategory, withoutComments, resolved);
      }
      resolved.sort(Comparator.comparing(DataType::getPathName));
      return List.copyOf(resolved);
    }
  }

  /**
   * Parses a one-line C function prototype with {@link FunctionSignatureParser} and a {@link
   * CParser} fallback when parameters contain nested declarator parentheses.
   */
  public static ParsedFunctionSignature parseFunctionSignature(
      DataTypeManager programDataTypeManager, Function existingFunction, String signatureText) {
    if (programDataTypeManager == null) {
      throw new IllegalArgumentException("program data type manager is required");
    }
    if (signatureText == null || signatureText.isBlank()) {
      throw new IllegalArgumentException("function signature must not be blank");
    }
    String trimmed = signatureText.trim();
    if (trimmed.endsWith(";")) {
      trimmed = trimmed.substring(0, trimmed.length() - 1).trim();
    }
    if (trimmed.isEmpty() || trimmed.indexOf('{') >= 0 || trimmed.indexOf(';') >= 0) {
      throw new IllegalArgumentException("invalid function signature: " + signatureText);
    }

    String cleaned = normalizeTagKeywordsInSignature(programDataTypeManager, stripQualifiers(trimmed));
    boolean explicitCc = hasExplicitCallingConvention(programDataTypeManager, cleaned);

    try (ScratchEnvironment env = ScratchEnvironment.open(programDataTypeManager)) {
      FunctionSignatureParser signatureParser =
          new FunctionSignatureParser(env.scratch(), env.queryService());
      FunctionDefinitionDataType parsed = null;
      ParseException primaryFailure = null;
      if (!containsNestedParameterParens(cleaned) && !containsPointerToArrayDeclarator(cleaned)) {
        try {
          parsed =
              signatureParser.parse(
                  existingFunction == null ? null : existingFunction.getSignature(), cleaned);
        } catch (ParseException error) {
          primaryFailure = error;
        } catch (CancelledException error) {
          throw new IllegalArgumentException("function signature parse was cancelled", error);
        }
      }
      if (parsed == null) {
        parsed = parseSignatureFallback(env, cleaned, primaryFailure);
      }
      FunctionDefinitionDataType cloned =
          cloneFunctionDefinition(programDataTypeManager, parsed);
      return new ParsedFunctionSignature(cloned, explicitCc);
    }
  }

  private static FunctionDefinitionDataType parseSignatureFallback(
      ScratchEnvironment env, String cleanedSignature, ParseException primaryFailure) {
    // First try CParser in the isolated scratch manager.
    CParser parser = new CParser(env.scratch(), true, env.cParserSubArchives());
    try {
      DataType parsedTopLevel = parser.parse(cleanedSignature + ";");
      if (parser.didParseSucceed()) {
        DataType selected = parsedTopLevel;
        if (!(selected instanceof FunctionDefinition)) {
          String topName = extractTopLevelFunctionName(cleanedSignature);
          if (topName != null) {
            selected = parser.getFunctions().get(topName);
          }
        }
        if (selected instanceof FunctionDefinition definition) {
          FunctionDefinitionDataType result =
              new FunctionDefinitionDataType(definition, env.scratch());
          repairParameterDeclaratorsIfNeeded(env.programManager(), result, cleanedSignature);
          normalizeAnonymousFunctionPointers(result);
          return result;
        }
      }
    } catch (ParseException ignored) {
      // Try manual top-level signature decomposition below before this method reports failure.
    }

    FunctionDefinitionDataType decomposed =
        tryDecomposeFunctionSignature(env.programManager(), cleanedSignature);
    if (decomposed != null) {
      return decomposed;
    }
    String detail =
        primaryFailure != null
            ? detailMessage(primaryFailure, parser.getParseMessages())
            : nonBlankOr(parser.getParseMessages(), cleanedSignature);
    throw new IllegalArgumentException("invalid C function signature: " + detail, primaryFailure);
  }

  private static void repairParameterDeclaratorsIfNeeded(
      DataTypeManager programManager, FunctionDefinitionDataType result, String signature) {
    if (!containsPointerToArrayDeclarator(signature)) {
      return;
    }
    int openParen = findTopLevelParameterListOpen(signature);
    int closeParen = findMatchingParen(signature, openParen);
    if (openParen < 0 || closeParen < 0) {
      return;
    }
    List<String> rawParams = splitTopLevelCommaList(signature.substring(openParen + 1, closeParen));
    ParameterDefinition[] args = result.getArguments();
    int limit = Math.min(args.length, rawParams.size());
    for (int i = 0; i < limit; i++) {
      String rawParam = rawParams.get(i).trim();
      if ("...".equals(rawParam) || "void".equals(rawParam)) {
        continue;
      }
      if (containsPointerToArrayDeclarator(rawParam)) {
        ParsedParameter parsed = parseParameterDeclaration(programManager, rawParam, i);
        args[i] = new ParameterDefinitionImpl(parsed.name(), parsed.dataType(), null);
      }
    }
    result.setArguments(args);
  }

  private static FunctionDefinitionDataType tryDecomposeFunctionSignature(
      DataTypeManager programManager, String signature) {
    int openParen = findTopLevelParameterListOpen(signature);
    if (openParen <= 0) {
      return null;
    }
    int closeParen = findMatchingParen(signature, openParen);
    if (closeParen != signature.length() - 1) {
      return null;
    }
    String header = signature.substring(0, openParen).trim();
    int nameStart = header.length();
    while (nameStart > 0 && isIdentifierPart(header.charAt(nameStart - 1))) {
      nameStart--;
    }
    if (nameStart == header.length() || nameStart == 0) {
      return null;
    }
    String functionName = header.substring(nameStart).trim();
    String returnSpec = header.substring(0, nameStart).trim();
    String callingConvention = null;
    for (String candidateCc : collectCallingConventionTokens(programManager)) {
      String suffix = " " + candidateCc;
      if (returnSpec.endsWith(suffix)) {
        callingConvention = normalizeCallingConventionName(programManager, candidateCc);
        returnSpec = returnSpec.substring(0, returnSpec.length() - suffix.length()).trim();
        break;
      }
    }
    DataType returnType = resolveCType(programManager, returnSpec);
    String paramsBody = signature.substring(openParen + 1, closeParen).trim();
    List<ParameterDefinition> parameters = new ArrayList<>();
    boolean varArgs = false;
    if (!paramsBody.isEmpty() && !"void".equals(paramsBody)) {
      List<String> rawParams = splitTopLevelCommaList(paramsBody);
      for (int index = 0; index < rawParams.size(); index++) {
        String item = rawParams.get(index).trim();
        if ("...".equals(item) && index == rawParams.size() - 1) {
          varArgs = true;
          continue;
        }
        ParsedParameter param = parseParameterDeclaration(programManager, item, index);
        parameters.add(new ParameterDefinitionImpl(param.name(), param.dataType(), null));
      }
    }
    FunctionDefinitionDataType definition =
        new FunctionDefinitionDataType(CategoryPath.ROOT, functionName, programManager);
    definition.setReturnType(returnType);
    definition.setArguments(parameters.toArray(ParameterDefinition[]::new));
    definition.setVarArgs(varArgs);
    if (callingConvention != null) {
      try {
        definition.setCallingConvention(callingConvention);
      } catch (ghidra.util.exception.InvalidInputException error) {
        throw new IllegalArgumentException(
            "unknown calling convention in signature: " + callingConvention, error);
      }
    }
    return definition;
  }

  private static FunctionDefinitionDataType cloneFunctionDefinition(
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
      } catch (ghidra.util.exception.InvalidInputException error) {
        throw new IllegalArgumentException("invalid calling convention: " + cc, error);
      }
    }
    return copy;
  }

  private static DataType tryResolveFunctionPointerViaCParser(
      ScratchEnvironment env, String rawSpecifiers, String abstractDeclarator) {
    String normalizedSpecs = resolveVerifiedTagSpecifier(env.programManager(), rawSpecifiers, true);
    String namedDeclarator = insertDeclaratorIdentifier(abstractDeclarator, SYNTHETIC_TYPEDEF_NAME);
    String statement = "typedef " + normalizedSpecs + " " + namedDeclarator + ";";
    Set<String> preExistingComposites = collectCompositeNames(env.scratch());
    CParser parser = new CParser(env.scratch(), true, env.cParserSubArchives());
    try {
      parser.parse(statement);
    } catch (ParseException error) {
      return null;
    }
    if (!parser.didParseSucceed()) {
      return null;
    }
    // Reject accidental empty forward-declared structs fabricated by CParser for unknown names.
    for (String compositeName : collectCompositeNames(env.scratch())) {
      if (!preExistingComposites.contains(compositeName)) {
        throw new IllegalArgumentException("unknown composite data type: " + compositeName);
      }
    }
    DataType typedefCandidate = parser.getTypes().get(SYNTHETIC_TYPEDEF_NAME);
    if (!(typedefCandidate instanceof TypeDef typeDef)) {
      typedefCandidate = env.scratch().getDataType(CategoryPath.ROOT, SYNTHETIC_TYPEDEF_NAME);
    }
    if (!(typedefCandidate instanceof TypeDef resolvedTypeDef)) {
      return null;
    }
    DataType unwrapped = resolvedTypeDef.getDataType();
    if (containsImplicitUndefinedParameter(unwrapped, abstractDeclarator)) {
      return null;
    }
    normalizeAnonymousFunctionPointers(unwrapped);
    DataType cloned = detachFromScratch(env.programManager(), unwrapped);
    if (cloned instanceof Pointer pointer) {
      GhidraDataTypeReferences.requirePointerIdentityCanBePreserved(env.programManager(), pointer);
    }
    return cloned;
  }

  private static DataType detachFromScratch(DataTypeManager programManager, DataType dataType) {
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
          ? new ghidra.program.model.data.PointerDataType(programManager)
          : programManager.getPointer(pointee);
    }
    if (dataType instanceof ghidra.program.model.data.Array array) {
      DataType element = detachFromScratch(programManager, array.getDataType());
      return GhidraDataTypeReferences.buildArrayDataType(
          element, array.getNumElements(), programManager);
    }
    if (dataType instanceof TypeDef typeDef) {
      DataType existing = GhidraDataTypeReferences.findByPath(programManager, typeDef.getPathName());
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
      FunctionDefinitionDataType detached = cloneFunctionDefinition(programManager, functionDefinition);
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

  private static DataType resolveBaseSpecifier(ScratchEnvironment env, String rawSpecifiers) {
    DataTypeManager programManager = env.programManager();
    String trimmed = rawSpecifiers.trim();
    if (trimmed.startsWith("/")) {
      DataType byPath = GhidraDataTypeReferences.findByPath(programManager, trimmed);
      if (byPath == null) {
        throw new IllegalArgumentException("unknown data type: " + trimmed);
      }
      return byPath;
    }

    DataType tagMatch = matchExplicitTagType(programManager, trimmed);
    if (tagMatch != null) {
      return tagMatch;
    }

    // Check unambiguous single-token program data types before DataTypeParser runs.
    if (isSingleIdentifier(trimmed)) {
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
      return detachFromScratch(programManager, parsed);
    } catch (InvalidDataTypeException | CancelledException error) {
      if (isSingleIdentifier(trimmed)) {
        DataType stdintMatch = env.stdintType(trimmed);
        if (stdintMatch != null) {
          return detachFromScratch(programManager, stdintMatch);
        }
      }
      throw new IllegalArgumentException("unknown C data type: " + trimmed, error);
    }
  }

  private static DataType matchExplicitTagType(DataTypeManager programManager, String specifiers) {
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

  private static String resolveVerifiedTagSpecifier(
      DataTypeManager programManager, String specifiers, boolean forCParser) {
    DataType matched = matchExplicitTagType(programManager, specifiers.trim());
    if (matched == null) {
      return specifiers;
    }
    return forCParser ? matched.getName() : matched.getPathName();
  }

  private static DataType applyAbstractDeclarator(
      DataTypeManager manager, DataType baseType, String declarator, int depth) {
    if (depth > 32) {
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
      int closeParen = findMatchingParen(text, index);
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
        int count = parsePositiveArrayCount(countText, declarator);
        suffixes.add(new DeclaratorSuffix.ArraySuffix(count));
        index = closeBracket + 1;
      } else if (ch == '(') {
        int closeParen = findMatchingParen(text, index);
        if (closeParen < 0) {
          throw new IllegalArgumentException("unclosed '(' in C declarator: " + declarator);
        }
        String paramsText = text.substring(index + 1, closeParen).trim();
        suffixes.add(new DeclaratorSuffix.FunctionSuffix(paramsText));
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
      DeclaratorSuffix suffix = suffixes.get(s);
      switch (suffix) {
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
      List<String> items = splitTopLevelCommaList(paramsText);
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
    assignDeterministicAnonymousName(definition);
    return definition;
  }

  private record ParsedParameter(String name, DataType dataType) {}

  private static ParsedParameter parseParameterDeclaration(
      DataTypeManager manager, String rawDeclaration, int index) {
    String cleaned = stripQualifiers(rawDeclaration.trim());
    if (cleaned.isEmpty()) {
      throw new IllegalArgumentException("empty parameter at index " + index);
    }
    // Try to resolve directly as an unnamed abstract type first.
    try {
      DataType direct = resolveCType(manager, cleaned);
      return new ParsedParameter(null, direct);
    } catch (IllegalArgumentException ignored) {
      // Fall through to strip parameter identifier from named parameter declaration.
    }

    ExtractedDeclaratorName extracted = stripParameterIdentifier(cleaned);
    if (extracted == null) {
      throw new IllegalArgumentException("invalid C parameter declaration: " + rawDeclaration);
    }
    DataType resolved = resolveCType(manager, extracted.abstractType());
    return new ParsedParameter(extracted.name(), resolved);
  }

  private record ExtractedDeclaratorName(String name, String abstractType) {}

  private static ExtractedDeclaratorName stripParameterIdentifier(String cleaned) {
    // Case 1: identifier inside parenthesized declarator such as void (*cb)(int) or int (*arr)[4].
    int firstDecl = findFirstDeclaratorIndex(cleaned);
    if (firstDecl >= 0) {
      int open = cleaned.indexOf('(', firstDecl);
      if (open >= 0) {
        int close = findMatchingParen(cleaned, open);
        if (close > open) {
          String inside = cleaned.substring(open + 1, close);
          int starPos = inside.lastIndexOf('*');
          if (starPos >= 0) {
            int idStart = starPos + 1;
            while (idStart < inside.length() && Character.isWhitespace(inside.charAt(idStart))) {
              idStart++;
            }
            int idEnd = idStart;
            while (idEnd < inside.length() && isIdentifierPart(inside.charAt(idEnd))) {
              idEnd++;
            }
            if (idEnd > idStart && isIdentifierStart(inside.charAt(idStart))) {
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

    // Case 2: final identifier before optional [N] suffixes, such as const char *buf or int a[4].
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
    while (nameStart > 0 && isIdentifierPart(cleaned.charAt(nameStart - 1))) {
      nameStart--;
    }
    if (nameStart < scanEnd && nameStart > 0 && isIdentifierStart(cleaned.charAt(nameStart))) {
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
        int close = findMatchingParen(abstractDeclarator, index);
        if (close < 0) {
          return false;
        }
        String inside = abstractDeclarator.substring(index + 1, close).trim();
        if (!isGroupedAbstractDeclarator(inside)) {
          return true;
        }
        if (containsFunctionParameterSuffix(inside)) {
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
      int close = findMatchingParen(abstractDeclarator, open);
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

  private static void normalizeAnonymousFunctionPointers(DataType dataType) {
    if (dataType instanceof Pointer pointer && pointer.getDataType() != null) {
      normalizeAnonymousFunctionPointers(pointer.getDataType());
    } else if (dataType instanceof ghidra.program.model.data.Array array
        && array.getDataType() != null) {
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

  private static void assignDeterministicAnonymousName(FunctionDefinition definition) {
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

  private static List<DataType> collectDeclaredTypes(
      StandAloneDataTypeManager scratch, CParser parser, String maskedSource) {
    Set<String> topLevelFunctionNames = extractTopLevelDeclaredIdentifiers(maskedSource);
    List<DataType> rawCandidates = new ArrayList<>();
    rawCandidates.addAll(parser.getEnums().values());
    rawCandidates.addAll(parser.getComposites().values());
    rawCandidates.addAll(parser.getTypes().values());
    for (Map.Entry<String, DataType> entry : parser.getFunctions().entrySet()) {
      if (topLevelFunctionNames.contains(entry.getKey())) {
        rawCandidates.add(entry.getValue());
      }
    }

    List<DataType> collected = new ArrayList<>(rawCandidates.size());
    Set<String> seenPaths = new LinkedHashSet<>();
    Set<String> seenNames = new LinkedHashSet<>();
    for (DataType raw : rawCandidates) {
      if (raw == null || raw.getName().startsWith("anon_fn_")) {
        continue;
      }
      DataType live = scratch.getDataType(raw.getDataTypePath());
      DataType target = live != null ? live : raw;
      if (target instanceof TypeDef typeDef
          && typeDef.getDataType() != null
          && typeDef.getName().equals(typeDef.getDataType().getName())
          && seenNames.contains(typeDef.getName())) {
        continue;
      }
      if (!seenPaths.add(target.getPathName())) {
        continue;
      }
      if (!seenNames.add(target.getName())) {
        throw new IllegalArgumentException(
            "duplicate C declaration name in target category: " + target.getName());
      }
      collected.add(target);
    }
    return collected;
  }

  private static String extractTopLevelFunctionName(String signature) {
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

  private static Set<String> extractTopLevelDeclaredIdentifiers(String maskedSource) {
    Set<String> names = new LinkedHashSet<>();
    int braceDepth = 0;
    int parenDepth = 0;
    for (int i = 0; i < maskedSource.length(); i++) {
      char ch = maskedSource.charAt(i);
      if (ch == '{') {
        braceDepth++;
      } else if (ch == '}') {
        braceDepth = Math.max(0, braceDepth - 1);
      } else if (ch == '(') {
        if (braceDepth == 0 && parenDepth == 0) {
          int end = i;
          while (end > 0 && Character.isWhitespace(maskedSource.charAt(end - 1))) {
            end--;
          }
          int start = end;
          while (start > 0 && isIdentifierPart(maskedSource.charAt(start - 1))) {
            start--;
          }
          if (start < end && isIdentifierStart(maskedSource.charAt(start))) {
            names.add(maskedSource.substring(start, end));
          }
        }
        parenDepth++;
      } else if (ch == ')') {
        parenDepth = Math.max(0, parenDepth - 1);
      }
    }
    return names;
  }

  private static Set<String> collectCompositeNames(StandAloneDataTypeManager scratch) {
    Set<String> names = new LinkedHashSet<>();
    Iterator<Composite> composites = scratch.getAllComposites();
    while (composites.hasNext()) {
      names.add(composites.next().getName());
    }
    return names;
  }

  private static List<DataType> relocateScratchTypes(
      StandAloneDataTypeManager scratch, List<DataType> types, CategoryPath targetCategory) {
    List<DataType> relocated = new ArrayList<>(types.size());
    for (DataType dataType : types) {
      if (targetCategory.equals(dataType.getCategoryPath())) {
        relocated.add(dataType);
        continue;
      }
      try {
        DataType existing = scratch.getDataType(targetCategory, dataType.getName());
        if (existing != null && existing != dataType && !types.contains(existing)) {
          try {
            DataType replaced = scratch.replaceDataType(existing, dataType, false);
            if (!targetCategory.equals(replaced.getCategoryPath())) {
              replaced.setCategoryPath(targetCategory);
            }
            relocated.add(replaced);
            continue;
          } catch (DataTypeDependencyException ignored) {
            scratch.remove(existing);
          }
        }
        dataType.setCategoryPath(targetCategory);
        relocated.add(dataType);
      } catch (DuplicateNameException error) {
        throw new IllegalArgumentException(
            "duplicate C declaration name in target category: " + dataType.getName(), error);
      }
    }
    return relocated;
  }

  private static List<DataType> repairHeaderPointerToArrayDeclarators(
      DataTypeManager programManager,
      CategoryPath targetCategory,
      String maskedSource,
      List<DataType> resolved) {
    Map<String, String> compositeBodies = extractCompositeBodies(maskedSource);
    Map<String, DataType> typedefReplacements = new LinkedHashMap<>();
    Map<String, String> functionStatements = new LinkedHashMap<>();
    for (String statement : splitTopLevelStatements(maskedSource)) {
      String trimmed = statement.trim();
      if (!containsPointerToArrayDeclarator(trimmed)) {
        continue;
      }
      if (trimmed.startsWith("typedef ") && trimmed.indexOf('{') < 0) {
        String body = trimmed.substring("typedef".length()).trim();
        ParsedParameter parsed = parseParameterDeclaration(programManager, body, 0);
        if (parsed.name() != null) {
          typedefReplacements.put(parsed.name(), parsed.dataType());
        }
      } else if (trimmed.indexOf('{') < 0) {
        String fnName = extractTopLevelFunctionName(trimmed);
        if (fnName != null) {
          functionStatements.put(fnName, trimmed);
        }
      }
    }

    List<DataType> updated = new ArrayList<>(resolved.size());
    for (DataType item : resolved) {
      if (item instanceof Composite composite) {
        String body = compositeBodies.get(composite.getName());
        if (body != null && containsPointerToArrayDeclarator(body)) {
          repairCompositePointerToArrayFields(programManager, composite, body);
        }
        updated.add(item);
      } else if (item instanceof TypeDef typeDef
          && typedefReplacements.containsKey(typeDef.getName())) {
        TypedefDataType replacement =
            new TypedefDataType(
                targetCategory,
                typeDef.getName(),
                typedefReplacements.get(typeDef.getName()),
                programManager);
        updated.add(
            programManager.resolve(replacement, DataTypeConflictHandler.REPLACE_HANDLER));
      } else if (item instanceof FunctionDefinition fnDef
          && functionStatements.containsKey(fnDef.getName())) {
        String rawSig =
            normalizeTagKeywordsInSignature(
                programManager, stripQualifiers(functionStatements.get(fnDef.getName())));
        FunctionDefinitionDataType copy =
            new FunctionDefinitionDataType(fnDef, programManager);
        copy.setCategoryPath(targetCategory);
        repairParameterDeclaratorsIfNeeded(programManager, copy, rawSig);
        updated.add(programManager.resolve(copy, DataTypeConflictHandler.REPLACE_HANDLER));
      } else {
        updated.add(item);
      }
    }
    return updated;
  }

  private static void repairCompositePointerToArrayFields(
      DataTypeManager programManager, Composite composite, String body) {
    Map<String, DataType> repairedByField = new LinkedHashMap<>();
    for (String statement : splitTopLevelStatements(body)) {
      String trimmed = statement.trim();
      if (trimmed.isEmpty() || !containsPointerToArrayDeclarator(trimmed)) {
        continue;
      }
      String normalized = normalizeTagKeywordsInSignature(programManager, stripQualifiers(trimmed));
      ParsedParameter parsed = parseParameterDeclaration(programManager, normalized, 0);
      if (parsed.name() != null) {
        repairedByField.put(parsed.name(), parsed.dataType());
      }
    }
    if (repairedByField.isEmpty()) {
      return;
    }
    if (composite instanceof Structure structure) {
      StructureDataType aligned =
          new StructureDataType(
              structure.getCategoryPath(), structure.getName(), 0, programManager);
      aligned.setPackingEnabled(true);
      for (DataTypeComponent comp : structure.getDefinedComponents()) {
        String fieldName = comp.getFieldName();
        DataType dt =
            fieldName != null && repairedByField.containsKey(fieldName)
                ? repairedByField.get(fieldName)
                : comp.getDataType();
        aligned.add(dt, fieldName, comp.getComment());
      }
      if (structure.isPackingEnabled()) {
        structure.replaceWith(aligned);
      } else {
        StructureDataType fixed =
            new StructureDataType(
                structure.getCategoryPath(),
                structure.getName(),
                aligned.getLength(),
                programManager);
        for (DataTypeComponent comp : aligned.getDefinedComponents()) {
          fixed.replaceAtOffset(
              comp.getOffset(),
              comp.getDataType(),
              comp.getLength(),
              comp.getFieldName(),
              comp.getComment());
        }
        structure.replaceWith(fixed);
      }
    } else if (composite instanceof Union union) {
      UnionDataType rebuilt =
          new UnionDataType(union.getCategoryPath(), union.getName(), programManager);
      rebuilt.setPackingEnabled(union.isPackingEnabled());
      for (DataTypeComponent comp : union.getComponents()) {
        String fieldName = comp.getFieldName();
        DataType dt =
            fieldName != null && repairedByField.containsKey(fieldName)
                ? repairedByField.get(fieldName)
                : comp.getDataType();
        rebuilt.add(dt, fieldName, comp.getComment());
      }
      union.replaceWith(rebuilt);
    }
  }

  private static Map<String, String> extractCompositeBodies(String maskedSource) {
    Map<String, String> bodies = new LinkedHashMap<>();
    int index = 0;
    while (index < maskedSource.length()) {
      if (isIdentifierStart(maskedSource.charAt(index))) {
        int end = index + 1;
        while (end < maskedSource.length() && isIdentifierPart(maskedSource.charAt(end))) {
          end++;
        }
        String token = maskedSource.substring(index, end);
        if ("struct".equals(token) || "union".equals(token)) {
          int cursor = end;
          while (cursor < maskedSource.length()
              && Character.isWhitespace(maskedSource.charAt(cursor))) {
            cursor++;
          }
          String tagName = null;
          if (cursor < maskedSource.length() && isIdentifierStart(maskedSource.charAt(cursor))) {
            int tagEnd = cursor + 1;
            while (tagEnd < maskedSource.length()
                && isIdentifierPart(maskedSource.charAt(tagEnd))) {
              tagEnd++;
            }
            tagName = maskedSource.substring(cursor, tagEnd);
            cursor = tagEnd;
            while (cursor < maskedSource.length()
                && Character.isWhitespace(maskedSource.charAt(cursor))) {
              cursor++;
            }
          }
          if (cursor < maskedSource.length() && maskedSource.charAt(cursor) == '{') {
            int closeBrace = findMatchingBrace(maskedSource, cursor);
            if (closeBrace > cursor) {
              String body = maskedSource.substring(cursor + 1, closeBrace);
              if (tagName != null) {
                bodies.put(tagName, body);
              }
              int after = closeBrace + 1;
              while (after < maskedSource.length()
                  && Character.isWhitespace(maskedSource.charAt(after))) {
                after++;
              }
              if (after < maskedSource.length()
                  && isIdentifierStart(maskedSource.charAt(after))) {
                int aliasEnd = after + 1;
                while (aliasEnd < maskedSource.length()
                    && isIdentifierPart(maskedSource.charAt(aliasEnd))) {
                  aliasEnd++;
                }
                bodies.putIfAbsent(maskedSource.substring(after, aliasEnd), body);
              }
              index = closeBrace + 1;
              continue;
            }
          }
        }
        index = end;
      } else {
        index++;
      }
    }
    return bodies;
  }

  private static int findMatchingBrace(String text, int openIndex) {
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

  private static List<String> splitTopLevelStatements(String source) {
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

  private static String normalizeTagKeywordsInSignature(
      DataTypeManager programManager, String signature) {
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

  private static boolean hasExplicitCallingConvention(
      DataTypeManager programManager, String signature) {
    int openParen = findTopLevelParameterListOpen(signature);
    String prefix = openParen > 0 ? signature.substring(0, openParen) : signature;
    Set<String> conventions = collectCallingConventionTokens(programManager);
    int index = 0;
    while (index < prefix.length()) {
      if (isIdentifierStart(prefix.charAt(index))) {
        int end = index + 1;
        while (end < prefix.length() && isIdentifierPart(prefix.charAt(end))) {
          end++;
        }
        if (conventions.contains(prefix.substring(index, end))) {
          return true;
        }
        index = end;
      } else {
        index++;
      }
    }
    return false;
  }

  private static Set<String> collectCallingConventionTokens(DataTypeManager programManager) {
    Set<String> conventions = new LinkedHashSet<>(COMMON_CALLING_CONVENTIONS);
    conventions.addAll(programManager.getKnownCallingConventionNames());
    return conventions;
  }

  private static String normalizeCallingConventionName(
      DataTypeManager programManager, String token) {
    if (programManager.getKnownCallingConventionNames().contains(token)) {
      return token;
    }
    String prefixed = "__" + token;
    if (programManager.getKnownCallingConventionNames().contains(prefixed)) {
      return prefixed;
    }
    return token;
  }

  private static boolean containsNestedParameterParens(String signature) {
    int openParen = findTopLevelParameterListOpen(signature);
    if (openParen < 0) {
      return false;
    }
    int closeParen = findMatchingParen(signature, openParen);
    if (closeParen < 0) {
      return true;
    }
    return signature.substring(openParen + 1, closeParen).indexOf('(') >= 0;
  }

  private static boolean containsPointerToArrayDeclarator(String text) {
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

  private static int findTopLevelParameterListOpen(String signature) {
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

  private static List<String> splitTopLevelCommaList(String body) {
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

  private static int findFirstDeclaratorIndex(String cleaned) {
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

  private static int findMatchingParen(String text, int openIndex) {
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
      pathAllowedHere =
          preserveLeadingCategoryPath && (ch == '(' || ch == ',' || ch == ';');
      index++;
    }
    return out.toString();
  }

  private static String maskCommentsAndStrings(String input) {
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

  private static boolean isSingleIdentifier(String text) {
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

  private static boolean isIdentifierStart(char ch) {
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_' || ch == '$';
  }

  private static boolean isIdentifierPart(char ch) {
    return isIdentifierStart(ch) || (ch >= '0' && ch <= '9');
  }

  private static String detailMessage(Throwable error, String parseMessages) {
    String parseText = parseMessages == null ? "" : parseMessages.trim();
    if (!parseText.isEmpty()) {
      return parseText;
    }
    String message = error.getMessage();
    return message == null || message.isBlank() ? error.getClass().getSimpleName() : message;
  }

  private static String nonBlankOr(String candidate, String fallback) {
    return candidate == null || candidate.isBlank() ? fallback : candidate.trim();
  }

  private sealed interface DeclaratorSuffix {
    record ArraySuffix(int count) implements DeclaratorSuffix {}

    record FunctionSuffix(String params) implements DeclaratorSuffix {}
  }

  private static final class ScratchEnvironment implements AutoCloseable {
    private final DataTypeManager programManager;
    private final StandAloneDataTypeManager scratch;
    private final StandAloneDataTypeManager stdintArchive;
    private final int scratchTx;

    private ScratchEnvironment(
        DataTypeManager programManager,
        StandAloneDataTypeManager scratch,
        StandAloneDataTypeManager stdintArchive,
        int scratchTx) {
      this.programManager = programManager;
      this.scratch = scratch;
      this.stdintArchive = stdintArchive;
      this.scratchTx = scratchTx;
    }

    static ScratchEnvironment open(DataTypeManager programManager) {
      DataOrganization organization = programManager.getDataOrganization();
      StandAloneDataTypeManager stdint = buildStdintArchive(organization);
      StandAloneDataTypeManager scratch =
          new StandAloneDataTypeManager("c_parser_scratch", organization);
      int tx = scratch.startTransaction("parse_c");
      return new ScratchEnvironment(programManager, scratch, stdint, tx);
    }

    DataTypeManager programManager() {
      return programManager;
    }

    StandAloneDataTypeManager scratch() {
      return scratch;
    }

    DataType stdintType(String name) {
      return stdintArchive.getDataType(CategoryPath.ROOT, name);
    }

    DataTypeManager[] cParserSubArchives() {
      return new DataTypeManager[] {
        BuiltInDataTypeManager.getDataTypeManager(), programManager, stdintArchive
      };
    }

    DataTypeQueryService queryService() {
      List<DataTypeManager> managers =
          List.of(programManager, BuiltInDataTypeManager.getDataTypeManager(), stdintArchive);
      return new DataTypeQueryService() {
        @Override
        public List<DataType> getSortedDataTypeList() {
          List<DataType> all = new ArrayList<>();
          for (DataTypeManager manager : managers) {
            manager.getAllDataTypes(all);
          }
          return all;
        }

        @Override
        public List<CategoryPath> getSortedCategoryPathList() {
          return List.of(CategoryPath.ROOT);
        }

        @Override
        @SuppressWarnings({"deprecation", "removal"})
        public DataType getDataType(String filterText) {
          if (filterText == null || filterText.isBlank()) {
            return null;
          }
          if (filterText.startsWith("/")) {
            for (DataTypeManager manager : managers) {
              DataType byPath = manager.getDataType(filterText);
              if (byPath != null) return byPath;
            }
          }
          for (DataTypeManager manager : managers) {
            List<DataType> matches = new ArrayList<>();
            manager.findDataTypes(filterText, matches);
            if (!matches.isEmpty()) {
              return matches.getFirst();
            }
          }
          return null;
        }

        @Override
        public DataType promptForDataType(String filterText) {
          return getDataType(filterText);
        }

        @Override
        public List<DataType> findDataTypes(String name, TaskMonitor monitor) {
          List<DataType> matches = new ArrayList<>();
          for (DataTypeManager manager : managers) {
            manager.findDataTypes(name, matches);
            if (!matches.isEmpty()) {
              return matches;
            }
          }
          return matches;
        }

        @Override
        public List<DataType> getDataTypesByPath(DataTypePath path) {
          List<DataType> matches = new ArrayList<>();
          for (DataTypeManager manager : managers) {
            DataType found = manager.getDataType(path);
            if (found != null) {
              matches.add(found);
            }
          }
          return matches;
        }

        @Override
        public DataType getProgramDataTypeByPath(DataTypePath path) {
          return programManager.getDataType(path);
        }
      };
    }

    @Override
    public void close() {
      try {
        scratch.endTransaction(scratchTx, false);
      } finally {
        try {
          scratch.close();
        } finally {
          stdintArchive.close();
        }
      }
    }

    private static StandAloneDataTypeManager buildStdintArchive(DataOrganization organization) {
      StandAloneDataTypeManager archive =
          new StandAloneDataTypeManager("c_std_types", organization);
      int tx = archive.startTransaction("init_std_types");
      boolean ok = false;
      try {
        int pointerSize = Math.max(organization.getPointerSize(), 1);
        Map<String, DataType> definitions =
            Map.ofEntries(
                Map.entry("int8_t", AbstractIntegerDataType.getSignedDataType(1, archive)),
                Map.entry("uint8_t", AbstractIntegerDataType.getUnsignedDataType(1, archive)),
                Map.entry("int16_t", AbstractIntegerDataType.getSignedDataType(2, archive)),
                Map.entry("uint16_t", AbstractIntegerDataType.getUnsignedDataType(2, archive)),
                Map.entry("int32_t", AbstractIntegerDataType.getSignedDataType(4, archive)),
                Map.entry("uint32_t", AbstractIntegerDataType.getUnsignedDataType(4, archive)),
                Map.entry("int64_t", AbstractIntegerDataType.getSignedDataType(8, archive)),
                Map.entry("uint64_t", AbstractIntegerDataType.getUnsignedDataType(8, archive)),
                Map.entry(
                    "size_t", AbstractIntegerDataType.getUnsignedDataType(pointerSize, archive)),
                Map.entry(
                    "ssize_t", AbstractIntegerDataType.getSignedDataType(pointerSize, archive)),
                Map.entry(
                    "uintptr_t",
                    AbstractIntegerDataType.getUnsignedDataType(pointerSize, archive)),
                Map.entry(
                    "intptr_t", AbstractIntegerDataType.getSignedDataType(pointerSize, archive)),
                Map.entry(
                    "ptrdiff_t", AbstractIntegerDataType.getSignedDataType(pointerSize, archive)));
        for (Map.Entry<String, DataType> entry : definitions.entrySet()) {
          archive.addDataType(
              new TypedefDataType(CategoryPath.ROOT, entry.getKey(), entry.getValue(), archive),
              DataTypeConflictHandler.DEFAULT_HANDLER);
        }
        ok = true;
      } finally {
        archive.endTransaction(tx, ok);
      }
      return archive;
    }
  }
}
