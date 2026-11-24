package app.byteland.ghidra.adapter.ghidra;

import app.byteland.ghidra.service.datatype.DataTypeAlreadyExistsException;
import app.byteland.ghidra.service.datatype.DataTypeMutationValidationException;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.cparser.C.TokenMgrError;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeDependencyException;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.InvalidDataTypeException;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.util.data.DataTypeParser;
import ghidra.util.data.DataTypeParser.AllowedDataTypes;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.CRC32;

public final class GhidraCTypeParser {
  private static final String SYNTHETIC_DECL_NAME = "__bridge_decl";
  private static final String PATH_PLACEHOLDER_PREFIX = "__bridge_path_";
  private static final CategoryPath FUNCTIONS_CATEGORY = new CategoryPath("/functions");

  private static final Set<String> C_QUALIFIERS =
      Set.of("const", "volatile", "restrict", "__restrict", "__restrict__", "_Atomic");

  private static final Set<String> C_TAG_KEYWORDS = Set.of("struct", "union", "enum");

  private static final Set<String> C_KEYWORDS_AND_BUILTINS =
      Set.of(
          "void",
          "char",
          "short",
          "int",
          "long",
          "float",
          "double",
          "signed",
          "unsigned",
          "bool",
          "_Bool",
          "__int8",
          "__int16",
          "__int32",
          "__int64",
          "pointer",
          "typedef",
          "struct",
          "union",
          "enum",
          "const",
          "volatile",
          "restrict",
          "__restrict",
          "__restrict__",
          "_Atomic",
          "inline",
          "__inline",
          "__inline__",
          "extern",
          "static",
          "_Noreturn",
          "__noreturn");

  private static final Set<String> COMMON_CALLING_CONVENTIONS =
      Set.of(
          "__cdecl",
          "_cdecl",
          "__stdcall",
          "_stdcall",
          "__fastcall",
          "_fastcall",
          "__thiscall",
          "_thiscall",
          "__vectorcall",
          "_vectorcall",
          "__regparm");

  public record ParsedPrototype(
      String name,
      DataType returnType,
      List<ParameterDefinition> parameters,
      String callingConvention,
      boolean hasVarArgs,
      boolean hasNoReturn) {}

  private record SubstitutedInput(String text, Map<String, DataType> placeholders) {}

  private GhidraCTypeParser() {}

  public static DataType resolveExpression(
      DataTypeManager manager, String rawExpression, int depth) {
    GhidraDataTypeReferences.requireCanDescend(depth);
    if (rawExpression == null) {
      throw new IllegalArgumentException("data type expression is required");
    }
    String trimmed = rawExpression.trim();
    if (trimmed.isEmpty()) {
      throw new IllegalArgumentException("data type expression must not be empty");
    }
    if (trimmed.indexOf(';') >= 0 || trimmed.indexOf('{') >= 0 || trimmed.indexOf('}') >= 0) {
      throw new IllegalArgumentException(
          "data type expression must not contain declarations or composite bodies: "
              + rawExpression);
    }
    if ("pointer".equals(trimmed)) {
      return GhidraDataTypeReferences.resolveUntypedPointer(manager);
    }
    if (isPlainCategoryPath(trimmed)) {
      DataType direct = GhidraDataTypeReferences.findByPath(manager, trimmed);
      if (direct == null) {
        throw new IllegalArgumentException("unknown data type: " + trimmed);
      }
      return materializeIntoProgram(manager, direct, Map.of(), depth);
    }

    SubstitutedInput substituted = substituteCategoryPathsAndValidateTags(manager, trimmed, false);

    if (substituted.placeholders().isEmpty()
        && substituted.text().indexOf('(') < 0
        && substituted.text().indexOf(')') < 0) {
      validateUnqualifiedTypeAmbiguity(manager, substituted.text());
      String stripped = stripQualifiersAndTags(substituted.text());
      if ("pointer".equals(stripped)) {
        return GhidraDataTypeReferences.resolveUntypedPointer(manager);
      }
      DataType parsedByDataTypeParser = tryDataTypeParser(manager, stripped);
      if (parsedByDataTypeParser != null) {
        return materializeIntoProgram(manager, parsedByDataTypeParser, Map.of(), depth);
      }
    }

    return resolveViaCParserDeclarator(manager, substituted, rawExpression, depth);
  }

  public static ParsedPrototype parseFunctionPrototype(
      DataTypeManager manager, FunctionSignature originalSignature, String rawSignature) {
    if (manager == null) {
      throw new IllegalArgumentException("data type manager is required");
    }
    if (rawSignature == null || rawSignature.isBlank()) {
      throw new IllegalArgumentException("function signature must not be blank");
    }
    String strippedComments = stripComments(rawSignature).trim();
    if (strippedComments.isEmpty()) {
      throw new IllegalArgumentException("function signature must not be blank");
    }
    if (strippedComments.indexOf('{') >= 0 || strippedComments.indexOf('}') >= 0) {
      throw new IllegalArgumentException(
          "function signature must be a prototype without a body: " + rawSignature);
    }
    String singlePrototype = requireSingleTopLevelStatement(strippedComments, false);
    if (singlePrototype.indexOf('(') < 0 || singlePrototype.indexOf(')') < 0) {
      throw new IllegalArgumentException(
          "function signature must include a parameter list: " + rawSignature);
    }

    HeaderSpecifiers specifiers = extractHeaderSpecifiers(manager, singlePrototype);
    SubstitutedInput substituted =
        substituteCategoryPathsAndValidateTags(manager, specifiers.cleanedPrototype(), false);

    if (substituted.placeholders().isEmpty() && !hasNestedParenthesesInParams(substituted.text())) {
      String normalizedForSignatureParser = stripQualifiersAndTags(substituted.text());
      FunctionDefinitionDataType parsed =
          tryFunctionSignatureParser(manager, originalSignature, normalizedForSignatureParser);
      if (parsed != null) {
        DataType returnType = materializeIntoProgram(manager, parsed.getReturnType(), Map.of(), 0);
        List<ParameterDefinition> params =
            materializeParameters(manager, parsed.getArguments(), Map.of());
        String convention =
            specifiers.callingConvention() != null
                ? specifiers.callingConvention()
                : normalizedParsedConvention(parsed.getCallingConventionName());
        boolean noReturn = specifiers.hasNoReturn() || parsed.hasNoReturn();
        return new ParsedPrototype(
            parsed.getName(), returnType, params, convention, parsed.hasVarArgs(), noReturn);
      }
    }

    try (StandAloneDataTypeManager scratch = createScratchManager(manager)) {
      int tx = scratch.startTransaction("parse_prototype");
      try {
        registerPlaceholders(scratch, substituted.placeholders());
        CParser parser = createCParser(scratch, manager);
        DataType parsed = parser.parse(substituted.text() + ";");
        if (!parser.getDeclarations().isEmpty()
            || !parser.getComposites().isEmpty()
            || !parser.getEnums().isEmpty()
            || !parser.getTypes().isEmpty()
            || parser.getFunctions().size() != 1
            || !(parsed instanceof FunctionDefinition fn)) {
          throw new IllegalArgumentException(
              "signature must be a single C function prototype: " + rawSignature);
        }
        DataType returnType =
            materializeIntoProgram(manager, fn.getReturnType(), substituted.placeholders(), 0);
        List<ParameterDefinition> params =
            materializeParameters(manager, fn.getArguments(), substituted.placeholders());
        String convention =
            specifiers.callingConvention() != null
                ? specifiers.callingConvention()
                : normalizedParsedConvention(fn.getCallingConventionName());
        boolean noReturn = specifiers.hasNoReturn() || fn.hasNoReturn();
        return new ParsedPrototype(
            fn.getName(), returnType, params, convention, fn.hasVarArgs(), noReturn);
      } catch (ParseException | TokenMgrError error) {
        throw new IllegalArgumentException(
            "invalid C function prototype: " + error.getMessage(), error);
      } finally {
        scratch.endTransaction(tx, false);
      }
    }
  }

  public static String writeSingleDeclaration(
      DataTypeManager manager, String categoryPath, String rawDeclaration, boolean upsert) {
    if (manager == null) {
      throw new IllegalArgumentException("data type manager is required");
    }
    if (rawDeclaration == null || rawDeclaration.isBlank()) {
      throw new IllegalArgumentException("declaration must not be blank");
    }
    String withoutComments = stripComments(rawDeclaration).trim();
    String statement = requireSingleTopLevelStatement(withoutComments, true);
    validateSingleDeclarationSyntax(statement);

    String normalizedCategory =
        categoryPath == null || categoryPath.isBlank() ? "/" : categoryPath.trim();
    if (!normalizedCategory.startsWith("/")) {
      normalizedCategory = "/" + normalizedCategory;
    }
    CategoryPath targetCategory = new CategoryPath(normalizedCategory);
    Set<String> sourceIdentifiers = collectIdentifiers(withoutComments);
    SubstitutedInput substituted =
        substituteCategoryPathsAndValidateTags(manager, statement, true);

    try (StandAloneDataTypeManager scratch = createScratchManager(manager)) {
      int tx = scratch.startTransaction("parse_declaration");
      try {
        registerPlaceholders(scratch, substituted.placeholders());
        CParser parser = createCParser(scratch, manager);
        DataType parsed = parser.parse(substituted.text() + ";");
        validateSingleDeclarationResult(parser, parsed, sourceIdentifiers);
        DataType candidate =
            prepareDeclarationCandidate(
                manager, targetCategory, parsed, substituted.placeholders());
        return applyDeclarationCandidate(manager, targetCategory, candidate, upsert);
      } catch (ParseException | TokenMgrError error) {
        throw new IllegalArgumentException("invalid C declaration: " + error.getMessage(), error);
      } finally {
        scratch.endTransaction(tx, false);
      }
    }
  }

  private static DataType tryDataTypeParser(DataTypeManager manager, String expression) {
    DataTypeParser parser = new DataTypeParser(manager, manager, null, AllowedDataTypes.ALL);
    try {
      return parser.parse(expression);
    } catch (InvalidDataTypeException | CancelledException ignored) {
      return null;
    }
  }

  private static FunctionDefinitionDataType tryFunctionSignatureParser(
      DataTypeManager manager, FunctionSignature originalSignature, String prototype) {
    FunctionSignatureParser parser = new FunctionSignatureParser(manager, null);
    try {
      return parser.parse(originalSignature, prototype);
    } catch (ParseException | CancelledException ignored) {
      return null;
    }
  }

  private static DataType resolveViaCParserDeclarator(
      DataTypeManager manager,
      SubstitutedInput substituted,
      String rawExpression,
      int depth) {
    String declarator = insertDeclaratorName(substituted.text(), SYNTHETIC_DECL_NAME);
    try (StandAloneDataTypeManager scratch = createScratchManager(manager)) {
      int tx = scratch.startTransaction("parse_type_expr");
      try {
        registerPlaceholders(scratch, substituted.placeholders());
        CParser parser = createCParser(scratch, manager);
        DataType parsed = parser.parse("typedef " + declarator + ";");
        if (!parser.getDeclarations().isEmpty()
            || !parser.getComposites().isEmpty()
            || !parser.getEnums().isEmpty()
            || parser.getTypes().size() != 1
            || !(parsed instanceof TypeDef typeDef)
            || !SYNTHETIC_DECL_NAME.equals(typeDef.getName())) {
          throw new IllegalArgumentException("invalid C data type expression: " + rawExpression);
        }
        return materializeIntoProgram(
            manager, typeDef.getDataType(), substituted.placeholders(), depth);
      } catch (ParseException | TokenMgrError error) {
        throw new IllegalArgumentException(
            "invalid C data type expression '" + rawExpression + "': " + error.getMessage(), error);
      } finally {
        scratch.endTransaction(tx, false);
      }
    }
  }

  static String insertDeclaratorName(String expression, String identifier) {
    String trimmed = expression.trim();
    int depth = 0;
    int firstOpenParen = -1;
    int matchingCloseParen = -1;
    int firstOpenBracket = -1;
    for (int i = 0; i < trimmed.length(); i++) {
      char ch = trimmed.charAt(i);
      if (ch == '(') {
        if (depth == 0 && firstOpenParen < 0) {
          firstOpenParen = i;
        }
        depth++;
      } else if (ch == ')') {
        depth--;
        if (depth < 0) {
          throw new IllegalArgumentException("unmatched ')' in C type expression: " + expression);
        }
        if (depth == 0 && firstOpenParen >= 0 && matchingCloseParen < 0) {
          matchingCloseParen = i;
        }
      } else if (ch == '[') {
        if (depth == 0 && firstOpenBracket < 0 && firstOpenParen < 0) {
          firstOpenBracket = i;
        }
        depth++;
      } else if (ch == ']') {
        depth--;
        if (depth < 0) {
          throw new IllegalArgumentException("unmatched ']' in C type expression: " + expression);
        }
      }
    }
    if (depth != 0) {
      throw new IllegalArgumentException("unclosed delimiter in C type expression: " + expression);
    }

    if (firstOpenParen >= 0 && matchingCloseParen > firstOpenParen) {
      String inside = trimmed.substring(firstOpenParen + 1, matchingCloseParen).trim();
      if (startsAbstractGroupingDeclarator(inside)) {
        String rewrittenInside = insertDeclaratorName(inside, identifier);
        return trimmed.substring(0, firstOpenParen + 1)
            + rewrittenInside
            + trimmed.substring(matchingCloseParen);
      }
      return trimmed.substring(0, firstOpenParen)
          + " "
          + identifier
          + trimmed.substring(firstOpenParen);
    }

    if (firstOpenBracket >= 0) {
      return trimmed.substring(0, firstOpenBracket)
          + " "
          + identifier
          + trimmed.substring(firstOpenBracket);
    }

    return trimmed + " " + identifier;
  }

  private static boolean startsAbstractGroupingDeclarator(String insideParen) {
    if (insideParen.isEmpty()) {
      return false;
    }
    char first = insideParen.charAt(0);
    return first == '*' || first == '(' || first == '[';
  }

  private static DataType materializeIntoProgram(
      DataTypeManager manager,
      DataType dataType,
      Map<String, DataType> placeholders,
      int depth) {
    if (dataType == null) {
      throw new IllegalArgumentException("resolved data type is null");
    }
    if (dataType instanceof TypeDef typeDef && placeholders.containsKey(typeDef.getName())) {
      return placeholders.get(typeDef.getName());
    }
    if (dataType instanceof TypeDef typeDef) {
      return resolveExistingScalarType(manager, typeDef);
    }
    if (dataType instanceof Pointer pointer) {
      GhidraDataTypeReferences.requireCanDescend(depth);
      DataType pointee = pointer.getDataType();
      if (pointee == null) {
        return GhidraDataTypeReferences.resolveUntypedPointer(manager);
      }
      DataType resolvedPointee =
          materializeIntoProgram(manager, pointee, placeholders, depth + 1);
      Pointer resolved = manager.getPointer(resolvedPointee);
      GhidraDataTypeReferences.requirePointerIdentityCanBePreserved(manager, resolved);
      return resolved;
    }
    if (dataType instanceof Array array) {
      GhidraDataTypeReferences.requireCanDescend(depth);
      DataType element = array.getDataType();
      if (element == null) {
        throw new IllegalArgumentException("array has no element data type");
      }
      DataType resolvedElement =
          materializeIntoProgram(manager, element, placeholders, depth + 1);
      return GhidraDataTypeReferences.buildArrayDataType(
          resolvedElement, array.getNumElements(), manager);
    }
    if (dataType instanceof FunctionDefinition funcDef) {
      return materializeFunctionDefinition(manager, funcDef, placeholders, depth);
    }
    return resolveExistingScalarType(manager, dataType);
  }

  private static DataType materializeFunctionDefinition(
      DataTypeManager manager,
      FunctionDefinition funcDef,
      Map<String, DataType> placeholders,
      int depth) {
    if (funcDef.getDataTypeManager() == manager) {
      return funcDef;
    }
    DataType existingByPath = manager.getDataType(funcDef.getPathName());
    if (existingByPath instanceof FunctionDefinition existingFn
        && placeholders.isEmpty()
        && existingFn.isEquivalent(funcDef)) {
      return existingFn;
    }

    DataType returnType =
        materializeIntoProgram(manager, funcDef.getReturnType(), placeholders, depth + 1);
    List<ParameterDefinition> args =
        materializeParameters(manager, funcDef.getArguments(), placeholders);
    String baseName = canonicalFunctionDefinitionName(returnType, args, funcDef);
    String chosenName = baseName;
    int suffix = 1;
    while (true) {
      FunctionDefinitionDataType candidate =
          buildFunctionDefinition(manager, FUNCTIONS_CATEGORY, chosenName, returnType, args, funcDef);
      DataType existing = manager.getDataType(FUNCTIONS_CATEGORY, chosenName);
      if (existing == null) {
        return candidate;
      }
      if (existing instanceof FunctionDefinition existingFn && existingFn.isEquivalent(candidate)) {
        return existingFn;
      }
      chosenName = baseName + "_" + suffix;
      suffix++;
    }
  }

  private static FunctionDefinitionDataType buildFunctionDefinition(
      DataTypeManager manager,
      CategoryPath category,
      String name,
      DataType returnType,
      List<ParameterDefinition> args,
      FunctionDefinition source) {
    FunctionDefinitionDataType prototype = new FunctionDefinitionDataType(category, name, manager);
    prototype.setReturnType(returnType);
    prototype.setArguments(args.toArray(ParameterDefinition[]::new));
    prototype.setVarArgs(source.hasVarArgs());
    prototype.setNoReturn(source.hasNoReturn());
    String convention = normalizedParsedConvention(source.getCallingConventionName());
    if (convention != null) {
      try {
        prototype.setCallingConvention(convention);
      } catch (InvalidInputException error) {
        throw new IllegalArgumentException(
            "invalid function calling convention: " + convention, error);
      }
    }
    return prototype;
  }

  private static List<ParameterDefinition> materializeParameters(
      DataTypeManager manager,
      ParameterDefinition[] arguments,
      Map<String, DataType> placeholders) {
    if (arguments == null || arguments.length == 0) {
      return List.of();
    }
    List<ParameterDefinition> result = new ArrayList<>(arguments.length);
    for (ParameterDefinition argument : arguments) {
      DataType argType = materializeIntoProgram(manager, argument.getDataType(), placeholders, 1);
      if (GhidraDataTypeReferences.isBareFunctionDefinition(argType)) {
        argType = manager.getPointer(argType);
      }
      result.add(new ParameterDefinitionImpl(argument.getName(), argType, argument.getComment()));
    }
    return List.copyOf(result);
  }

  private static String canonicalFunctionDefinitionName(
      DataType returnType, List<ParameterDefinition> args, FunctionDefinition source) {
    StringBuilder sig = new StringBuilder();
    sig.append(returnType.getPathName()).append('(');
    for (int i = 0; i < args.size(); i++) {
      if (i > 0) sig.append(',');
      sig.append(args.get(i).getDataType().getPathName());
    }
    if (source.hasVarArgs()) {
      if (!args.isEmpty()) sig.append(',');
      sig.append("...");
    }
    sig.append(')');
    String convention = normalizedParsedConvention(source.getCallingConventionName());
    if (convention != null) {
      sig.append('@').append(convention);
    }
    if (source.hasNoReturn()) {
      sig.append("!noreturn");
    }
    CRC32 crc = new CRC32();
    crc.update(sig.toString().getBytes(StandardCharsets.UTF_8));
    return String.format("fn_%08x", crc.getValue());
  }

  private static DataType resolveExistingScalarType(DataTypeManager manager, DataType dataType) {
    if (dataType.getDataTypeManager() == manager) {
      return dataType;
    }
    DataType byPath = GhidraDataTypeReferences.findByPath(manager, dataType.getPathName());
    if (byPath != null) {
      return byPath;
    }
    List<DataType> named = GhidraDataTypeReferences.findNamed(manager, dataType.getName());
    if (named.size() == 1) {
      return named.getFirst();
    }
    if (named.size() > 1) {
      throw new IllegalArgumentException(
          "ambiguous data type name: " + dataType.getName() + "; use an absolute path");
    }
    return dataType.clone(manager);
  }

  private static DataType prepareDeclarationCandidate(
      DataTypeManager manager,
      CategoryPath targetCategory,
      DataType parsed,
      Map<String, DataType> placeholders) {
    if (parsed instanceof TypeDef typeDef) {
      DataType base = materializeIntoProgram(manager, typeDef.getDataType(), placeholders, 0);
      if (GhidraDataTypeReferences.isBareFunctionDefinition(base)) {
        throw new IllegalArgumentException(
            "typedef base type must use a function pointer rather than a bare function type");
      }
      return new TypedefDataType(targetCategory, typeDef.getName(), base, manager);
    }
    if (parsed instanceof FunctionDefinition funcDef) {
      String convention = funcDef.getCallingConventionName();
      if (convention != null && !convention.isBlank()) {
        requireKnownCallingConvention(manager, convention);
      }
      DataType returnType =
          materializeIntoProgram(manager, funcDef.getReturnType(), placeholders, 0);
      if (GhidraDataTypeReferences.isBareFunctionDefinition(returnType)) {
        throw new DataTypeMutationValidationException(
            "signature.returnType",
            "signature.returnType must use kind=pointer for a function definition");
      }
      List<ParameterDefinition> args =
          materializeParameters(manager, funcDef.getArguments(), placeholders);
      return buildFunctionDefinition(
          manager, targetCategory, funcDef.getName(), returnType, args, funcDef);
    }
    if (!placeholders.isEmpty() && parsed instanceof Structure struct) {
      replaceCompositePlaceholders(manager, struct, placeholders);
    } else if (!placeholders.isEmpty() && parsed instanceof Union union) {
      replaceUnionPlaceholders(manager, union, placeholders);
    }
    DataType cloned = parsed.copy(manager);
    try {
      cloned.setCategoryPath(targetCategory);
    } catch (ghidra.util.exception.DuplicateNameException error) {
      throw new IllegalArgumentException(error.getMessage(), error);
    }
    return cloned;
  }

  private static void replaceCompositePlaceholders(
      DataTypeManager manager, Structure struct, Map<String, DataType> placeholders) {
    DataTypeComponent[] components = struct.getDefinedComponents();
    for (DataTypeComponent component : components) {
      DataType replaced =
          materializeIntoProgram(manager, component.getDataType(), placeholders, 0);
      if (replaced != component.getDataType()) {
        struct.replaceAtOffset(
            component.getOffset(),
            replaced,
            replaced.getLength(),
            component.getFieldName(),
            component.getComment());
      }
    }
  }

  private static void replaceUnionPlaceholders(
      DataTypeManager manager, Union union, Map<String, DataType> placeholders) {
    DataTypeComponent[] components = union.getComponents();
    if (components.length == 0) {
      return;
    }
    record Entry(DataType type, int length, String name, String comment) {}
    List<Entry> entries = new ArrayList<>(components.length);
    for (DataTypeComponent component : components) {
      DataType replaced =
          materializeIntoProgram(manager, component.getDataType(), placeholders, 0);
      entries.add(
          new Entry(
              replaced,
              replaced.getLength() > 0 ? replaced.getLength() : component.getLength(),
              component.getFieldName(),
              component.getComment()));
    }
    while (union.getNumComponents() > 0) {
      union.delete(0);
    }
    for (Entry entry : entries) {
      union.add(entry.type(), entry.length(), entry.name(), entry.comment());
    }
  }

  private static String applyDeclarationCandidate(
      DataTypeManager manager,
      CategoryPath targetCategory,
      DataType candidate,
      boolean upsert) {
    String exactPath = targetCategory.getPath(candidate.getName());
    DataType existing = manager.getDataType(targetCategory, candidate.getName());
    if (!upsert) {
      if (existing != null) {
        throw new DataTypeAlreadyExistsException(
            "/declaration", "data type already exists: " + exactPath);
      }
      DataType resolved = manager.addDataType(candidate, DataTypeConflictHandler.DEFAULT_HANDLER);
      return resolved.getPathName();
    }
    if (existing == null) {
      DataType resolved = manager.addDataType(candidate, DataTypeConflictHandler.DEFAULT_HANDLER);
      return resolved.getPathName();
    }
    if (existing instanceof FunctionDefinition existingFn
        && candidate instanceof FunctionDefinition newFn) {
      existingFn.setReturnType(newFn.getReturnType());
      existingFn.setArguments(newFn.getArguments());
      String convention = newFn.getCallingConventionName();
      if (convention != null) {
        try {
          existingFn.setCallingConvention(convention);
        } catch (InvalidInputException error) {
          throw new DataTypeMutationValidationException(
              "signature.callingConvention", "invalid function callingConvention", error);
        }
      }
      existingFn.setVarArgs(newFn.hasVarArgs());
      existingFn.setNoReturn(newFn.hasNoReturn());
      return existingFn.getPathName();
    }
    try {
      DataType replaced = manager.replaceDataType(existing, candidate, false);
      return replaced.getPathName();
    } catch (DataTypeDependencyException error) {
      throw new IllegalArgumentException(
          "unable to replace data type at " + exactPath + ": " + error.getMessage(), error);
    }
  }

  private static void requireKnownCallingConvention(
      DataTypeManager manager, String callingConvention) {
    if (CompilerSpec.CALLING_CONVENTION_unknown.equalsIgnoreCase(callingConvention)) {
      return;
    }
    if (!CompilerSpec.CALLING_CONVENTION_default.equals(callingConvention)
        && !manager.getKnownCallingConventionNames().contains(callingConvention)) {
      throw new DataTypeMutationValidationException(
          "signature.callingConvention",
          "function callingConvention is not known by the target program: " + callingConvention);
    }
  }

  private static void validateSingleDeclarationResult(
      CParser parser, DataType parsed, Set<String> sourceIdentifiers) {
    if (parsed == null || !parser.getDeclarations().isEmpty()) {
      throw new IllegalArgumentException("declaration must define one data type, not a variable");
    }
    int compositeCount = parser.getComposites().size();
    int enumCount = parser.getEnums().size();
    int typedefCount = parser.getTypes().size();
    int primaryCount = compositeCount + enumCount + typedefCount;
    int functionCount = parser.getFunctions().size();

    boolean singlePrimaryType =
        primaryCount == 1
            && (parsed instanceof Structure
                || parsed instanceof Union
                || parsed instanceof ghidra.program.model.data.Enum
                || parsed instanceof TypeDef);
    boolean singleFunctionType =
        primaryCount == 0 && functionCount == 1 && parsed instanceof FunctionDefinition;
    if (!singlePrimaryType && !singleFunctionType) {
      throw new IllegalArgumentException(
          "declaration must define exactly one top-level struct, union, enum, typedef, or"
              + " function");
    }
    String name = parsed.getName();
    if (name == null || name.isBlank() || !sourceIdentifiers.contains(name)) {
      throw new IllegalArgumentException("declaration must define a named top-level data type");
    }
  }

  private static void validateSingleDeclarationSyntax(String statement) {
    int braceDepth = 0;
    int parenDepth = 0;
    int bracketDepth = 0;
    int topLevelCloseBrace = -1;
    boolean startsWithTypedef = startsWithKeyword(statement, "typedef");
    boolean startsWithTag =
        startsWithKeyword(statement, "struct")
            || startsWithKeyword(statement, "union")
            || startsWithKeyword(statement, "enum");

    for (int i = 0; i < statement.length(); i++) {
      char ch = statement.charAt(i);
      if (ch == '"' || ch == '\'') {
        i = skipLiteral(statement, i, ch);
        continue;
      }
      if (ch == '{') {
        if (braceDepth == 0 && parenDepth == 0 && bracketDepth == 0
            && !startsWithTypedef && !startsWithTag) {
          throw new IllegalArgumentException(
              "function declaration must be a prototype without a body");
        }
        braceDepth++;
      } else if (ch == '}') {
        braceDepth--;
        if (braceDepth < 0) {
          throw new IllegalArgumentException("unmatched '}' in declaration");
        }
        if (braceDepth == 0 && parenDepth == 0 && bracketDepth == 0) {
          topLevelCloseBrace = i;
        }
      } else if (ch == '(') {
        parenDepth++;
      } else if (ch == ')') {
        parenDepth--;
        if (parenDepth < 0) {
          throw new IllegalArgumentException("unmatched ')' in declaration");
        }
      } else if (ch == '[') {
        bracketDepth++;
      } else if (ch == ']') {
        bracketDepth--;
        if (bracketDepth < 0) {
          throw new IllegalArgumentException("unmatched ']' in declaration");
        }
      } else if (ch == ',' && braceDepth == 0 && parenDepth == 0 && bracketDepth == 0) {
        throw new IllegalArgumentException(
            "declaration must not declare multiple comma-separated names");
      }
    }
    if (braceDepth != 0 || parenDepth != 0 || bracketDepth != 0) {
      throw new IllegalArgumentException("unclosed delimiter in declaration");
    }
    if (startsWithTag && !startsWithTypedef && topLevelCloseBrace >= 0) {
      String trailing = statement.substring(topLevelCloseBrace + 1).trim();
      if (!trailing.isEmpty()) {
        throw new IllegalArgumentException(
            "declaration must define only a type, without trailing variable declarators");
      }
    }
  }

  private static String requireSingleTopLevelStatement(String text, boolean declarationMode) {
    int braceDepth = 0;
    int parenDepth = 0;
    int bracketDepth = 0;
    int firstSemicolon = -1;
    for (int i = 0; i < text.length(); i++) {
      char ch = text.charAt(i);
      if (ch == '"' || ch == '\'') {
        i = skipLiteral(text, i, ch);
        continue;
      }
      if (ch == '{') braceDepth++;
      else if (ch == '}') braceDepth--;
      else if (ch == '(') parenDepth++;
      else if (ch == ')') parenDepth--;
      else if (ch == '[') bracketDepth++;
      else if (ch == ']') bracketDepth--;
      else if (ch == ';' && braceDepth == 0 && parenDepth == 0 && bracketDepth == 0) {
        if (firstSemicolon < 0) {
          firstSemicolon = i;
        } else {
          throw new IllegalArgumentException(
              declarationMode
                  ? "declaration must contain exactly one top-level statement"
                  : "signature must contain a single function prototype");
        }
      }
    }
    if (firstSemicolon >= 0) {
      String before = text.substring(0, firstSemicolon).trim();
      String after = text.substring(firstSemicolon + 1).trim();
      if (!after.isEmpty()) {
        throw new IllegalArgumentException(
            declarationMode
                ? "declaration must define at most one top-level type"
                : "signature must contain a single function prototype");
      }
      if (before.isEmpty()) {
        throw new IllegalArgumentException(
            declarationMode
                ? "declaration must define one top-level type"
                : "signature must not be empty");
      }
      return before;
    }
    if (text.isEmpty()) {
      throw new IllegalArgumentException("input must not be empty");
    }
    return text;
  }

  private static SubstitutedInput substituteCategoryPathsAndValidateTags(
      DataTypeManager manager, String input, boolean allowNewCompositeDefinitions) {
    Map<String, DataType> placeholders = new LinkedHashMap<>();
    StringBuilder out = new StringBuilder(input.length() + 16);
    int index = 0;
    String pendingTag = null;
    int pendingTagStartInOut = -1;

    while (index < input.length()) {
      char ch = input.charAt(index);
      if (ch == '"' || ch == '\'') {
        int end = skipLiteral(input, index, ch);
        out.append(input, index, end + 1);
        index = end + 1;
        pendingTag = null;
        continue;
      }
      if (Character.isWhitespace(ch)) {
        out.append(ch);
        index++;
        continue;
      }
      if (ch == '/' && canStartCategoryPath(input, index)) {
        int end = scanCategoryPathEnd(input, index);
        String path = input.substring(index, end);
        DataType target = GhidraDataTypeReferences.findByPath(manager, path);
        if (target == null) {
          throw new IllegalArgumentException("unknown data type: " + path);
        }
        if (pendingTag != null) {
          requireTagMatches(pendingTag, target, path);
          out.setLength(pendingTagStartInOut);
          pendingTag = null;
        }
        String placeholder = PATH_PLACEHOLDER_PREFIX + placeholders.size();
        placeholders.put(placeholder, target);
        out.append(placeholder);
        index = end;
        continue;
      }
      if (isIdentifierStart(ch)) {
        int end = scanIdentifierEnd(input, index);
        String token = input.substring(index, end);
        if (C_TAG_KEYWORDS.contains(token)) {
          pendingTag = token;
          pendingTagStartInOut = out.length();
          out.append(token);
        } else {
          if (pendingTag != null) {
            int afterWs = skipWhitespace(input, end);
            boolean definingCompositeOrSelfRef =
                allowNewCompositeDefinitions
                    && ((afterWs < input.length() && input.charAt(afterWs) == '{')
                        || input.contains(pendingTag + " " + token + " {")
                        || input.contains(pendingTag + " " + token + "{"));
            if (!definingCompositeOrSelfRef) {
              validateTaggedName(manager, pendingTag, token);
            }
            pendingTag = null;
          }
          out.append(token);
        }
        index = end;
        continue;
      }
      pendingTag = null;
      out.append(ch);
      index++;
    }
    return new SubstitutedInput(out.toString(), placeholders);
  }

  private static void validateTaggedName(DataTypeManager manager, String tag, String name) {
    List<DataType> matches = GhidraDataTypeReferences.findNamed(manager, name);
    if (matches.isEmpty()) {
      throw new IllegalArgumentException("unknown " + tag + " data type: " + name);
    }
    if (matches.size() > 1) {
      throw new IllegalArgumentException(
          "ambiguous data type name: " + name + "; use an absolute path");
    }
    requireTagMatches(tag, matches.getFirst(), name);
  }

  private static void requireTagMatches(String tag, DataType type, String display) {
    boolean ok =
        switch (tag) {
          case "struct" -> type instanceof Structure;
          case "union" -> type instanceof Union;
          case "enum" -> type instanceof ghidra.program.model.data.Enum;
          default -> true;
        };
    if (!ok) {
      throw new IllegalArgumentException(
          "data type '" + display + "' is not a " + tag + " (actual: " + type.getName() + ")");
    }
  }

  private static void validateUnqualifiedTypeAmbiguity(DataTypeManager manager, String text) {
    int index = 0;
    while (index < text.length()) {
      char ch = text.charAt(index);
      if (ch == '[') {
        while (index < text.length() && text.charAt(index) != ']') {
          index++;
        }
        continue;
      }
      if (isIdentifierStart(ch)) {
        int end = scanIdentifierEnd(text, index);
        String token = text.substring(index, end);
        if (!C_KEYWORDS_AND_BUILTINS.contains(token)
            && !token.startsWith(PATH_PLACEHOLDER_PREFIX)) {
          List<DataType> programMatches = new ArrayList<>();
          manager.findDataTypes(token, programMatches);
          if (programMatches.size() > 1) {
            throw new IllegalArgumentException(
                "ambiguous data type name: " + token + "; use an absolute path");
          }
        }
        index = end;
        continue;
      }
      index++;
    }
  }

  private static String stripQualifiersAndTags(String text) {
    StringBuilder out = new StringBuilder(text.length());
    int index = 0;
    while (index < text.length()) {
      char ch = text.charAt(index);
      if (isIdentifierStart(ch)) {
        int end = scanIdentifierEnd(text, index);
        String token = text.substring(index, end);
        if (C_QUALIFIERS.contains(token) || C_TAG_KEYWORDS.contains(token)) {
          index = skipSingleSpaceAfterSkippedKeyword(text, end, out);
          continue;
        }
        out.append(token);
        index = end;
        continue;
      }
      out.append(ch);
      index++;
    }
    return out.toString().trim().replaceAll("\\s+", " ");
  }

  private static int skipSingleSpaceAfterSkippedKeyword(
      String text, int end, StringBuilder out) {
    if (end < text.length()
        && Character.isWhitespace(text.charAt(end))
        && (out.isEmpty() || Character.isWhitespace(out.charAt(out.length() - 1))
            || out.charAt(out.length() - 1) == '('
            || out.charAt(out.length() - 1) == ','
            || out.charAt(out.length() - 1) == '*')) {
      return skipWhitespace(text, end);
    }
    return end;
  }

  private record HeaderSpecifiers(
      String cleanedPrototype, String callingConvention, boolean hasNoReturn) {}

  private static HeaderSpecifiers extractHeaderSpecifiers(
      DataTypeManager manager, String prototype) {
    int openParen = prototype.indexOf('(');
    if (openParen < 0) {
      return new HeaderSpecifiers(prototype, null, false);
    }
    Set<String> knownConventions = new LinkedHashSet<>(manager.getKnownCallingConventionNames());
    String header = prototype.substring(0, openParen);
    String rest = prototype.substring(openParen);

    StringBuilder cleanedHeader = new StringBuilder(header.length());
    String foundConvention = null;
    boolean hasNoReturn = false;
    int index = 0;
    while (index < header.length()) {
      char ch = header.charAt(index);
      if (isIdentifierStart(ch)) {
        int end = scanIdentifierEnd(header, index);
        String token = header.substring(index, end);
        if ("_Noreturn".equals(token) || "__noreturn".equals(token)) {
          hasNoReturn = true;
          index = skipSingleSpaceAfterSkippedKeyword(header, end, cleanedHeader);
          continue;
        }
        if (knownConventions.contains(token) || COMMON_CALLING_CONVENTIONS.contains(token)) {
          String normalized = normalizeCallingConventionToken(manager, token);
          foundConvention = normalized;
          index = skipSingleSpaceAfterSkippedKeyword(header, end, cleanedHeader);
          continue;
        }
        cleanedHeader.append(token);
        index = end;
        continue;
      }
      cleanedHeader.append(ch);
      index++;
    }
    return new HeaderSpecifiers(
        cleanedHeader.toString().trim() + rest, foundConvention, hasNoReturn);
  }

  private static String normalizeCallingConventionToken(DataTypeManager manager, String token) {
    if (manager.getKnownCallingConventionNames().contains(token)) {
      return token;
    }
    String doubleUnderscore = token.startsWith("_") && !token.startsWith("__") ? "_" + token : token;
    if (manager.getKnownCallingConventionNames().contains(doubleUnderscore)) {
      return doubleUnderscore;
    }
    throw new IllegalArgumentException(
        "calling convention is not supported by the target program: " + token);
  }

  private static String normalizedParsedConvention(String convention) {
    if (convention == null
        || convention.isBlank()
        || CompilerSpec.CALLING_CONVENTION_unknown.equalsIgnoreCase(convention)
        || CompilerSpec.CALLING_CONVENTION_default.equals(convention)) {
      return null;
    }
    return convention;
  }

  private static boolean hasNestedParenthesesInParams(String prototype) {
    int openParen = prototype.indexOf('(');
    if (openParen < 0) return false;
    int depth = 0;
    for (int i = openParen; i < prototype.length(); i++) {
      char ch = prototype.charAt(i);
      if (ch == '(') {
        depth++;
        if (depth > 1) return true;
      } else if (ch == ')') {
        depth--;
      }
    }
    return false;
  }

  private static StandAloneDataTypeManager createScratchManager(DataTypeManager programManager) {
    return new StandAloneDataTypeManager("bridge_c_scratch", programManager.getDataOrganization());
  }

  private static CParser createCParser(
      StandAloneDataTypeManager scratch, DataTypeManager programManager) {
    return new CParser(
        scratch,
        false,
        new DataTypeManager[] {programManager, BuiltInDataTypeManager.getDataTypeManager()});
  }

  private static void registerPlaceholders(
      StandAloneDataTypeManager scratch, Map<String, DataType> placeholders) {
    for (Map.Entry<String, DataType> entry : placeholders.entrySet()) {
      DataType cloned = entry.getValue().clone(scratch);
      TypedefDataType alias =
          new TypedefDataType(CategoryPath.ROOT, entry.getKey(), cloned, scratch);
      scratch.addDataType(alias, DataTypeConflictHandler.REPLACE_HANDLER);
    }
  }

  private static boolean isPlainCategoryPath(String text) {
    if (!text.startsWith("/") || text.length() < 2) {
      return false;
    }
    for (int i = 0; i < text.length(); i++) {
      char ch = text.charAt(i);
      if (Character.isWhitespace(ch)
          || ch == '*'
          || ch == '['
          || ch == ']'
          || ch == '('
          || ch == ')') {
        return false;
      }
    }
    return true;
  }

  private static boolean canStartCategoryPath(String text, int slashIndex) {
    if (slashIndex + 1 >= text.length()) {
      return false;
    }
    char next = text.charAt(slashIndex + 1);
    if (!Character.isLetterOrDigit(next) && next != '_') {
      return false;
    }
    if (slashIndex == 0) {
      return true;
    }
    char prev = text.charAt(slashIndex - 1);
    return Character.isWhitespace(prev) || prev == '(' || prev == ',' || prev == '*' || prev == '{';
  }

  private static int scanCategoryPathEnd(String text, int start) {
    int i = start;
    while (i < text.length()) {
      char ch = text.charAt(i);
      if (Character.isLetterOrDigit(ch) || ch == '_' || ch == '/' || ch == '.' || ch == '-') {
        i++;
      } else {
        break;
      }
    }
    return i;
  }

  private static String stripComments(String input) {
    StringBuilder out = new StringBuilder(input.length());
    int i = 0;
    while (i < input.length()) {
      char ch = input.charAt(i);
      if (ch == '"' || ch == '\'') {
        int end = skipLiteral(input, i, ch);
        out.append(input, i, end + 1);
        i = end + 1;
        continue;
      }
      if (ch == '/' && i + 1 < input.length() && input.charAt(i + 1) == '/') {
        i += 2;
        while (i < input.length() && input.charAt(i) != '\n') {
          i++;
        }
        out.append(' ');
        continue;
      }
      if (ch == '/' && i + 1 < input.length() && input.charAt(i + 1) == '*') {
        int close = input.indexOf("*/", i + 2);
        if (close < 0) {
          throw new IllegalArgumentException("unterminated block comment in C input");
        }
        out.append(' ');
        i = close + 2;
        continue;
      }
      out.append(ch);
      i++;
    }
    return out.toString();
  }

  private static Set<String> collectIdentifiers(String text) {
    Set<String> identifiers = new LinkedHashSet<>();
    int i = 0;
    while (i < text.length()) {
      char ch = text.charAt(i);
      if (ch == '"' || ch == '\'') {
        i = skipLiteral(text, i, ch) + 1;
        continue;
      }
      if (isIdentifierStart(ch)) {
        int end = scanIdentifierEnd(text, i);
        identifiers.add(text.substring(i, end));
        i = end;
        continue;
      }
      i++;
    }
    return identifiers;
  }

  private static boolean startsWithKeyword(String statement, String keyword) {
    if (!statement.startsWith(keyword)) {
      return false;
    }
    return statement.length() == keyword.length()
        || !isIdentifierPart(statement.charAt(keyword.length()));
  }

  private static int skipLiteral(String text, int quoteStart, char quote) {
    int i = quoteStart + 1;
    while (i < text.length()) {
      char ch = text.charAt(i);
      if (ch == '\\') {
        i += 2;
        continue;
      }
      if (ch == quote) {
        return i;
      }
      i++;
    }
    throw new IllegalArgumentException("unterminated string or character literal in C input");
  }

  private static int skipWhitespace(String text, int start) {
    int i = start;
    while (i < text.length() && Character.isWhitespace(text.charAt(i))) {
      i++;
    }
    return i;
  }

  private static boolean isIdentifierStart(char ch) {
    return Character.isLetter(ch) || ch == '_';
  }

  private static boolean isIdentifierPart(char ch) {
    return Character.isLetterOrDigit(ch) || ch == '_';
  }

  private static int scanIdentifierEnd(String text, int start) {
    int i = start;
    while (i < text.length() && isIdentifierPart(text.charAt(i))) {
      i++;
    }
    return i;
  }
}
