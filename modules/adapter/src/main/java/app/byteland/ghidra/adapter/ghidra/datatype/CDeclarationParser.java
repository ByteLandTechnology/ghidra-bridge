package app.byteland.ghidra.adapter.ghidra.datatype;

import app.byteland.ghidra.adapter.ghidra.CParserScratchEnvironment;
import app.byteland.ghidra.adapter.ghidra.CTypeExpressionResolver;
import app.byteland.ghidra.adapter.ghidra.CTypeExpressionResolver.ParsedParameter;
import app.byteland.ghidra.adapter.ghidra.GhidraCParserSupport;
import app.byteland.ghidra.service.datatype.DataTypeResource;
import app.byteland.ghidra.service.datatype.DataTypeService.ConflictMode;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.cparser.C.TokenMgrError;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeDependencyException;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.UnionDataType;
import ghidra.util.exception.DuplicateNameException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Parses multi-declaration C headers in an isolated scratch manager and stores the data types.
 */
public final class CDeclarationParser {
  private static final Pattern INCLUDE_DIRECTIVE =
      Pattern.compile("(?m)^\\s*#\\s*include\\b");

  private CDeclarationParser() {}

  /**
   * Parses C declarations and returns structured {@link DataTypeResource} descriptions.
   */
  public static List<DataTypeResource> parseAndStore(
      DataTypeManager programDataTypeManager,
      String source,
      String categoryPath,
      ConflictMode conflictMode) {
    List<DataType> created =
        parseHeader(programDataTypeManager, source, categoryPath, conflictMode);
    List<DataTypeResource> resources = new ArrayList<>(created.size());
    for (DataType dataType : created) {
      resources.add(DataTypeDescriptions.detail(dataType));
    }
    return List.copyOf(resources);
  }

  /**
   * Parses C header declarations with {@link ConflictMode#REPLACE}.
   */
  public static List<DataType> parseHeader(
      DataTypeManager programDataTypeManager, String source, String categoryPath) {
    return parseHeader(programDataTypeManager, source, categoryPath, ConflictMode.REPLACE);
  }

  /**
   * Parses C header declarations and resolves all declared types into {@code
   * programDataTypeManager} under {@code categoryPath}.
   */
  public static List<DataType> parseHeader(
      DataTypeManager programDataTypeManager,
      String source,
      String categoryPath,
      ConflictMode conflictMode) {
    if (programDataTypeManager == null) {
      throw new IllegalArgumentException("program data type manager is required");
    }
    if (source == null || source.isBlank()) {
      throw new IllegalArgumentException("C source must not be blank");
    }
    if (source.getBytes(StandardCharsets.UTF_8).length
        > GhidraCParserSupport.MAX_DECLARATIONS_BYTES) {
      throw new IllegalArgumentException(
          "C source exceeds maximum size of "
              + GhidraCParserSupport.MAX_DECLARATIONS_BYTES
              + " UTF-8 bytes");
    }

    String withoutComments = GhidraCParserSupport.maskCommentsAndStrings(source);
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
    ConflictMode effectiveMode = conflictMode == null ? ConflictMode.REPLACE : conflictMode;
    DataTypeConflictHandler conflictHandler = toConflictHandler(effectiveMode);
    String sanitizedSource = GhidraCParserSupport.stripRestrictQualifiers(source);

    try (CParserScratchEnvironment env = CParserScratchEnvironment.open(programDataTypeManager)) {
      CParser parser = new CParser(env.scratch(), true, env.cParserSubArchives());
      try {
        parser.parse(sanitizedSource);
      } catch (ParseException | TokenMgrError error) {
        throw new IllegalArgumentException(
            "C header parse failed: "
                + GhidraCParserSupport.detailMessage(error, parser.getParseMessages()),
            error);
      }
      if (!parser.didParseSucceed()) {
        throw new IllegalArgumentException(
            "C header parse failed: "
                + GhidraCParserSupport.nonBlankOr(parser.getParseMessages(), "syntax error"));
      }

      List<DataType> localTypes = collectDeclaredTypes(env.scratch(), parser, withoutComments);
      if (localTypes.isEmpty()) {
        throw new IllegalArgumentException("C source did not declare any data types");
      }

      localTypes = relocateScratchTypes(env.scratch(), localTypes, targetCategory);
      env.clearScratchSourceArchives();
      env.resolveUsedStdintTypedefs(programDataTypeManager);
      if (!CategoryPath.ROOT.equals(targetCategory)) {
        programDataTypeManager.createCategory(targetCategory);
      }

      List<ResolvedDeclaration> resolvedDeclarations = new ArrayList<>(localTypes.size());
      Set<String> seenPaths = new LinkedHashSet<>();
      for (DataType candidate : localTypes) {
        String declaredName = candidate.getName();
        boolean preExisting =
            programDataTypeManager.getDataType(candidate.getCategoryPath(), declaredName) != null;
        GhidraCParserSupport.normalizeAnonymousFunctionPointers(candidate);
        DataType committed = programDataTypeManager.resolve(candidate, conflictHandler);
        programDataTypeManager.disassociate(committed);
        if (seenPaths.add(committed.getPathName())) {
          resolvedDeclarations.add(
              new ResolvedDeclaration(
                  declaredName, committed, effectiveMode == ConflictMode.KEEP && preExisting));
        }
      }

      List<DataType> resolved;
      if (GhidraCParserSupport.containsPointerToArrayDeclarator(withoutComments)) {
        resolved =
            repairHeaderPointerToArrayDeclarators(
                programDataTypeManager, withoutComments, resolvedDeclarations);
      } else {
        resolved = new ArrayList<>(resolvedDeclarations.size());
        for (ResolvedDeclaration item : resolvedDeclarations) {
          resolved.add(item.committed());
        }
      }
      env.removeTemporaryArchives(programDataTypeManager);
      resolved.sort(Comparator.comparing(DataType::getPathName));
      return List.copyOf(resolved);
    }
  }

  private static DataTypeConflictHandler toConflictHandler(ConflictMode mode) {
    return switch (mode) {
      case REPLACE -> DataTypeConflictHandler.REPLACE_HANDLER;
      case KEEP -> DataTypeConflictHandler.KEEP_HANDLER;
      case RENAME -> DataTypeConflictHandler.DEFAULT_HANDLER;
    };
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
          while (start > 0 && GhidraCParserSupport.isIdentifierPart(maskedSource.charAt(start - 1))) {
            start--;
          }
          if (start < end && GhidraCParserSupport.isIdentifierStart(maskedSource.charAt(start))) {
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
      String maskedSource,
      List<ResolvedDeclaration> resolvedDeclarations) {
    Map<String, String> compositeBodies = extractCompositeBodies(maskedSource);
    Map<String, DataType> typedefReplacements = new LinkedHashMap<>();
    Map<String, String> functionStatements = new LinkedHashMap<>();
    for (String statement : GhidraCParserSupport.splitTopLevelStatements(maskedSource)) {
      String trimmed = statement.trim();
      if (!GhidraCParserSupport.containsPointerToArrayDeclarator(trimmed)) {
        continue;
      }
      if (trimmed.startsWith("typedef ") && trimmed.indexOf('{') < 0) {
        String body = trimmed.substring("typedef".length()).trim();
        ParsedParameter parsed =
            CTypeExpressionResolver.parseParameterDeclaration(programManager, body, 0);
        if (parsed.name() != null) {
          typedefReplacements.put(parsed.name(), parsed.dataType());
        }
      } else if (trimmed.indexOf('{') < 0) {
        String fnName = GhidraCParserSupport.extractTopLevelFunctionName(trimmed);
        if (fnName != null) {
          functionStatements.put(fnName, trimmed);
        }
      }
    }

    List<DataType> updated = new ArrayList<>(resolvedDeclarations.size());
    for (ResolvedDeclaration decl : resolvedDeclarations) {
      DataType item = decl.committed();
      if (decl.keptExisting()) {
        updated.add(item);
        continue;
      }
      String declaredName = decl.declaredName();
      if (item instanceof Composite composite) {
        String body = compositeBodies.get(declaredName);
        if (body != null && GhidraCParserSupport.containsPointerToArrayDeclarator(body)) {
          repairCompositePointerToArrayFields(programManager, composite, body);
        }
        updated.add(item);
      } else if (item instanceof TypeDef && typedefReplacements.containsKey(declaredName)) {
        TypedefDataType replacement =
            new TypedefDataType(
                item.getCategoryPath(),
                item.getName(),
                typedefReplacements.get(declaredName),
                programManager);
        updated.add(
            programManager.resolve(replacement, DataTypeConflictHandler.REPLACE_HANDLER));
      } else if (item instanceof FunctionDefinition fnDef
          && functionStatements.containsKey(declaredName)) {
        String rawSig =
            GhidraCParserSupport.normalizeTagKeywords(
                programManager,
                GhidraCParserSupport.stripQualifiers(functionStatements.get(declaredName)));
        FunctionDefinitionDataType copy =
            new FunctionDefinitionDataType(item.getCategoryPath(), item.getName(), programManager);
        copy.setReturnType(fnDef.getReturnType());
        copy.setArguments(fnDef.getArguments());
        copy.setVarArgs(fnDef.hasVarArgs());
        copy.setNoReturn(fnDef.hasNoReturn());
        repairFunctionParameters(programManager, copy, rawSig);
        updated.add(programManager.resolve(copy, DataTypeConflictHandler.REPLACE_HANDLER));
      } else {
        updated.add(item);
      }
    }
    return updated;
  }

  private static void repairFunctionParameters(
      DataTypeManager programManager, FunctionDefinitionDataType result, String signature) {
    int openParen = GhidraCParserSupport.findTopLevelParameterListOpen(signature);
    int closeParen = GhidraCParserSupport.findMatchingParen(signature, openParen);
    if (openParen < 0 || closeParen < 0) {
      return;
    }
    List<String> rawParams =
        GhidraCParserSupport.splitTopLevelCommaList(signature.substring(openParen + 1, closeParen));
    ParameterDefinition[] args = result.getArguments();
    int limit = Math.min(args.length, rawParams.size());
    for (int i = 0; i < limit; i++) {
      String rawParam = rawParams.get(i).trim();
      if ("...".equals(rawParam) || "void".equals(rawParam)) {
        continue;
      }
      if (GhidraCParserSupport.containsPointerToArrayDeclarator(rawParam)) {
        ParsedParameter parsed =
            CTypeExpressionResolver.parseParameterDeclaration(programManager, rawParam, i);
        args[i] = new ParameterDefinitionImpl(parsed.name(), parsed.dataType(), null);
      }
    }
    result.setArguments(args);
  }

  private static void repairCompositePointerToArrayFields(
      DataTypeManager programManager, Composite composite, String body) {
    Map<String, DataType> repairedByField = new LinkedHashMap<>();
    for (String statement : GhidraCParserSupport.splitTopLevelStatements(body)) {
      String trimmed = statement.trim();
      if (trimmed.isEmpty() || !GhidraCParserSupport.containsPointerToArrayDeclarator(trimmed)) {
        continue;
      }
      String normalized =
          GhidraCParserSupport.normalizeTagKeywords(
              programManager, GhidraCParserSupport.stripQualifiers(trimmed));
      ParsedParameter parsed =
          CTypeExpressionResolver.parseParameterDeclaration(programManager, normalized, 0);
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
      if (GhidraCParserSupport.isIdentifierStart(maskedSource.charAt(index))) {
        int end = index + 1;
        while (end < maskedSource.length()
            && GhidraCParserSupport.isIdentifierPart(maskedSource.charAt(end))) {
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
          if (cursor < maskedSource.length()
              && GhidraCParserSupport.isIdentifierStart(maskedSource.charAt(cursor))) {
            int tagEnd = cursor + 1;
            while (tagEnd < maskedSource.length()
                && GhidraCParserSupport.isIdentifierPart(maskedSource.charAt(tagEnd))) {
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
            int closeBrace = GhidraCParserSupport.findMatchingBrace(maskedSource, cursor);
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
                  && GhidraCParserSupport.isIdentifierStart(maskedSource.charAt(after))) {
                int aliasEnd = after + 1;
                while (aliasEnd < maskedSource.length()
                    && GhidraCParserSupport.isIdentifierPart(maskedSource.charAt(aliasEnd))) {
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

  private record ResolvedDeclaration(String declaredName, DataType committed, boolean keptExisting) {}
}
