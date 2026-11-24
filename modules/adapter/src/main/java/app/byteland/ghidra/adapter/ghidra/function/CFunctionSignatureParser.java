package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.CParserScratchEnvironment;
import app.byteland.ghidra.adapter.ghidra.CTypeExpressionResolver;
import app.byteland.ghidra.adapter.ghidra.CTypeExpressionResolver.ParsedParameter;
import app.byteland.ghidra.adapter.ghidra.GhidraCParserSupport;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.cparser.C.TokenMgrError;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Parses one-line C function prototypes in an isolated scratch manager.
 */
public final class CFunctionSignatureParser {
  private static final Set<String> COMMON_CALLING_CONVENTIONS =
      Set.of("__cdecl", "__stdcall", "__fastcall", "__thiscall", "__vectorcall", "cdecl", "stdcall");

  private CFunctionSignatureParser() {}

  /**
   * Parsed C function signature ready for {@code ApplyFunctionSignatureCmd}.
   *
   * @param definition parsed function definition cloned for the target program manager
   * @param explicitCallingConvention true if the signature text contains an explicit convention
   */
  public record ParsedFunctionSignature(
      FunctionDefinitionDataType definition, boolean explicitCallingConvention) {
    public ParsedFunctionSignature {
      Objects.requireNonNull(definition, "definition");
    }
  }

  /**
   * Parses a one-line C function prototype with {@link FunctionSignatureParser} and a {@link
   * CParser} fallback when parameters contain nested declarator parentheses.
   */
  public static ParsedFunctionSignature parse(
      DataTypeManager programDataTypeManager, Function existingFunction, String signatureText) {
    if (programDataTypeManager == null) {
      throw new IllegalArgumentException("program data type manager is required");
    }
    if (signatureText == null || signatureText.isBlank()) {
      throw new IllegalArgumentException("function signature must not be blank");
    }
    if (signatureText.getBytes(StandardCharsets.UTF_8).length
        > GhidraCParserSupport.MAX_SIGNATURE_BYTES) {
      throw new IllegalArgumentException(
          "function signature exceeds maximum size of "
              + GhidraCParserSupport.MAX_SIGNATURE_BYTES
              + " UTF-8 bytes");
    }
    String trimmed = signatureText.trim();
    if (trimmed.endsWith(";")) {
      trimmed = trimmed.substring(0, trimmed.length() - 1).trim();
    }
    if (trimmed.isEmpty()
        || trimmed.indexOf('{') >= 0
        || trimmed.indexOf('}') >= 0
        || trimmed.indexOf(';') >= 0) {
      throw new IllegalArgumentException("invalid function signature: " + signatureText);
    }

    String cleaned =
        GhidraCParserSupport.normalizeTagKeywords(
            programDataTypeManager, GhidraCParserSupport.stripQualifiers(trimmed));
    boolean explicitCc = hasExplicitCallingConvention(programDataTypeManager, cleaned);

    try (CParserScratchEnvironment env = CParserScratchEnvironment.open(programDataTypeManager)) {
      FunctionSignatureParser signatureParser =
          new FunctionSignatureParser(env.scratch(), env.queryService());
      FunctionDefinitionDataType parsed = null;
      ParseException primaryFailure = null;
      if (!containsNestedParameterParens(cleaned)
          && !GhidraCParserSupport.containsPointerToArrayDeclarator(cleaned)) {
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
          GhidraCParserSupport.cloneFunctionDefinition(programDataTypeManager, parsed);
      return new ParsedFunctionSignature(cloned, explicitCc);
    }
  }

  private static FunctionDefinitionDataType parseSignatureFallback(
      CParserScratchEnvironment env, String cleanedSignature, ParseException primaryFailure) {
    CParser parser = new CParser(env.scratch(), true, env.cParserSubArchives());
    try {
      DataType parsedTopLevel = parser.parse(cleanedSignature + ";");
      if (parser.didParseSucceed()) {
        DataType selected = parsedTopLevel;
        if (!(selected instanceof FunctionDefinition)) {
          String topName = GhidraCParserSupport.extractTopLevelFunctionName(cleanedSignature);
          if (topName != null) {
            selected = parser.getFunctions().get(topName);
          }
        }
        if (selected instanceof FunctionDefinition definition) {
          FunctionDefinitionDataType result =
              new FunctionDefinitionDataType(definition, env.scratch());
          repairParameterDeclarators(env.programManager(), result, cleanedSignature);
          GhidraCParserSupport.normalizeAnonymousFunctionPointers(result);
          return result;
        }
      }
    } catch (ParseException | TokenMgrError ignored) {
      // Fall back to top-level signature decomposition below.
    }

    FunctionDefinitionDataType decomposed =
        tryDecomposeFunctionSignature(env.programManager(), cleanedSignature);
    if (decomposed != null) {
      return decomposed;
    }
    String detail =
        primaryFailure != null
            ? GhidraCParserSupport.detailMessage(primaryFailure, parser.getParseMessages())
            : GhidraCParserSupport.nonBlankOr(parser.getParseMessages(), cleanedSignature);
    throw new IllegalArgumentException("invalid C function signature: " + detail, primaryFailure);
  }

  private static void repairParameterDeclarators(
      DataTypeManager programManager, FunctionDefinitionDataType result, String signature) {
    if (!GhidraCParserSupport.containsPointerToArrayDeclarator(signature)) {
      return;
    }
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

  private static FunctionDefinitionDataType tryDecomposeFunctionSignature(
      DataTypeManager programManager, String signature) {
    int openParen = GhidraCParserSupport.findTopLevelParameterListOpen(signature);
    if (openParen <= 0) {
      return null;
    }
    int closeParen = GhidraCParserSupport.findMatchingParen(signature, openParen);
    if (closeParen != signature.length() - 1) {
      return null;
    }
    String header = signature.substring(0, openParen).trim();
    int nameStart = header.length();
    while (nameStart > 0 && GhidraCParserSupport.isIdentifierPart(header.charAt(nameStart - 1))) {
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
    DataType returnType = CTypeExpressionResolver.resolveCType(programManager, returnSpec);
    String paramsBody = signature.substring(openParen + 1, closeParen).trim();
    List<ParameterDefinition> parameters = new ArrayList<>();
    boolean varArgs = false;
    if (!paramsBody.isEmpty() && !"void".equals(paramsBody)) {
      List<String> rawParams = GhidraCParserSupport.splitTopLevelCommaList(paramsBody);
      for (int index = 0; index < rawParams.size(); index++) {
        String item = rawParams.get(index).trim();
        if ("...".equals(item) && index == rawParams.size() - 1) {
          varArgs = true;
          continue;
        }
        ParsedParameter param =
            CTypeExpressionResolver.parseParameterDeclaration(programManager, item, index);
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
      } catch (InvalidInputException error) {
        throw new IllegalArgumentException(
            "unknown calling convention in signature: " + callingConvention, error);
      }
    }
    return definition;
  }

  private static boolean hasExplicitCallingConvention(
      DataTypeManager programManager, String signature) {
    int openParen = GhidraCParserSupport.findTopLevelParameterListOpen(signature);
    String prefix = openParen > 0 ? signature.substring(0, openParen) : signature;
    Set<String> conventions = collectCallingConventionTokens(programManager);
    int index = 0;
    while (index < prefix.length()) {
      if (GhidraCParserSupport.isIdentifierStart(prefix.charAt(index))) {
        int end = index + 1;
        while (end < prefix.length() && GhidraCParserSupport.isIdentifierPart(prefix.charAt(end))) {
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
    int openParen = GhidraCParserSupport.findTopLevelParameterListOpen(signature);
    if (openParen < 0) {
      return false;
    }
    int closeParen = GhidraCParserSupport.findMatchingParen(signature, openParen);
    if (closeParen < 0) {
      return true;
    }
    return signature.substring(openParen + 1, closeParen).indexOf('(') >= 0;
  }
}
