package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.GhidraCParserSupport;
import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.datatype.DataTypeMutationValidationException;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.app.services.DataTypeQueryService;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import java.lang.reflect.Proxy;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses and applies C function prototypes for {@code function.patch}.
 */
final class FunctionSignaturePatchSupport {
  private static final String SIGNATURE_TARGET = "/patch/signature";
  private static final Set<String> COMMON_CALLING_CONVENTIONS =
      Set.of(
          "__cdecl",
          "__stdcall",
          "__fastcall",
          "__thiscall",
          "__vectorcall",
          "__rustcall",
          "__pascal",
          "_cdecl",
          "_stdcall",
          "_fastcall",
          "cdecl",
          "stdcall",
          "fastcall",
          "thiscall");
  private static final Pattern QUALIFIER_OR_SPECIFIER_PATTERN =
      Pattern.compile(
          "\\b(const|volatile|restrict|_Restrict|__restrict|__restrict__|struct|union|enum|unsigned|signed|short|long)\\b");

  private FunctionSignaturePatchSupport() {}

  record AppliedSignature(Function function, boolean explicitCallingConvention) {}

  static AppliedSignature applySignature(
      GhidraSession context,
      Function function,
      String rawSignature,
      boolean preserveExistingName) {
    if (rawSignature == null) {
      throw new DataTypeMutationValidationException(
          SIGNATURE_TARGET, "/patch/signature must not be blank");
    }
    if (GhidraCParserSupport.utf8BytesExceed(
        rawSignature, GhidraCParserSupport.MAX_SIGNATURE_BYTES)) {
      throw new DataTypeMutationValidationException(
          SIGNATURE_TARGET,
          "/patch/signature exceeds maximum size of "
              + GhidraCParserSupport.MAX_SIGNATURE_BYTES
              + " UTF-8 bytes");
    }
    if (rawSignature.isBlank()) {
      throw new DataTypeMutationValidationException(
          SIGNATURE_TARGET, "/patch/signature must not be blank");
    }
    String trimmed = rawSignature.trim();
    if (trimmed.indexOf('{') >= 0 || trimmed.indexOf('}') >= 0) {
      throw new DataTypeMutationValidationException(
          SIGNATURE_TARGET, "/patch/signature must be a prototype without a function body");
    }
    if (trimmed.endsWith(";")) {
      trimmed = trimmed.substring(0, trimmed.length() - 1).trim();
    }
    if (!trimmed.contains("(") || !trimmed.endsWith(")")) {
      throw new DataTypeMutationValidationException(
          SIGNATURE_TARGET, "invalid C function signature: " + rawSignature);
    }

    Program program = context.currentProgram();
    DataTypeManager programDtm = program.getDataTypeManager();
    ExtractedConvention extracted = extractCallingConvention(program, trimmed);

    try (StandAloneDataTypeManager scratch = GhidraCParserSupport.createScratchManager(programDtm);
        StandAloneDataTypeManager stdintFallback =
            GhidraCParserSupport.createStdintFallbackManager(programDtm)) {
      FunctionDefinitionDataType parsed =
          parseSignatureDefinition(
              programDtm, scratch, stdintFallback, function, extracted.cleanedSignature());

      if (parsed.getName() == null || parsed.getName().isBlank()) {
        throw new DataTypeMutationValidationException(
            SIGNATURE_TARGET, "C function signature must include a function name");
      }

      if (extracted.callingConvention() != null) {
        try {
          parsed.setCallingConvention(extracted.callingConvention());
        } catch (InvalidInputException error) {
          throw new DataTypeMutationValidationException(
              SIGNATURE_TARGET,
              "invalid calling convention: " + extracted.callingConvention(),
              error);
        }
      }

      materializeSignatureDataTypes(parsed, programDtm, stdintFallback);

      FunctionRenameOption renameOption =
          preserveExistingName || parsed.getName().equals(function.getName())
              ? FunctionRenameOption.NO_CHANGE
              : FunctionRenameOption.RENAME;
      ApplyFunctionSignatureCmd command =
          new ApplyFunctionSignatureCmd(
              function.getEntryPoint(),
              parsed,
              SourceType.USER_DEFINED,
              extracted.callingConvention() == null,
              false,
              DataTypeConflictHandler.DEFAULT_HANDLER,
              renameOption);
      if (!command.applyTo(program, context.flatApi().getMonitor())) {
        String status = command.getStatusMsg();
        throw new DataTypeMutationValidationException(
            SIGNATURE_TARGET,
            status == null || status.isBlank() ? "unable to apply function signature" : status);
      }
      Function refreshed =
          FunctionMutationSupport.refreshFunction(context, function, "signature update");
      return new AppliedSignature(refreshed, extracted.callingConvention() != null);
    }
  }

  private static FunctionDefinitionDataType parseSignatureDefinition(
      DataTypeManager programDtm,
      StandAloneDataTypeManager scratch,
      StandAloneDataTypeManager stdintFallback,
      Function function,
      String signatureText) {
    boolean canTrySimpleParser = canUseFunctionSignatureParser(signatureText);
    ParseException firstFailure = null;
    if (canTrySimpleParser) {
      DataTypeQueryService queryService =
          queryService(GhidraCParserSupport.allLookupDataTypes(programDtm, stdintFallback));
      FunctionSignatureParser signatureParser =
          new FunctionSignatureParser(programDtm, queryService);
      try {
        return signatureParser.parse(function.getSignature(), signatureText);
      } catch (CancelledException error) {
        throw new DataTypeMutationValidationException(
            SIGNATURE_TARGET, "function signature parsing was cancelled", error);
      } catch (ParseException error) {
        firstFailure = error;
      }
    }

    DataTypeManager[] lookupManagers =
        GhidraCParserSupport.lookupManagers(programDtm, stdintFallback);
    try {
      return GhidraCParserSupport.parseSignatureWithCParserUtils(
          scratch, lookupManagers, signatureText);
    } catch (ParseException cParserFailure) {
      Throwable reported = cParserFailure != null ? cParserFailure : firstFailure;
      throw new DataTypeMutationValidationException(
          SIGNATURE_TARGET,
          GhidraCParserSupport.cleanParseMessage(reported, null),
          reported);
    }
  }

  private static boolean canUseFunctionSignatureParser(String signatureText) {
    if (QUALIFIER_OR_SPECIFIER_PATTERN.matcher(signatureText).find()) {
      return false;
    }
    int firstOpen = signatureText.indexOf('(');
    int lastClose = signatureText.lastIndexOf(')');
    if (firstOpen <= 0 || lastClose <= firstOpen) {
      return false;
    }
    String prefix = signatureText.substring(0, firstOpen);
    if (prefix.indexOf('*') >= 0) {
      return false;
    }
    String params = signatureText.substring(firstOpen + 1, lastClose);
    return params.indexOf('(') < 0 && params.indexOf(')') < 0;
  }

  private static void materializeSignatureDataTypes(
      FunctionDefinitionDataType definition,
      DataTypeManager programDtm,
      StandAloneDataTypeManager stdintFallback) {
    GhidraCParserSupport.resolveReferencedStdintTypedefs(
        definition, programDtm, stdintFallback);
    DataType returnType = definition.getReturnType();
    if (returnType != null) {
      definition.setReturnType(
          GhidraDataTypeReferences.materializeParsedDataType(programDtm, returnType));
    }
    ParameterDefinition[] arguments = definition.getArguments();
    for (ParameterDefinition argument : arguments) {
      DataType argType = argument.getDataType();
      if (argType != null) {
        argument.setDataType(
            GhidraDataTypeReferences.materializeParsedDataType(programDtm, argType));
      }
    }
    definition.setArguments(arguments);
  }

  private static ExtractedConvention extractCallingConvention(Program program, String signature) {
    int firstOpen = signature.indexOf('(');
    if (firstOpen <= 0) {
      return new ExtractedConvention(signature, null);
    }
    String prefix = signature.substring(0, firstOpen);
    String suffix = signature.substring(firstOpen);
    Set<String> knownProgramConventions = new LinkedHashSet<>();
    knownProgramConventions.add(CompilerSpec.CALLING_CONVENTION_default);
    knownProgramConventions.addAll(program.getDataTypeManager().getKnownCallingConventionNames());
    knownProgramConventions.addAll(program.getFunctionManager().getCallingConventionNames());

    Set<String> candidateTokens = new LinkedHashSet<>(knownProgramConventions);
    candidateTokens.addAll(COMMON_CALLING_CONVENTIONS);
    for (String token : candidateTokens) {
      if (token == null || token.isBlank()) {
        continue;
      }
      Pattern tokenPattern =
          Pattern.compile("(?<![A-Za-z0-9_$])" + Pattern.quote(token) + "(?![A-Za-z0-9_$])");
      Matcher matcher = tokenPattern.matcher(prefix);
      if (matcher.find()) {
        if (!knownProgramConventions.contains(token)) {
          throw new DataTypeMutationValidationException(
              SIGNATURE_TARGET,
              "calling convention is not known by the target program: " + token);
        }
        String updatedPrefix =
            (prefix.substring(0, matcher.start()) + " " + prefix.substring(matcher.end()))
                .replaceAll("\\s+", " ")
                .trim();
        return new ExtractedConvention(updatedPrefix + suffix, token);
      }
    }
    return new ExtractedConvention(signature, null);
  }

  @SuppressWarnings({"PMD.UseProperClassLoader", "PMD.CompareObjectsWithEquals"})
  private static DataTypeQueryService queryService(List<DataType> allDataTypes) {
    return (DataTypeQueryService)
        Proxy.newProxyInstance(
            FunctionSignaturePatchSupport.class.getClassLoader(),
            new Class<?>[] {DataTypeQueryService.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getSortedDataTypeList" -> allDataTypes;
                  case "getCategoryPathList" -> List.of(CategoryPath.ROOT);
                  case "promptForDataType" -> null;
                  case "toString" -> "bridge-dt-query-service";
                  case "hashCode" -> System.identityHashCode(proxy);
                  case "equals" -> proxy == args[0];
                  default -> null;
                });
  }

  private record ExtractedConvention(String cleanedSignature, String callingConvention) {}
}
