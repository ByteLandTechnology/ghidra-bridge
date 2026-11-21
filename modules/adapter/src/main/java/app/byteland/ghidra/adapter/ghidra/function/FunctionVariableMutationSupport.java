package app.byteland.ghidra.adapter.ghidra.function;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.EquateSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import java.util.Iterator;
import java.util.NoSuchElementException;

final class FunctionVariableMutationSupport {
  private FunctionVariableMutationSupport() {}

  @FunctionalInterface
  interface HighSymbolMutation {
    void run() throws DuplicateNameException, InvalidInputException;
  }

  static Parameter requireParameter(Function function, int ordinal) {
    Parameter[] params = function.getParameters();
    if (ordinal < 0 || ordinal >= params.length) {
      throw new NoSuchElementException("parameter ordinal not found: " + ordinal);
    }
    return params[ordinal];
  }

  static Variable findLocalVariable(Function function, String variableName) {
    for (Variable variable : function.getLocalVariables()) {
      if (variable.getName().equals(variableName)) {
        return variable;
      }
    }
    return null;
  }

  static Variable requireLocalVariable(Function function, String variableName) {
    Variable variable = findLocalVariable(function, variableName);
    if (variable != null) {
      return variable;
    }
    throw new NoSuchElementException("local variable not found: " + variableName);
  }

  static HighSymbol findHighSymbol(HighFunction highFunction, String variableName) {
    if (highFunction == null || variableName == null) {
      return null;
    }
    LocalSymbolMap symbolMap = highFunction.getLocalSymbolMap();
    if (symbolMap == null) {
      return null;
    }
    Iterator<HighSymbol> symbols = symbolMap.getSymbols();
    while (symbols != null && symbols.hasNext()) {
      HighSymbol symbol = symbols.next();
      if (symbol == null
          || symbol instanceof EquateSymbol
          || symbol.isGlobal()
          || symbol.isHiddenReturn()) {
        continue;
      }
      if (variableName.equals(symbol.getName())) {
        return symbol;
      }
    }
    return null;
  }

  static boolean needsParameterCommit(HighSymbol highSymbol, HighFunction highFunction) {
    if (highFunction == null || (highSymbol != null && !highSymbol.isParameter())) {
      return false;
    }
    LocalSymbolMap symbolMap = highFunction.getLocalSymbolMap();
    if (symbolMap == null) {
      return false;
    }
    Parameter[] committed = highFunction.getFunction().getParameters();
    int count = symbolMap.getNumParams();
    if (committed.length != count) {
      return true;
    }
    for (int index = 0; index < count; index++) {
      HighSymbol paramSymbol = symbolMap.getParamSymbol(index);
      if (paramSymbol == null || paramSymbol.getCategoryIndex() != index) {
        return true;
      }
      if (paramSymbol.getStorage() == null
          || paramSymbol.getStorage().compareTo(committed[index].getVariableStorage()) != 0) {
        return true;
      }
    }
    return false;
  }

  static void commitParameters(Function function, HighFunction highFunction) {
    SourceType signatureSource = function.getSignatureSource();
    if (signatureSource == null || signatureSource == SourceType.DEFAULT) {
      signatureSource = SourceType.USER_DEFINED;
    }
    SourceType effectiveSource = signatureSource;
    runHighSymbolMutation(
        () ->
            HighFunctionDBUtil.commitParamsToDatabase(
                highFunction, true, ReturnCommitOption.NO_COMMIT, effectiveSource));
  }

  static void runHighSymbolMutation(HighSymbolMutation mutation) {
    try {
      mutation.run();
    } catch (DuplicateNameException | InvalidInputException error) {
      throw new IllegalArgumentException(
          error.getMessage() == null || error.getMessage().isBlank()
              ? "invalid variable update"
              : error.getMessage(),
          error);
    }
  }
}
