package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.function.FunctionStorageSupport.ParsedStorage;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

final class FunctionVariableMutationSupport {
  private FunctionVariableMutationSupport() {}

  @FunctionalInterface
  interface HighSymbolMutation {
    void run() throws DuplicateNameException, InvalidInputException;
  }

  static void commitParameters(Function function, HighFunction highFunction) {
    SourceType signatureSource = function.getSignatureSource();
    if (signatureSource == null || signatureSource == SourceType.DEFAULT) {
      signatureSource = SourceType.USER_DEFINED;
    }
    SourceType effectiveSource = signatureSource;
    runHighSymbolMutation(
        "unable to commit inferred parameters",
        () ->
            HighFunctionDBUtil.commitParamsToDatabase(
                highFunction, true, ReturnCommitOption.NO_COMMIT, effectiveSource));
  }

  static void runHighSymbolMutation(String prefix, HighSymbolMutation mutation) {
    try {
      mutation.run();
    } catch (DuplicateNameException | InvalidInputException ex) {
      String detail = ex.getMessage();
      if (detail == null || detail.isBlank()) {
        detail = ex.getClass().getSimpleName();
      }
      throw new IllegalArgumentException(prefix + ": " + detail, ex);
    }
  }

  static Parameter requireParameter(Function function, int ordinal) {
    Parameter[] params = function.getParameters();
    if (ordinal < 0 || ordinal >= params.length) {
      throw new NoSuchElementException("parameter ordinal not found: " + ordinal);
    }
    return params[ordinal];
  }

  static Variable findCommittedLocalVariable(
      Function function, String variableName, ParsedStorage selectorStorage) {
    List<Variable> matches = new ArrayList<>();
    for (Variable variable : function.getLocalVariables()) {
      if (!variable.getName().equals(variableName)) {
        continue;
      }
      if (selectorStorage != null
          && !matchesStorage(variable.getVariableStorage(), selectorStorage)) {
        continue;
      }
      matches.add(variable);
    }
    if (matches.size() > 1) {
      throw new IllegalArgumentException(
          "ambiguous local variable selector; specify storage: " + variableName);
    }
    return matches.isEmpty() ? null : matches.getFirst();
  }

  static Variable requireLocalVariable(Function function, String variableName) {
    Variable variable = findCommittedLocalVariable(function, variableName, null);
    if (variable == null) {
      throw new NoSuchElementException("local variable not found: " + variableName);
    }
    return variable;
  }

  static HighSymbol requireHighLocalSymbol(
      HighFunction highFunction, String variableName, ParsedStorage selectorStorage) {
    if (highFunction == null || highFunction.getLocalSymbolMap() == null) {
      throw new NoSuchElementException("local variable not found: " + variableName);
    }
    List<HighSymbol> matches = new ArrayList<>();
    Iterator<HighSymbol> iterator = highFunction.getLocalSymbolMap().getSymbols();
    while (iterator.hasNext()) {
      HighSymbol symbol = iterator.next();
      if (symbol == null || symbol.isParameter() || symbol.isGlobal()) {
        continue;
      }
      if (!variableName.equals(symbol.getName())) {
        continue;
      }
      if (HighFunctionDBUtil.getFunctionVariable(symbol) != null && selectorStorage == null) {
        continue;
      }
      if (selectorStorage != null && !matchesHighSymbolStorage(symbol, selectorStorage)) {
        continue;
      }
      matches.add(symbol);
    }
    if (matches.isEmpty()) {
      throw new NoSuchElementException("local variable not found: " + variableName);
    }
    if (matches.size() > 1) {
      throw new IllegalArgumentException(
          "ambiguous local variable selector; specify storage: " + variableName);
    }
    return matches.getFirst();
  }

  private static boolean matchesHighSymbolStorage(
      HighSymbol symbol, ParsedStorage selectorStorage) {
    VariableStorage effective = FunctionDescriptions.effectiveStorage(symbol);
    if (effective != null && matchesStorage(effective, selectorStorage)) {
      return true;
    }
    VariableStorage raw = symbol.getFirstWholeMap() == null ? null : symbol.getStorage();
    return raw != null && matchesStorage(raw, selectorStorage);
  }

  private static boolean matchesStorage(VariableStorage actual, ParsedStorage expected) {
    return actual.equals(expected.storage())
        || actual.getSerializationString().equals(expected.serialization());
  }
}
