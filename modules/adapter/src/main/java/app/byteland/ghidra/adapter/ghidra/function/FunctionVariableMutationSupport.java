package app.byteland.ghidra.adapter.ghidra.function;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import java.util.NoSuchElementException;
import java.util.Optional;

final class FunctionVariableMutationSupport {
  private FunctionVariableMutationSupport() {}

  static Parameter requireParameter(Function function, int ordinal) {
    Parameter[] params = function.getParameters();
    if (ordinal < 0 || ordinal >= params.length) {
      throw new NoSuchElementException("parameter ordinal not found: " + ordinal);
    }
    return params[ordinal];
  }

  static Optional<Variable> findLocalVariable(Function function, String variableName) {
    Variable matched = null;
    for (Variable variable : function.getLocalVariables()) {
      if (variable.getName().equals(variableName)) {
        if (matched != null) {
          throw new IllegalArgumentException("ambiguous local variable name: " + variableName);
        }
        matched = variable;
      }
    }
    return Optional.ofNullable(matched);
  }

  static Variable requireLocalVariable(Function function, String variableName) {
    return findLocalVariable(function, variableName)
        .orElseThrow(
            () -> new NoSuchElementException("local variable not found: " + variableName));
  }
}
