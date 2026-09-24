package app.byteland.ghidra.adapter.ghidra.function;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import java.util.NoSuchElementException;

final class FunctionVariableMutationSupport {
  private FunctionVariableMutationSupport() {}

  static Parameter requireParameter(Function function, int ordinal) {
    Parameter[] params = function.getParameters();
    if (ordinal < 0 || ordinal >= params.length) {
      throw new NoSuchElementException("parameter ordinal not found: " + ordinal);
    }
    return params[ordinal];
  }

  static Variable requireLocalVariable(Function function, String variableName) {
    for (Variable variable : function.getLocalVariables()) {
      if (variable.getName().equals(variableName)) {
        return variable;
      }
    }
    throw new NoSuchElementException("local variable not found: " + variableName);
  }
}
