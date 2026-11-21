package app.byteland.ghidra.adapter.ghidra.decompilation;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.symbol.SymbolDescriptions;
import app.byteland.ghidra.service.decompilation.DecompilationResource.Line;
import app.byteland.ghidra.service.decompilation.DecompilationResource.LocatedToken;
import app.byteland.ghidra.service.decompilation.DecompilationResource.Token.Kind;
import app.byteland.ghidra.service.symbol.SymbolResource;
import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.decompiler.PrettyPrinter;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.EquateSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import java.util.ArrayList;
import java.util.List;

record GuiDocument(String code, List<Line> lines) {
  static GuiDocument render(Function function, ClangTokenGroup markup) {
    return render(function, null, markup);
  }

  static GuiDocument render(Function function, HighFunction highFunction, ClangTokenGroup markup) {
    if (markup == null) return new GuiDocument("", List.of());
    Program program = function.getProgram();
    List<ClangLine> nativeLines = new PrettyPrinter(function, markup, null).getLines();
    List<Line> lines = new ArrayList<>();
    StringBuilder code = new StringBuilder();
    Address previous = null;
    for (ClangLine line : nativeLines) {
      code.append(PrettyPrinter.getText(line)).append('\n');
      List<LocatedToken> tokens = new ArrayList<>();
      int column = line.getIndentString().length();
      for (ClangToken token : line.getAllTokens()) {
        Address closest = DecompilerUtils.getClosestAddress(program, token);
        if (closest == null) closest = previous;
        if (closest == null) closest = function.getEntryPoint();
        CodeUnit unit = program.getListing().getCodeUnitContaining(closest);
        String text = token.getText();
        Kind kind = DecompilationServiceImpl.tokenKind(token);
        SymbolResource symbol = resolveSymbol(program, function, highFunction, token, kind);
        tokens.add(new LocatedToken(
            kind, text, column, column + text.length(),
            canonical(token.getMinAddress()), canonical(token.getMaxAddress()),
            canonical(closest), unit == null ? null : canonical(unit.getMinAddress()), symbol));
        column += text.length();
      }
      lines.add(new Line(line.getLineNumber() - 1, line.getIndentString().length(), tokens));
      // findAddressBefore selects the first addressed token on the previous addressed line.
      for (ClangToken token : line.getAllTokens()) {
        if (token.getMinAddress() != null) {
          previous = token.getMinAddress();
          break;
        }
      }
    }
    return new GuiDocument(code.toString(), List.copyOf(lines));
  }

  static SymbolResource resolveSymbol(
      Program program,
      Function function,
      HighFunction highFunction,
      ClangToken token,
      Kind kind) {
    if (token instanceof ClangFuncNameToken nameToken) {
      Function target = DecompilerUtils.getFunction(program, nameToken);
      return target == null ? null : SymbolDescriptions.describe(target.getSymbol());
    }
    if (token instanceof ClangVariableToken variableToken) {
      HighSymbol highSymbol = variableToken.getHighSymbol(highFunction);
      if (highSymbol == null) {
        HighVariable highVariable = variableToken.getHighVariable();
        if (highVariable != null) {
          highSymbol = highVariable.getSymbol();
        }
      }
      if (highSymbol == null || highSymbol instanceof EquateSymbol) {
        return null;
      }
      Symbol backing = highSymbol.getSymbol();
      if (backing != null) {
        return SymbolDescriptions.describe(backing);
      }
      if (highSymbol.isGlobal()) {
        return null;
      }
      String symbolName = highSymbol.getName();
      if (symbolName == null || symbolName.isBlank()) {
        return null;
      }
      if (kind != Kind.VARIABLE && kind != Kind.PARAMETER && !highSymbol.isParameter()) {
        return null;
      }
      Address symbolAddress =
          highSymbol.getPCAddress() != null ? highSymbol.getPCAddress() : function.getEntryPoint();
      String symbolType =
          (highSymbol.isParameter() || kind == Kind.PARAMETER)
              ? SymbolType.PARAMETER.toString()
              : SymbolType.LOCAL_VAR.toString();
      return new SymbolResource(
          String.valueOf(highSymbol.getId()),
          symbolName,
          canonical(symbolAddress),
          function.getName(true),
          symbolType,
          SourceType.DEFAULT.toString(),
          false,
          null);
    }
    return null;
  }

  private static String canonical(Address address) {
    return address == null ? null : AddressUtil.canonicalAddress(address);
  }
}
