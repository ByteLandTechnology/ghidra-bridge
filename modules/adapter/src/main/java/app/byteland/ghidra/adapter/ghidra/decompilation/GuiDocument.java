package app.byteland.ghidra.adapter.ghidra.decompilation;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.symbol.SymbolDescriptions;
import app.byteland.ghidra.service.decompilation.DecompilationResource.Line;
import app.byteland.ghidra.service.decompilation.DecompilationResource.LocatedToken;
import app.byteland.ghidra.service.symbol.SymbolResource;
import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.PrettyPrinter;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import java.util.ArrayList;
import java.util.List;

record GuiDocument(String code, List<Line> lines) {
  static GuiDocument render(Function function, ClangTokenGroup markup) {
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
        SymbolResource symbol = null;
        if (token instanceof ClangFuncNameToken nameToken) {
          Function target = DecompilerUtils.getFunction(program, nameToken);
          if (target != null) symbol = SymbolDescriptions.describe(target.getSymbol());
        }
        tokens.add(new LocatedToken(
            DecompilationServiceImpl.tokenKind(token), text, column, column + text.length(),
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

  private static String canonical(Address address) {
    return address == null ? null : AddressUtil.canonicalAddress(address);
  }
}
