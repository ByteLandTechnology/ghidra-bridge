package app.byteland.ghidra.adapter.ghidra.decompilation;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.function.FunctionDescriptions;
import app.byteland.ghidra.adapter.ghidra.symbol.SymbolDescriptions;
import app.byteland.ghidra.service.decompilation.DecompilationResource.Line;
import app.byteland.ghidra.service.decompilation.DecompilationResource.LocatedToken;
import app.byteland.ghidra.service.decompilation.DecompilationResource.Token;
import app.byteland.ghidra.service.symbol.SymbolResource;
import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.ClangVariableDecl;
import ghidra.app.decompiler.PrettyPrinter;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import java.util.ArrayList;
import java.util.List;

record GuiDocument(String code, List<Line> lines) {
  static GuiDocument render(Function function, ClangTokenGroup markup) {
    return render(function, markup, null);
  }

  static GuiDocument render(
      Function function, ClangTokenGroup markup, HighFunction highFunction) {
    if (markup == null) return new GuiDocument("", List.of());
    Program program = function.getProgram();
    String entry = AddressUtil.canonicalAddress(function.getEntryPoint());
    String namespace =
        function.getSymbol() == null ? function.getName() : function.getSymbol().getName(true);
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
        Token.Kind kind = DecompilationServiceImpl.tokenKind(token);
        SymbolResource symbol = describeTokenSymbol(
            program, entry, namespace, token, kind, highFunction);
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

  private static SymbolResource describeTokenSymbol(
      Program program,
      String entry,
      String namespace,
      ClangToken token,
      Token.Kind kind,
      HighFunction highFunction) {
    if (token instanceof ClangFuncNameToken nameToken) {
      Function target = DecompilerUtils.getFunction(program, nameToken);
      return target == null ? null : SymbolDescriptions.describe(target.getSymbol());
    }
    if ((kind != Token.Kind.VARIABLE && kind != Token.Kind.PARAMETER)
        || token instanceof ClangFieldToken) {
      return null;
    }
    HighSymbol highSymbol = resolveHighSymbol(token, highFunction);
    if (highSymbol == null || highSymbol.isGlobal()) {
      return null;
    }
    Symbol dbSymbol = highSymbol.getSymbol();
    String sourceType =
        String.valueOf(dbSymbol == null ? SourceType.DEFAULT : dbSymbol.getSource());
    boolean primary = dbSymbol == null || dbSymbol.isPrimary();
    if (highSymbol.isParameter()) {
      return new SymbolResource(
          "parameter:" + highSymbol.getCategoryIndex(),
          highSymbol.getName(),
          entry,
          namespace,
          SymbolType.PARAMETER.toString(),
          sourceType,
          primary,
          null);
    }
    VariableStorage storage = FunctionDescriptions.effectiveStorage(highSymbol);
    String serialization = storage == null ? "" : storage.getSerializationString();
    return new SymbolResource(
        "local:" + highSymbol.getId() + ":" + serialization,
        highSymbol.getName(),
        entry,
        namespace,
        SymbolType.LOCAL_VAR.toString(),
        sourceType,
        primary,
        null);
  }

  private static HighSymbol resolveHighSymbol(ClangToken token, HighFunction highFunction) {
    HighSymbol symbol = token.getHighSymbol(highFunction);
    if (symbol == null && token.Parent() instanceof ClangVariableDecl declaration) {
      symbol = declaration.getHighSymbol();
    }
    return symbol;
  }

  private static String canonical(Address address) {
    return address == null ? null : AddressUtil.canonicalAddress(address);
  }
}
