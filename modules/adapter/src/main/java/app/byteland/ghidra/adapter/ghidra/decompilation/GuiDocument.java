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
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.PrettyPrinter;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

record GuiDocument(String code, List<Line> lines) {
  static String renderText(Function function, DecompileResults results) {
    if (results == null) return "";
    ClangTokenGroup markup = results.getCCodeMarkup();
    if (markup != null) {
      return renderText(function, markup);
    }
    DecompiledFunction decompiled = results.getDecompiledFunction();
    return decompiled == null || decompiled.getC() == null ? "" : decompiled.getC();
  }

  static String renderText(Function function, ClangTokenGroup markup) {
    if (markup == null) return "";
    StringBuilder code = new StringBuilder();
    for (ClangLine line : new PrettyPrinter(function, markup, null).getLines()) {
      code.append(PrettyPrinter.getText(line)).append('\n');
    }
    return code.toString();
  }

  static GuiDocument render(Function function, ClangTokenGroup markup) {
    return render(function, markup, null);
  }

  static GuiDocument render(
      Function function, ClangTokenGroup markup, HighFunction highFunction) {
    if (markup == null) return new GuiDocument("", List.of());
    return renderLines(function, new PrettyPrinter(function, markup, null).getLines(), highFunction);
  }

  static GuiDocument renderLines(Function function, List<ClangLine> nativeLines) {
    return renderLines(function, nativeLines, null);
  }

  static GuiDocument renderLines(
      Function function, List<ClangLine> nativeLines, HighFunction highFunction) {
    Program program = function.getProgram();
    Listing listing = program.getListing();
    Address entryPoint = function.getEntryPoint();
    Map<Address, String> canonicalAddresses = new HashMap<>();
    Map<Address, String> codeUnitAddresses = new HashMap<>();
    Map<Function, SymbolResource> functionSymbols = new HashMap<>();
    String[] namespaceHolder = new String[1];
    List<Line> lines = new ArrayList<>(nativeLines.size());
    StringBuilder code = new StringBuilder();
    Address previous = null;
    boolean hasLastClosest = false;
    Address lastClosest = null;
    String lastLocationAddress = null;
    String lastCodeUnitAddress = null;
    for (ClangLine line : nativeLines) {
      code.append(PrettyPrinter.getText(line)).append('\n');
      List<ClangToken> lineTokens = line.getAllTokens();
      List<LocatedToken> tokens = new ArrayList<>(lineTokens.size());
      int indent = line.getIndentString().length();
      int column = indent;
      Address firstLineAddress = null;
      for (ClangToken token : lineTokens) {
        Address minAddress = token.getMinAddress();
        if (firstLineAddress == null && minAddress != null) {
          firstLineAddress = minAddress;
        }
        Address closest =
            minAddress != null ? minAddress : DecompilerUtils.getClosestAddress(program, token);
        if (closest == null) closest = previous;
        if (closest == null) closest = entryPoint;
        String locationAddress;
        String codeUnitAddress;
        if (hasLastClosest && Objects.equals(closest, lastClosest)) {
          locationAddress = lastLocationAddress;
          codeUnitAddress = lastCodeUnitAddress;
        } else {
          locationAddress = canonical(closest, canonicalAddresses);
          if (codeUnitAddresses.containsKey(closest)) {
            codeUnitAddress = codeUnitAddresses.get(closest);
          } else {
            CodeUnit unit = listing.getCodeUnitContaining(closest);
            codeUnitAddress =
                unit == null ? null : canonical(unit.getMinAddress(), canonicalAddresses);
            codeUnitAddresses.put(closest, codeUnitAddress);
          }
          hasLastClosest = true;
          lastClosest = closest;
          lastLocationAddress = locationAddress;
          lastCodeUnitAddress = codeUnitAddress;
        }
        Address maxAddress = token.getMaxAddress();
        String address =
            minAddress == null
                ? null
                : (Objects.equals(minAddress, closest)
                    ? locationAddress
                    : canonical(minAddress, canonicalAddresses));
        String maxCanonical =
            maxAddress == null
                ? null
                : (Objects.equals(maxAddress, closest)
                    ? locationAddress
                    : canonical(maxAddress, canonicalAddresses));
        String text = token.getText();
        Token.Kind kind = DecompilationServiceImpl.tokenKind(token);
        SymbolResource symbol =
            describeTokenSymbol(
                program,
                function,
                entryPoint,
                canonicalAddresses,
                functionSymbols,
                namespaceHolder,
                token,
                kind,
                highFunction);
        tokens.add(
            new LocatedToken(
                kind,
                text,
                column,
                column + text.length(),
                address,
                maxCanonical,
                locationAddress,
                codeUnitAddress,
                symbol));
        column += text.length();
      }
      lines.add(new Line(line.getLineNumber() - 1, indent, tokens));
      // findAddressBefore selects the first addressed token on the previous addressed line.
      if (firstLineAddress != null) {
        previous = firstLineAddress;
      }
    }
    return new GuiDocument(code.toString(), List.copyOf(lines));
  }

  private static SymbolResource describeTokenSymbol(
      Program program,
      Function function,
      Address entryPoint,
      Map<Address, String> canonicalAddresses,
      Map<Function, SymbolResource> functionSymbols,
      String[] namespaceHolder,
      ClangToken token,
      Token.Kind kind,
      HighFunction highFunction) {
    if (token instanceof ClangFuncNameToken nameToken) {
      Function target = DecompilerUtils.getFunction(program, nameToken);
      if (target == null) return null;
      return functionSymbols.computeIfAbsent(
          target, fn -> SymbolDescriptions.describe(fn.getSymbol()));
    }
    if ((kind != Token.Kind.VARIABLE && kind != Token.Kind.PARAMETER)
        || token instanceof ClangFieldToken) {
      return null;
    }
    HighSymbol highSymbol = resolveHighSymbol(token, highFunction);
    if (highSymbol == null || highSymbol.isGlobal()) {
      return null;
    }
    String entry = canonical(entryPoint, canonicalAddresses);
    String namespace = namespaceHolder[0];
    if (namespace == null) {
      Symbol functionSymbol = function.getSymbol();
      namespace = functionSymbol == null ? function.getName() : functionSymbol.getName(true);
      namespaceHolder[0] = namespace;
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

  private static String canonical(Address address, Map<Address, String> canonicalAddresses) {
    return address == null
        ? null
        : canonicalAddresses.computeIfAbsent(address, AddressUtil::canonicalAddress);
  }
}
