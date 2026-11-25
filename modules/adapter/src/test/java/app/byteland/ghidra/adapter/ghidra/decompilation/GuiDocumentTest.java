package app.byteland.ghidra.adapter.ghidra.decompilation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.symbol.SymbolDescriptions;
import app.byteland.ghidra.service.decompilation.DecompilationResource.Line;
import app.byteland.ghidra.service.decompilation.DecompilationResource.LocatedToken;
import app.byteland.ghidra.service.decompilation.DecompilationResource.Token;
import app.byteland.ghidra.service.symbol.SymbolResource;
import ghidra.app.decompiler.ClangBreak;
import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangStatement;
import ghidra.app.decompiler.ClangSyntaxToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.PrettyPrinter;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class GuiDocumentTest {
  @Test
  void preservesQuotedLiteralsAndMatchesDocumentIndentation() {
    String stringLiteral = "\"a; { b } /* block */ // line \\\"quoted\\\"\"";
    String charSemicolon = "';'";
    String charBrace = "'{'";

    ClangTokenGroup markup = new ClangTokenGroup(null);
    markup.AddTokenGroup(new ClangToken(markup, "int", ClangToken.TYPE_COLOR));
    markup.AddTokenGroup(new ClangToken(markup, " ", ClangToken.DEFAULT_COLOR));
    markup.AddTokenGroup(new ClangToken(markup, "parse", ClangToken.FUNCTION_COLOR));
    markup.AddTokenGroup(new ClangSyntaxToken(markup, "(void)"));
    markup.AddTokenGroup(new ClangBreak(markup, 0));
    markup.AddTokenGroup(new ClangSyntaxToken(markup, "{"));
    markup.AddTokenGroup(new ClangBreak(markup, 1));
    markup.AddTokenGroup(new ClangToken(markup, "puts", ClangToken.FUNCTION_COLOR));
    markup.AddTokenGroup(new ClangSyntaxToken(markup, "("));
    markup.AddTokenGroup(new ClangToken(markup, stringLiteral, ClangToken.CONST_COLOR));
    markup.AddTokenGroup(new ClangSyntaxToken(markup, ");"));
    markup.AddTokenGroup(new ClangBreak(markup, 1));
    markup.AddTokenGroup(new ClangToken(markup, "if", ClangToken.KEYWORD_COLOR));
    markup.AddTokenGroup(new ClangSyntaxToken(markup, " ("));
    markup.AddTokenGroup(new ClangToken(markup, charSemicolon, ClangToken.CONST_COLOR));
    markup.AddTokenGroup(new ClangSyntaxToken(markup, " != "));
    markup.AddTokenGroup(new ClangToken(markup, charBrace, ClangToken.CONST_COLOR));
    markup.AddTokenGroup(new ClangSyntaxToken(markup, ") {"));
    markup.AddTokenGroup(new ClangBreak(markup, 2));
    markup.AddTokenGroup(new ClangToken(markup, "return", ClangToken.KEYWORD_COLOR));
    markup.AddTokenGroup(new ClangSyntaxToken(markup, " "));
    markup.AddTokenGroup(new ClangToken(markup, "0", ClangToken.CONST_COLOR));
    markup.AddTokenGroup(new ClangSyntaxToken(markup, ";"));
    markup.AddTokenGroup(new ClangBreak(markup, 1));
    markup.AddTokenGroup(new ClangSyntaxToken(markup, "}"));
    markup.AddTokenGroup(new ClangBreak(markup, 0));
    markup.AddTokenGroup(new ClangSyntaxToken(markup, "}"));

    Function function = stubFunction();
    String textCode = GuiDocument.renderText(function, resultsWith(function, markup, null));
    GuiDocument document = GuiDocument.render(function, markup);

    assertEquals(document.code(), textCode);
    assertTrue(
        textCode.contains(PrettyPrinter.INDENT_STRING + "puts(" + stringLiteral + ");\n"));
    assertTrue(
        textCode.contains(PrettyPrinter.INDENT_STRING + "if (';' != '{') {\n"));
    assertTrue(
        textCode.contains(PrettyPrinter.INDENT_STRING.repeat(2) + "return 0;\n"));
    assertFalse(textCode.contains("\"a;\n"));
  }

  @Test
  void returnsRawCodeOrEmptyStringWhenDecompilationTimesOutWithNullMarkup() {
    Function function = stubFunction();

    DecompileResults fallbackResults =
        resultsWith(function, null, new DecompiledFunction("void f(void);", "/* partial */"));
    assertEquals("/* partial */", GuiDocument.renderText(function, fallbackResults));

    DecompileResults nullCResults =
        resultsWith(function, null, new DecompiledFunction("void f(void);", null));
    assertEquals("", GuiDocument.renderText(function, nullCResults));

    DecompileResults timedOutResults = resultsWith(function, null, null);
    assertEquals("", GuiDocument.renderText(function, timedOutResults));
    assertEquals("", GuiDocument.renderText(function, (DecompileResults) null));
    assertEquals("", GuiDocument.renderText(function, (ClangTokenGroup) null));

    GuiDocument emptyDoc = GuiDocument.render(function, null);
    assertEquals("", emptyDoc.code());
    assertEquals(List.of(), emptyDoc.lines());
  }

  @Test
  void nullMarkupReturnsEmptyDocumentWithoutQueryingFunction() {
    Function untouchedFunction =
        proxy(
            Function.class,
            (self, method, args) -> {
              throw new AssertionError("unexpected call: " + method.getName());
            });

    GuiDocument document = GuiDocument.render(untouchedFunction, null);

    assertEquals("", document.code());
    assertEquals(List.of(), document.lines());
  }

  @Test
  void deduplicatesCanonicalAddressesCodeUnitsAndCalleeSymbolsWithinSingleRender() {
    Map<Long, AtomicInteger> canonicalCounts = new HashMap<>();
    Address entry = countedAddress(0x1000L, canonicalCounts);
    Address unitStartA = countedAddress(0x1010L, canonicalCounts);
    Address callSiteA = countedAddress(0x1012L, canonicalCounts);
    Address callSiteAMax = countedAddress(0x1015L, canonicalCounts);
    Address unitStartB = countedAddress(0x1020L, canonicalCounts);
    Address callSiteB = countedAddress(0x1022L, canonicalCounts);
    Address helperEntry = countedAddress(0x2000L, canonicalCounts);
    Address loggerEntry = countedAddress(0x2100L, canonicalCounts);
    Address missingEntry = countedAddress(0x2200L, canonicalCounts);

    Map<Address, CodeUnit> codeUnitsByAddress = new HashMap<>();
    codeUnitsByAddress.put(entry, codeUnit(entry));
    codeUnitsByAddress.put(callSiteA, codeUnit(unitStartA));
    codeUnitsByAddress.put(callSiteB, codeUnit(unitStartB));

    AtomicInteger helperSymbolCalls = new AtomicInteger();
    AtomicInteger loggerSymbolCalls = new AtomicInteger();
    Symbol helperSymbol = symbol(101L, "helper_alpha", helperEntry, "app", true);
    Symbol loggerSymbol = symbol(102L, "logger_beta", loggerEntry, "diag", true);
    Function helperFunction = calleeFunction(helperSymbol, helperSymbolCalls);
    Function loggerFunction = calleeFunction(loggerSymbol, loggerSymbolCalls);

    Map<Address, Function> referencedFunctions = new HashMap<>();
    referencedFunctions.put(helperEntry, helperFunction);
    referencedFunctions.put(loggerEntry, loggerFunction);

    Map<Address, AtomicInteger> codeUnitQueries = new HashMap<>();
    Listing listing = countedListing(codeUnitsByAddress, codeUnitQueries);
    FunctionManager functionManager = functionManager(referencedFunctions);
    AtomicInteger getListingCalls = new AtomicInteger();
    Program program = program(listing, functionManager, getListingCalls);
    AtomicInteger getProgramCalls = new AtomicInteger();
    AtomicInteger getEntryPointCalls = new AtomicInteger();
    Function owner = ownerFunction(program, entry, getProgramCalls, getEntryPointCalls);

    // Line 1: unaddressed signature line -> falls back to entry (0x1000) across adjacent tokens.
    ClangLine line1 = new ClangLine(1, 0);
    line1.addToken(token("void", ClangToken.TYPE_COLOR, null, null));
    line1.addToken(token(" ", ClangToken.DEFAULT_COLOR, null, null));
    line1.addToken(token("run()", ClangToken.FUNCTION_COLOR, null, null));

    // Line 2: helper_alpha(x); at callSiteA..callSiteAMax inside code unit unitStartA.
    ClangLine line2 = new ClangLine(2, 2);
    line2.addToken(callToken("helper_alpha", helperEntry, callSiteA, callSiteAMax));
    line2.addToken(token("(", ClangToken.DEFAULT_COLOR, null, null));
    line2.addToken(token("x", ClangToken.VARIABLE_COLOR, callSiteA, callSiteA));
    line2.addToken(token(");", ClangToken.DEFAULT_COLOR, null, null));

    // Line 3: logger_beta(); + unresolved_fn(); at callSiteB inside code unit unitStartB.
    ClangLine line3 = new ClangLine(3, 1);
    line3.addToken(callToken("logger_beta", loggerEntry, callSiteB, callSiteB));
    line3.addToken(token("(); ", ClangToken.DEFAULT_COLOR, null, null));
    line3.addToken(callToken("unresolved_fn", missingEntry, callSiteB, callSiteB));
    line3.addToken(token("();", ClangToken.DEFAULT_COLOR, null, null));

    // Line 4: non-adjacent revisit of callSiteA (with a distinct equal Address) and second call to helper_alpha.
    Address duplicateCallSiteA = countedAddress(0x1012L, canonicalCounts);
    ClangLine line4 = new ClangLine(4, 1);
    line4.addToken(callToken("helper_alpha", helperEntry, duplicateCallSiteA, callSiteAMax));
    line4.addToken(token("(y);", ClangToken.DEFAULT_COLOR, null, null));

    // Reset address space name counters after fixture construction (Varnode setup).
    canonicalCounts.values().forEach(counter -> counter.set(0));

    List<ClangLine> nativeLines = List.of(line1, line2, line3, line4);
    GuiDocument rendered = GuiDocument.renderLines(owner, nativeLines);

    assertEquals(1, getProgramCalls.get(), "function.getProgram() must run once");
    assertEquals(1, getListingCalls.get(), "program.getListing() must run once");
    assertEquals(1, getEntryPointCalls.get(), "function.getEntryPoint() must run once");

    assertEquals(3, codeUnitQueries.size(), "only 3 distinct closest addresses should be queried");
    assertEquals(1, codeUnitQueries.get(entry).get());
    assertEquals(1, codeUnitQueries.get(callSiteA).get());
    assertEquals(1, codeUnitQueries.get(callSiteB).get());

    // Every distinct address touched during render is canonicalized once.
    assertEquals(1, canonicalCounts.get(0x1000L).get(), "entry canonicalized once");
    assertEquals(1, canonicalCounts.get(0x1010L).get(), "unitStartA canonicalized once");
    assertEquals(1, canonicalCounts.get(0x1012L).get(), "callSiteA canonicalized once");
    assertEquals(1, canonicalCounts.get(0x1015L).get(), "callSiteAMax canonicalized once");
    assertEquals(1, canonicalCounts.get(0x1020L).get(), "unitStartB canonicalized once");
    assertEquals(1, canonicalCounts.get(0x1022L).get(), "callSiteB canonicalized once");
    assertEquals(1, canonicalCounts.get(0x2000L).get(), "helperEntry canonicalized once");
    assertEquals(1, canonicalCounts.get(0x2100L).get(), "loggerEntry canonicalized once");
    assertEquals(0, canonicalCounts.get(0x2200L).get(), "unresolved callee never canonicalized");

    // Repeated helper_alpha calls describe the callee symbol once and share the SymbolResource.
    assertEquals(1, helperSymbolCalls.get(), "helper_alpha symbol described once");
    assertEquals(1, loggerSymbolCalls.get(), "logger_beta symbol described once");
    SymbolResource firstHelperSymbol = rendered.lines().get(1).tokens().get(0).symbol();
    SymbolResource secondHelperSymbol = rendered.lines().get(3).tokens().get(0).symbol();
    assertSame(firstHelperSymbol, secondHelperSymbol);
    assertEquals("helper_alpha", firstHelperSymbol.name());
    assertNull(rendered.lines().get(2).tokens().get(2).symbol(), "unresolved callee has null symbol");

    // Verify zero state persists across separate render calls.
    GuiDocument secondRender = GuiDocument.renderLines(owner, List.of(line2));
    assertEquals(2, helperSymbolCalls.get(), "second render must not retain prior symbol cache");
    assertEquals(2, codeUnitQueries.get(callSiteA).get(), "second render must re-query code unit");
    assertEquals("  helper_alpha(x);\n", secondRender.code());
  }

  @Test
  void cachesNullCodeUnitWithoutRepeatingLookup() {
    Map<Long, AtomicInteger> canonicalCounts = new HashMap<>();
    Address entry = countedAddress(0x1000L, canonicalCounts);
    Address unmapped = countedAddress(0x9000L, canonicalCounts);
    Address mapped = countedAddress(0x1010L, canonicalCounts);

    Map<Address, CodeUnit> codeUnitsByAddress = new HashMap<>();
    codeUnitsByAddress.put(mapped, codeUnit(mapped));

    Map<Address, AtomicInteger> codeUnitQueries = new HashMap<>();
    Listing listing = countedListing(codeUnitsByAddress, codeUnitQueries);
    Program program = program(listing, functionManager(Map.of()), new AtomicInteger());
    Function owner = ownerFunction(program, entry, new AtomicInteger(), new AtomicInteger());

    // Line 1: two adjacent tokens map to unmapped (0x9000 -> null CodeUnit).
    ClangLine line1 = new ClangLine(1, 0);
    line1.addToken(token("ext", ClangToken.GLOBAL_COLOR, unmapped, unmapped));
    line1.addToken(token(" + 1", ClangToken.DEFAULT_COLOR, null, null));

    // Line 2: a middle mapped address (0x1010) breaks the adjacent-token fast path.
    ClangLine line2 = new ClangLine(2, 0);
    line2.addToken(token("ok", ClangToken.VARIABLE_COLOR, mapped, mapped));

    // Line 3: revisits unmapped (0x9000); containsKey check must prevent a second query.
    ClangLine line3 = new ClangLine(3, 0);
    line3.addToken(token("ext", ClangToken.GLOBAL_COLOR, unmapped, unmapped));

    GuiDocument document = GuiDocument.renderLines(owner, List.of(line1, line2, line3));

    assertEquals(1, codeUnitQueries.get(unmapped).get(), "null CodeUnit must be cached");
    assertEquals(1, codeUnitQueries.get(mapped).get());
    assertNull(document.lines().get(0).tokens().get(0).codeUnitAddress());
    assertNull(document.lines().get(0).tokens().get(1).codeUnitAddress());
    assertEquals("ram:00001010", document.lines().get(1).tokens().get(0).codeUnitAddress());
    assertNull(document.lines().get(2).tokens().get(0).codeUnitAddress());
    assertEquals("ram:00009000", document.lines().get(2).tokens().get(0).locationAddress());
  }

  @Test
  void tracksLineFallbackAddressesInSinglePass() {
    Map<Long, AtomicInteger> canonicalCounts = new HashMap<>();
    Address entry = countedAddress(0x1000L, canonicalCounts);
    Address firstOnLine2 = countedAddress(0x1010L, canonicalCounts);
    Address secondOnLine2 = countedAddress(0x1014L, canonicalCounts);
    Address onLine3 = countedAddress(0x1020L, canonicalCounts);

    Map<Address, CodeUnit> codeUnits =
        Map.of(
            entry, codeUnit(entry),
            firstOnLine2, codeUnit(firstOnLine2),
            secondOnLine2, codeUnit(secondOnLine2),
            onLine3, codeUnit(onLine3));
    Listing listing = countedListing(codeUnits, new HashMap<>());
    Program program = program(listing, functionManager(Map.of()), new AtomicInteger());
    Function owner = ownerFunction(program, entry, new AtomicInteger(), new AtomicInteger());

    // Line 1: unaddressed open brace before any addressed token falls back to entry (0x1000).
    ClangLine line1 = new ClangLine(1, 0);
    line1.addToken(token("{", ClangToken.DEFAULT_COLOR, null, null));

    // Line 2: two addressed tokens (0x1010 then 0x1014) -> previous becomes 0x1010 (first!).
    ClangLine line2 = new ClangLine(2, 1);
    line2.addToken(token("a", ClangToken.VARIABLE_COLOR, firstOnLine2, firstOnLine2));
    line2.addToken(token(" = ", ClangToken.DEFAULT_COLOR, null, null));
    line2.addToken(token("b", ClangToken.VARIABLE_COLOR, secondOnLine2, secondOnLine2));

    // Line 3: first token returns null from getClosestAddress, then 0x1020 appears on the same line.
    // Because previous updates only after the line finishes, the first token inherits 0x1010.
    ClangLine detachedEmptyParent = new ClangLine(99, 0);
    ClangLine line3 = new ClangLine(3, 1);
    ClangToken detachedLeading =
        new TestToken("/*lead*/ ", ClangToken.COMMENT_COLOR, null, null) {
          @Override
          public ClangLine getLineParent() {
            return detachedEmptyParent;
          }
        };
    line3.addToken(detachedLeading);
    line3.addToken(token("c", ClangToken.VARIABLE_COLOR, onLine3, onLine3));

    // Line 4 & Line 5: consecutive unaddressed lines -> both inherit 0x1020 from Line 3.
    ClangLine line4 = new ClangLine(4, 1);
    line4.addToken(token("// comment", ClangToken.COMMENT_COLOR, null, null));
    ClangLine line5 = new ClangLine(5, 0);
    line5.addToken(token("}", ClangToken.DEFAULT_COLOR, null, null));

    GuiDocument document =
        GuiDocument.renderLines(owner, List.of(line1, line2, line3, line4, line5));

    assertEquals("ram:00001000", document.lines().get(0).tokens().get(0).locationAddress());
    assertEquals("ram:00001010", document.lines().get(1).tokens().get(0).locationAddress());
    assertEquals("ram:00001014", document.lines().get(1).tokens().get(1).locationAddress());
    assertEquals("ram:00001014", document.lines().get(1).tokens().get(2).locationAddress());
    assertEquals(
        "ram:00001010",
        document.lines().get(2).tokens().get(0).locationAddress(),
        "leading token with null closestAddress must inherit prior line address");
    assertEquals("ram:00001020", document.lines().get(2).tokens().get(1).locationAddress());
    assertEquals("ram:00001020", document.lines().get(3).tokens().get(0).locationAddress());
    assertEquals("ram:00001020", document.lines().get(4).tokens().get(0).locationAddress());
  }

  @Test
  void preservesIdenticalLocatedTokenAndLineOutput() {
    Map<Long, AtomicInteger> canonicalCounts = new HashMap<>();
    Address entry = countedAddress(0x401000L, canonicalCounts);
    Address insn1Unit = countedAddress(0x401004L, canonicalCounts);
    Address insn1 = countedAddress(0x401006L, canonicalCounts);
    Address insn1Max = countedAddress(0x401009L, canonicalCounts);
    Address insn2 = countedAddress(0x401010L, canonicalCounts);
    Address unmapped = countedAddress(0x500000L, canonicalCounts);
    Address calleeAddr = countedAddress(0x402000L, canonicalCounts);

    Map<Address, CodeUnit> codeUnits = new HashMap<>();
    codeUnits.put(entry, codeUnit(entry));
    codeUnits.put(insn1, codeUnit(insn1Unit));
    codeUnits.put(insn2, codeUnit(insn2));

    Symbol calleeSymbol = symbol(77L, "compute_crc", calleeAddr, "crypto", true);
    Function callee = calleeFunction(calleeSymbol, new AtomicInteger());
    Listing listing = countedListing(codeUnits, new HashMap<>());
    FunctionManager functionManager = functionManager(Map.of(calleeAddr, callee));
    Program program = program(listing, functionManager, new AtomicInteger());
    Function owner = ownerFunction(program, entry, new AtomicInteger(), new AtomicInteger());

    ClangLine line1 = new ClangLine(1, 0);
    line1.addToken(token("int", ClangToken.TYPE_COLOR, null, null));
    line1.addToken(token(" ", ClangToken.DEFAULT_COLOR, null, null));
    line1.addToken(token("main(void)", ClangToken.FUNCTION_COLOR, null, null));

    ClangLine line2 = new ClangLine(2, 2);
    line2.addToken(token("int", ClangToken.TYPE_COLOR, null, null));
    line2.addToken(token(" crc = ", ClangToken.DEFAULT_COLOR, null, null));
    line2.addToken(callToken("compute_crc", calleeAddr, insn1, insn1Max));
    line2.addToken(token("(0x2a);", ClangToken.CONST_COLOR, insn1, insn1));

    ClangLine line3 = new ClangLine(3, 2);
    line3.addToken(token("sink = ", ClangToken.GLOBAL_COLOR, unmapped, unmapped));
    line3.addToken(token("crc;", ClangToken.VARIABLE_COLOR, insn2, insn2));

    ClangLine line4 = new ClangLine(4, 2);
    line4.addToken(token("return", ClangToken.KEYWORD_COLOR, null, null));
    line4.addToken(token(" crc;", ClangToken.DEFAULT_COLOR, null, null));

    List<ClangLine> nativeLines = List.of(line1, line2, line3, line4);

    GuiDocument expected = referenceRender(owner, nativeLines);
    GuiDocument actual = GuiDocument.renderLines(owner, nativeLines);

    assertEquals(expected.code(), actual.code());
    assertEquals(expected.lines(), actual.lines());
    assertEquals(expected, actual);

    // Spot-check UTF-16 column spans with 2-space indentation on line 2 (0-based line number 1).
    Line secondLine = actual.lines().get(1);
    assertEquals(1, secondLine.number());
    assertEquals(2, secondLine.indent());
    assertEquals(Token.Kind.TYPE, secondLine.tokens().get(0).kind());
    assertEquals(2, secondLine.tokens().get(0).start());
    assertEquals(5, secondLine.tokens().get(0).end());
    assertEquals(Token.Kind.FUNCTION, secondLine.tokens().get(2).kind());
    assertEquals(12, secondLine.tokens().get(2).start());
    assertEquals(23, secondLine.tokens().get(2).end());
    assertTrue(actual.code().endsWith("  return crc;\n"));
  }

  private static GuiDocument referenceRender(Function function, List<ClangLine> nativeLines) {
    Program program = function.getProgram();
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
        tokens.add(
            new LocatedToken(
                DecompilationServiceImpl.tokenKind(token),
                text,
                column,
                column + text.length(),
                uncachedCanonical(token.getMinAddress()),
                uncachedCanonical(token.getMaxAddress()),
                uncachedCanonical(closest),
                unit == null ? null : uncachedCanonical(unit.getMinAddress()),
                symbol));
        column += text.length();
      }
      lines.add(new Line(line.getLineNumber() - 1, line.getIndentString().length(), tokens));
      for (ClangToken token : line.getAllTokens()) {
        if (token.getMinAddress() != null) {
          previous = token.getMinAddress();
          break;
        }
      }
    }
    return new GuiDocument(code.toString(), List.copyOf(lines));
  }

  private static String uncachedCanonical(Address address) {
    return address == null ? null : AddressUtil.canonicalAddress(address);
  }

  private static ClangToken token(String text, int syntaxType, Address min, Address max) {
    return new TestToken(text, syntaxType, min, max);
  }

  private static ClangFuncNameToken callToken(
      String text, Address calleeEntry, Address min, Address max) {
    ClangStatement statement = new ClangStatement(null);
    PcodeOp callOp =
        new PcodeOp(min, 0, PcodeOp.CALL, new Varnode[] {new Varnode(calleeEntry, 8)});
    return new ClangFuncNameToken(statement, null) {
      @Override
      public String getText() {
        return text;
      }

      @Override
      public int getSyntaxType() {
        return ClangToken.FUNCTION_COLOR;
      }

      @Override
      public PcodeOp getPcodeOp() {
        return callOp;
      }

      @Override
      public Address getMinAddress() {
        return min;
      }

      @Override
      public Address getMaxAddress() {
        return max;
      }
    };
  }

  static DecompileResults resultsWith(
      Function function, ClangTokenGroup markup, DecompiledFunction decompiledFunction) {
    return new DecompileResults(function, null, null, null, null, null, null) {
      @Override
      public ClangTokenGroup getCCodeMarkup() {
        return markup;
      }

      @Override
      public DecompiledFunction getDecompiledFunction() {
        return decompiledFunction;
      }
    };
  }

  static Function stubFunction() {
    Address entry = FunctionCommentsTest.address("ram", "00101000");
    CodeUnit unit = (CodeUnit) Proxy.newProxyInstance(
        CodeUnit.class.getClassLoader(),
        new Class<?>[] {CodeUnit.class},
        (proxy, method, args) -> switch (method.getName()) {
          case "getMinAddress" -> entry;
          default -> throw new AssertionError(method.getName());
        });
    Listing listing = (Listing) Proxy.newProxyInstance(
        Listing.class.getClassLoader(),
        new Class<?>[] {Listing.class},
        (proxy, method, args) -> switch (method.getName()) {
          case "getCodeUnitContaining" -> unit;
          default -> throw new AssertionError(method.getName());
        });
    Program program = (Program) Proxy.newProxyInstance(
        Program.class.getClassLoader(),
        new Class<?>[] {Program.class},
        (proxy, method, args) -> switch (method.getName()) {
          case "getListing" -> listing;
          default -> throw new AssertionError(method.getName());
        });
    return (Function) Proxy.newProxyInstance(
        Function.class.getClassLoader(),
        new Class<?>[] {Function.class},
        (proxy, method, args) -> switch (method.getName()) {
          case "getProgram" -> program;
          case "getEntryPoint" -> entry;
          case "getName" -> "parse";
          default -> throw new AssertionError(method.getName());
        });
  }

  private static class TestToken extends ClangToken {
    private final String tokenText;
    private final int tokenSyntaxType;
    private final Address minAddress;
    private final Address maxAddress;

    TestToken(String tokenText, int tokenSyntaxType, Address minAddress, Address maxAddress) {
      super(null, tokenText, tokenSyntaxType);
      this.tokenText = tokenText;
      this.tokenSyntaxType = tokenSyntaxType;
      this.minAddress = minAddress;
      this.maxAddress = maxAddress;
    }

    @Override
    public String getText() {
      return tokenText;
    }

    @Override
    public int getSyntaxType() {
      return tokenSyntaxType;
    }

    @Override
    public Address getMinAddress() {
      return minAddress;
    }

    @Override
    public Address getMaxAddress() {
      return maxAddress;
    }
  }

  private static Address countedAddress(long offset, Map<Long, AtomicInteger> canonicalCounts) {
    AtomicInteger spaceNameCalls =
        canonicalCounts.computeIfAbsent(offset, ignored -> new AtomicInteger());
    AddressSpace space =
        proxy(
            AddressSpace.class,
            (self, method, args) ->
                switch (method.getName()) {
                  case "getName" -> {
                    spaceNameCalls.incrementAndGet();
                    yield "ram";
                  }
                  case "getSpaceID" -> 1;
                  default -> throw new AssertionError("AddressSpace." + method.getName());
                });
    String hex = String.format("%08x", offset);
    return (Address)
        Proxy.newProxyInstance(
            Address.class.getClassLoader(),
            new Class<?>[] {Address.class},
            (self, method, args) ->
                switch (method.getName()) {
                  case "getAddressSpace" -> space;
                  case "getOffset" -> offset;
                  case "toString" -> hex;
                  case "hashCode" -> Long.hashCode(offset);
                  case "equals" ->
                      args[0] instanceof Address other && other.getOffset() == offset;
                  default -> throw new AssertionError("Address." + method.getName());
                });
  }

  private static CodeUnit codeUnit(Address minAddress) {
    return proxy(
        CodeUnit.class,
        (self, method, args) -> {
          if (method.getName().equals("getMinAddress")) return minAddress;
          throw new AssertionError("CodeUnit." + method.getName());
        });
  }

  private static Listing countedListing(
      Map<Address, CodeUnit> units, Map<Address, AtomicInteger> queryCounts) {
    return proxy(
        Listing.class,
        (self, method, args) -> {
          if (method.getName().equals("getCodeUnitContaining")) {
            Address address = (Address) args[0];
            queryCounts.computeIfAbsent(address, ignored -> new AtomicInteger()).incrementAndGet();
            return units.get(address);
          }
          throw new AssertionError("Listing." + method.getName());
        });
  }

  private static FunctionManager functionManager(Map<Address, Function> functionsByAddress) {
    return proxy(
        FunctionManager.class,
        (self, method, args) -> {
          if (method.getName().equals("getReferencedFunction")) {
            return functionsByAddress.get((Address) args[0]);
          }
          throw new AssertionError("FunctionManager." + method.getName());
        });
  }

  private static Program program(
      Listing listing, FunctionManager functionManager, AtomicInteger getListingCalls) {
    return proxy(
        Program.class,
        (self, method, args) ->
            switch (method.getName()) {
              case "getListing" -> {
                getListingCalls.incrementAndGet();
                yield listing;
              }
              case "getFunctionManager" -> functionManager;
              default -> throw new AssertionError("Program." + method.getName());
            });
  }

  private static Function ownerFunction(
      Program program,
      Address entryPoint,
      AtomicInteger getProgramCalls,
      AtomicInteger getEntryPointCalls) {
    return proxy(
        Function.class,
        (self, method, args) ->
            switch (method.getName()) {
              case "getProgram" -> {
                getProgramCalls.incrementAndGet();
                yield program;
              }
              case "getEntryPoint" -> {
                getEntryPointCalls.incrementAndGet();
                yield entryPoint;
              }
              default -> throw new AssertionError("Function." + method.getName());
            });
  }

  private static Function calleeFunction(Symbol symbol, AtomicInteger getSymbolCalls) {
    return proxy(
        Function.class,
        (self, method, args) -> {
          if (method.getName().equals("getSymbol")) {
            getSymbolCalls.incrementAndGet();
            return symbol;
          }
          throw new AssertionError("Function." + method.getName());
        });
  }

  private static Symbol symbol(
      long id, String name, Address address, String namespaceName, boolean primary) {
    Namespace namespace =
        namespaceName == null
            ? null
            : proxy(
                Namespace.class,
                (self, method, args) -> {
                  if (method.getName().equals("getName")) return namespaceName;
                  throw new AssertionError("Namespace." + method.getName());
                });
    return proxy(
        Symbol.class,
        (self, method, args) ->
            switch (method.getName()) {
              case "getID" -> id;
              case "getName" -> name;
              case "getAddress" -> address;
              case "getParentNamespace" -> namespace;
              case "getSymbolType" -> SymbolType.FUNCTION;
              case "getSource" -> SourceType.USER_DEFINED;
              case "isPrimary" -> primary;
              case "getProgram" -> null;
              default -> throw new AssertionError("Symbol." + method.getName());
            });
  }

  @SuppressWarnings("unchecked")
  private static <T> T proxy(Class<T> type, java.lang.reflect.InvocationHandler handler) {
    return (T)
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (self, method, args) -> {
              if (method.getDeclaringClass() == Object.class) {
                return switch (method.getName()) {
                  case "equals" -> self == args[0];
                  case "hashCode" -> System.identityHashCode(self);
                  case "toString" -> type.getSimpleName() + "@" + System.identityHashCode(self);
                  default -> throw new AssertionError(method.getName());
                };
              }
              return handler.invoke(self, method, args);
            });
  }
}
