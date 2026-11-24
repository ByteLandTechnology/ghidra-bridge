package app.byteland.ghidra.adapter.ghidra.decompilation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.app.decompiler.ClangBreak;
import ghidra.app.decompiler.ClangSyntaxToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.PrettyPrinter;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import java.lang.reflect.Proxy;
import java.util.List;
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
}
