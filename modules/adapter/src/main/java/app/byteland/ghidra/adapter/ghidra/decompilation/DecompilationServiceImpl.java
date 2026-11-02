package app.byteland.ghidra.adapter.ghidra.decompilation;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.decompilation.DecompilationResource;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.WeakHashMap;

public final class DecompilationServiceImpl implements DecompilationService {
  private final GhidraSession context;
  private final LeasePool<DecompInterface> decompilerPool;
  private final Map<DecompInterface, Boolean> commentModes =
      Collections.synchronizedMap(new WeakHashMap<>());

  public DecompilationServiceImpl(GhidraSession context) {
    this.context = Objects.requireNonNull(context, "context");
    this.decompilerPool = DecompilerPoolFactory.create(context.currentProgram());
  }

  @Override
  public DecompilationResource decompileFunction(
      String rawAddress, DecompilationResource.Format format, Integer timeoutMs,
      boolean includeComments) {
    int timeout = timeoutMs == null ? DEFAULT_TIMEOUT_MS : timeoutMs;
    if (timeout < MIN_TIMEOUT_MS || timeout > MAX_TIMEOUT_MS) {
      throw new IllegalArgumentException(
          "timeoutMs must be in " + MIN_TIMEOUT_MS + ".." + MAX_TIMEOUT_MS);
    }
    Function function = context.script().getFunctionAt(context.parseAddress(rawAddress));
    if (function == null) {
      throw new NoSuchElementException("function not found");
    }
    return decompile(function, timeout, format, includeComments);
  }

  @Override
  public void close() {
    if (decompilerPool != null) {
      decompilerPool.close();
    }
  }

  private DecompilationResource decompile(
      Function function, int timeoutMs, DecompilationResource.Format format,
      boolean includeComments) {
    try (LeasePool.Lease<DecompInterface> lease = decompilerPool.acquire()) {
      long startedAt = System.nanoTime();
      int timeoutSeconds = GhidraTimeout.secondsForMilliseconds(timeoutMs);
      DecompInterface decompiler = lease.value();
      applyCommentMode(decompiler, includeComments);
      // The native process keeps program data. Clear it to show the current names and comments.
      decompiler.flushCache();
      DecompileResults results = decompiler.decompileFunction(function, timeoutSeconds, null);
      boolean completed = results.decompileCompleted();
      List<String> warnings = new ArrayList<>();
      if (!completed && results.getErrorMessage() != null && !results.getErrorMessage().isBlank()) {
        warnings.add(results.getErrorMessage());
      }
      DecompilationResource.Format effectiveFormat =
          format == null ? DecompilationResource.Format.TEXT : format;
      ClangTokenGroup markup = results.getCCodeMarkup();
      String code =
          effectiveFormat == DecompilationResource.Format.TEXT ? renderCode(results) : null;
      List<DecompilationResource.Token> tokens =
          effectiveFormat == DecompilationResource.Format.TOKENS ? renderTokens(markup) : null;
      List<DecompilationResource.Line> lines = null;
      if (effectiveFormat == DecompilationResource.Format.DOCUMENT) {
        GuiDocument document = GuiDocument.render(function, markup);
        code = document.code();
        lines = document.lines();
      }
      FunctionComments comments = includeComments
          ? FunctionComments.read(function, startedAt, timeoutMs, warnings) : null;
      return new DecompilationResource(
          AddressUtil.canonicalAddress(function.getEntryPoint()),
          function.getName(), effectiveFormat, completed,
          (System.nanoTime() - startedAt) / 1_000_000L,
          code, tokens, lines,
          comments == null ? null : comments.items(),
          comments == null ? null : comments.complete(), warnings);
    }
  }

  private String renderCode(DecompileResults results) {
    if (results.getDecompiledFunction() == null || results.getDecompiledFunction().getC() == null) {
      return "";
    }
    return DecompilationFormatter.formatCCode(results.getDecompiledFunction().getC());
  }

  private List<DecompilationResource.Token> renderTokens(ClangTokenGroup markup) {
    if (markup == null) return List.of();
    List<DecompilationResource.Token> tokens = new ArrayList<>();
    java.util.Iterator<ClangToken> iterator = markup.tokenIterator(true);
    while (iterator.hasNext()) {
      ClangToken token = iterator.next();
      tokens.add(
          new DecompilationResource.Token(
              tokenKind(token),
              token.getText() == null ? "" : token.getText(),
              token.getMinAddress() == null
                  ? null
                  : AddressUtil.canonicalAddress(token.getMinAddress())));
    }
    return List.copyOf(tokens);
  }

  /** Sends display options only when the comment mode of the pooled decompiler changes. */
  private void applyCommentMode(DecompInterface decompiler, boolean includeComments) {
    if (Boolean.valueOf(includeComments).equals(commentModes.get(decompiler))) return;
    commentModes.remove(decompiler);
    if (!decompiler.setOptions(DecompilerPoolFactory.options(includeComments))) {
      throw new IllegalStateException("unable to set decompiler display options");
    }
    commentModes.put(decompiler, includeComments);
  }

  static DecompilationResource.Token.Kind tokenKind(ClangToken token) {
    return switch (token.getSyntaxType()) {
      case ClangToken.KEYWORD_COLOR -> DecompilationResource.Token.Kind.KEYWORD;
      case ClangToken.COMMENT_COLOR -> DecompilationResource.Token.Kind.COMMENT;
      case ClangToken.TYPE_COLOR -> DecompilationResource.Token.Kind.TYPE;
      case ClangToken.FUNCTION_COLOR -> DecompilationResource.Token.Kind.FUNCTION;
      case ClangToken.VARIABLE_COLOR -> DecompilationResource.Token.Kind.VARIABLE;
      case ClangToken.CONST_COLOR -> DecompilationResource.Token.Kind.CONSTANT;
      case ClangToken.PARAMETER_COLOR -> DecompilationResource.Token.Kind.PARAMETER;
      case ClangToken.GLOBAL_COLOR -> DecompilationResource.Token.Kind.GLOBAL;
      case ClangToken.ERROR_COLOR -> DecompilationResource.Token.Kind.ERROR;
      case ClangToken.SPECIAL_COLOR -> DecompilationResource.Token.Kind.SPECIAL;
      default -> DecompilationResource.Token.Kind.DEFAULT;
    };
  }
}
