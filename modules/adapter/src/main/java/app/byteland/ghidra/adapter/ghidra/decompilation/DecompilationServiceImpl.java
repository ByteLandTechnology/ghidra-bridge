package app.byteland.ghidra.adapter.ghidra.decompilation;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.FieldProjections;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.decompilation.DecompilationResource;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Set;
import java.util.WeakHashMap;

public final class DecompilationServiceImpl implements DecompilationService {
  private final GhidraSession context;
  private final LeasePool<DecompInterface> decompilerPool;
  private final Map<DecompInterface, Boolean> commentModes =
      Collections.synchronizedMap(new WeakHashMap<>());
  private final Map<DecompInterface, CacheState> cacheStates =
      Collections.synchronizedMap(new WeakHashMap<>());

  public DecompilationServiceImpl(GhidraSession context) {
    this(
        Objects.requireNonNull(context, "context"),
        DecompilerPoolFactory.create(context.currentProgram()));
  }

  DecompilationServiceImpl(GhidraSession context, LeasePool<DecompInterface> decompilerPool) {
    this.context = Objects.requireNonNull(context, "context");
    this.decompilerPool = Objects.requireNonNull(decompilerPool, "decompilerPool");
  }

  @Override
  public DecompilationResource decompileFunction(
      String rawAddress, DecompilationResource.Format format, Integer timeoutMs,
      boolean includeComments) {
    return decompileFunction(rawAddress, format, timeoutMs, includeComments, null);
  }

  @Override
  public DecompilationResource decompileFunction(
      String rawAddress,
      DecompilationResource.Format format,
      Integer timeoutMs,
      boolean includeComments,
      Set<String> fields) {
    int timeout = timeoutMs == null ? DEFAULT_TIMEOUT_MS : timeoutMs;
    if (timeout < MIN_TIMEOUT_MS || timeout > MAX_TIMEOUT_MS) {
      throw new IllegalArgumentException(
          "timeoutMs must be in " + MIN_TIMEOUT_MS + ".." + MAX_TIMEOUT_MS);
    }
    var entry = context.parseAddress(rawAddress);
    Program program = context.currentProgramOrNull();
    Function function =
        program != null
            ? program.getListing().getFunctionAt(entry)
            : context.script().getFunctionAt(entry);
    if (function == null) {
      throw new NoSuchElementException("function not found");
    }
    return decompile(function, timeout, format, includeComments, fields);
  }

  @Override
  public void close() {
    if (decompilerPool != null) {
      decompilerPool.close();
    }
  }

  private DecompilationResource decompile(
      Function function,
      int timeoutMs,
      DecompilationResource.Format format,
      boolean includeComments,
      Set<String> fields) {
    try (LeasePool.Lease<DecompInterface> lease = decompilerPool.acquire()) {
      long startedAt = System.nanoTime();
      int timeoutSeconds = GhidraTimeout.secondsForMilliseconds(timeoutMs);
      DecompInterface decompiler = lease.value();
      applyCommentMode(decompiler, includeComments);
      // The native process keeps program data. Clear it when program modifications occur.
      flushCacheIfNeeded(decompiler, function.getProgram());
      DecompileResults results = decompiler.decompileFunction(function, timeoutSeconds, null);
      boolean completed = results.decompileCompleted();
      boolean needName = FieldProjections.allows(fields, "name");
      boolean needC = FieldProjections.allows(fields, "c");
      boolean needTokens = FieldProjections.allows(fields, "tokens");
      boolean needLines = FieldProjections.allows(fields, "lines");
      boolean needComments = FieldProjections.allows(fields, "comments");
      boolean needCommentsComplete = FieldProjections.allows(fields, "comments_complete");
      boolean needWarnings = FieldProjections.allows(fields, "warnings");
      List<String> warnings = new ArrayList<>();
      if (needWarnings
          && !completed
          && results.getErrorMessage() != null
          && !results.getErrorMessage().isBlank()) {
        warnings.add(results.getErrorMessage());
      }
      DecompilationResource.Format effectiveFormat =
          format == null ? DecompilationResource.Format.TEXT : format;
      String code = null;
      List<DecompilationResource.Token> tokens = null;
      List<DecompilationResource.Line> lines = null;
      if (effectiveFormat == DecompilationResource.Format.TEXT) {
        code = needC ? GuiDocument.renderText(function, results) : "";
      } else if (effectiveFormat == DecompilationResource.Format.TOKENS) {
        tokens = needTokens ? renderTokens(results.getCCodeMarkup()) : List.of();
      } else if (effectiveFormat == DecompilationResource.Format.DOCUMENT) {
        if (needC || needLines) {
          GuiDocument document =
              GuiDocument.render(function, results.getCCodeMarkup(), needC, needLines);
          code = needC ? document.code() : "";
          lines = needLines ? document.lines() : List.of();
        } else {
          code = "";
          lines = List.of();
        }
      }
      FunctionComments comments =
          includeComments && (needComments || needCommentsComplete || needWarnings)
              ? FunctionComments.read(function, startedAt, timeoutMs, completed, warnings)
              : null;
      return new DecompilationResource(
          AddressUtil.canonicalAddress(function.getEntryPoint()),
          needName ? function.getName() : "",
          effectiveFormat,
          completed,
          FieldProjections.allows(fields, "elapsed_ms")
              ? Math.max(0L, (System.nanoTime() - startedAt) / 1_000_000L)
              : 0L,
          code,
          tokens,
          lines,
          comments == null || !needComments ? null : comments.items(),
          comments == null || !needCommentsComplete ? null : comments.complete(),
          needWarnings ? warnings : List.of());
    }
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

  /** Flushes the native cache only when the program or its modification number changes. */
  private void flushCacheIfNeeded(DecompInterface decompiler, Program program) {
    Program target = program != null ? program : context.currentProgramOrNull();
    if (target == null) {
      cacheStates.put(decompiler, CacheState.dirtyWithoutProgram());
      decompiler.flushCache();
      return;
    }
    long modificationNumber = target.getModificationNumber();
    CacheState state = cacheStates.get(decompiler);
    if (state == null) {
      Program openedProgram = decompiler.getProgram();
      if (openedProgram == null || openedProgram == target) {
        cacheStates.put(decompiler, CacheState.clean(target, modificationNumber));
        return;
      }
    } else if (state.isCleanFor(target, modificationNumber)) {
      return;
    }
    cacheStates.put(
        decompiler, state == null ? CacheState.dirtyWithoutProgram() : state.markDirty());
    if (decompiler.flushCache() >= 0) {
      cacheStates.put(decompiler, CacheState.clean(target, modificationNumber));
    }
  }

  private record CacheState(
      WeakReference<Program> program, long modificationNumber, boolean dirty) {
    private static final WeakReference<Program> NO_PROGRAM = new WeakReference<>(null);

    static CacheState clean(Program program, long modificationNumber) {
      return new CacheState(new WeakReference<>(program), modificationNumber, false);
    }

    static CacheState dirtyWithoutProgram() {
      return new CacheState(NO_PROGRAM, 0L, true);
    }

    CacheState markDirty() {
      return dirty ? this : new CacheState(program, modificationNumber, true);
    }

    boolean isCleanFor(Program candidate, long candidateModificationNumber) {
      return !dirty
          && program.refersTo(candidate)
          && modificationNumber == candidateModificationNumber;
    }
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
