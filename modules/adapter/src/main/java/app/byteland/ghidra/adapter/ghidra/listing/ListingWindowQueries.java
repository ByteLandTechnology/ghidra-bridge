package app.byteland.ghidra.adapter.ghidra.listing;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.comment.CommentServiceImpl;
import app.byteland.ghidra.adapter.ghidra.function.FunctionServiceImpl;
import app.byteland.ghidra.adapter.ghidra.reference.ReferenceServiceImpl;
import app.byteland.ghidra.adapter.ghidra.symbol.SymbolServiceImpl;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.ScanProgress;
import app.byteland.ghidra.service.comment.CommentResource;
import app.byteland.ghidra.service.comment.CommentService.CommentQuery;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.FunctionService.FunctionQuery;
import app.byteland.ghidra.service.listing.CodeUnitResource;
import app.byteland.ghidra.service.listing.DataUnitResource;
import app.byteland.ghidra.service.listing.ListingWindowResource;
import app.byteland.ghidra.service.reference.ReferenceResource;
import app.byteland.ghidra.service.symbol.SymbolResource;
import app.byteland.ghidra.service.symbol.SymbolService.SymbolQuery;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

final class ListingWindowQueries {
  private static final long NANOS_PER_MILLISECOND = 1_000_000L;

  private static final Comparator<CodeUnitResource> CODE_UNIT_ORDER =
      Comparator.comparing(CodeUnitResource::address);
  private static final Comparator<DataUnitResource> DATA_UNIT_ORDER =
      Comparator.comparing(DataUnitResource::address);
  private static final Comparator<SymbolResource> SYMBOL_ORDER =
      Comparator.comparing(SymbolResource::address).thenComparing(SymbolResource::id);
  private static final Comparator<FunctionResource> FUNCTION_ORDER =
      Comparator.comparing(FunctionResource::entry);
  private static final Comparator<CommentResource> COMMENT_ORDER =
      Comparator.comparing(CommentResource::address)
          .thenComparing(comment -> comment.type().name().toLowerCase(Locale.ROOT));
  private static final Comparator<ReferenceResource> REFERENCE_ORDER =
      Comparator.comparing(ReferenceResource::from)
          .thenComparing(ReferenceResource::to)
          .thenComparing(ReferenceResource::type)
          .thenComparingInt(ReferenceResource::operandIndex);

  private final GhidraSession context;
  private final ListingCodeUnitQueries codeUnitQueries;
  private final ListingDataQueries dataQueries;
  private final SymbolServiceImpl symbolService;
  private final FunctionServiceImpl functionService;
  private final CommentServiceImpl commentService;
  private final ReferenceServiceImpl referenceService;

  ListingWindowQueries(
      GhidraSession context,
      ListingCodeUnitQueries codeUnitQueries,
      ListingDataQueries dataQueries) {
    this.context = context;
    this.codeUnitQueries = codeUnitQueries;
    this.dataQueries = dataQueries;
    this.symbolService = new SymbolServiceImpl(context);
    this.functionService = new FunctionServiceImpl(context);
    this.commentService = new CommentServiceImpl(context);
    this.referenceService = new ReferenceServiceImpl(context);
  }

  ListingWindowResource getListingWindow(
      AddressScanOptions options, int limit, String kind, String cursor) {
    long startedNanos = System.nanoTime();
    long timeoutNanos = Math.max(1L, options.timeoutMs()) * NANOS_PER_MILLISECOND;

    Page<CodeUnitResource> codeUnitPage =
        codeUnitQueries.listCodeUnits(options, limit, kind, "forward", cursor);
    List<CodeUnitResource> units = new ArrayList<>(codeUnitPage.items());
    units.sort(CODE_UNIT_ORDER);
    ScanProgress baseScan = codeUnitPage.scanProgress();
    if (units.isEmpty()) {
      return new ListingWindowResource(
          List.of(),
          List.of(),
          List.of(),
          List.of(),
          List.of(),
          List.of(),
          List.of(),
          codeUnitPage.nextCursor(),
          withElapsed(baseScan, startedNanos, false));
    }

    String firstAddress = units.getFirst().address();
    String lastAddress = windowEndAddress(units.getLast());
    boolean timedOut = baseScan.stopReason() == ScanProgress.StopReason.TIMEOUT;

    List<DataUnitResource> dataUnits = new ArrayList<>();
    List<SymbolResource> symbols = new ArrayList<>();
    List<FunctionResource> functions = new ArrayList<>();
    List<CommentResource> comments = new ArrayList<>();
    List<ReferenceResource> incomingReferences = new ArrayList<>();
    List<ReferenceResource> outgoingReferences = new ArrayList<>();

    if (!timedOut && !deadlineReached(startedNanos, timeoutNanos)) {
      Page<DataUnitResource> dataPage =
          dataQueries.listDataUnits(
              windowScan(firstAddress, lastAddress, startedNanos, timeoutNanos),
              ListingWindowResource.MAX_DATA_UNITS,
              "forward",
              null);
      dataUnits.addAll(dataPage.items());
      dataUnits.sort(DATA_UNIT_ORDER);
      timedOut = dataPage.scanProgress().stopReason() == ScanProgress.StopReason.TIMEOUT;
    } else {
      timedOut = true;
    }

    if (!timedOut && !deadlineReached(startedNanos, timeoutNanos)) {
      Page<SymbolResource> symbolPage =
          symbolService.listSymbols(
              new SymbolQuery(
                  windowScan(firstAddress, lastAddress, startedNanos, timeoutNanos),
                  null,
                  null,
                  null,
                  null,
                  null,
                  false,
                  ListingWindowResource.MAX_SYMBOLS,
                  null));
      symbols.addAll(symbolPage.items());
      symbols.sort(SYMBOL_ORDER);
      timedOut = symbolPage.scanProgress().stopReason() == ScanProgress.StopReason.TIMEOUT;
    } else {
      timedOut = true;
    }

    if (!timedOut && !deadlineReached(startedNanos, timeoutNanos)) {
      Page<FunctionResource> functionPage =
          functionService.listFunctions(
              new FunctionQuery(
                  windowScan(firstAddress, lastAddress, startedNanos, timeoutNanos),
                  ListingWindowResource.MAX_FUNCTIONS,
                  null,
                  null,
                  null,
                  null,
                  null,
                  null,
                  Set.of("parameters", "locals")));
      functions.addAll(functionPage.items());
      functions.sort(FUNCTION_ORDER);
      timedOut = functionPage.scanProgress().stopReason() == ScanProgress.StopReason.TIMEOUT;
    } else {
      timedOut = true;
    }

    if (!timedOut && !deadlineReached(startedNanos, timeoutNanos)) {
      Page<CommentResource> commentPage =
          commentService.listComments(
              new CommentQuery(
                  windowScan(firstAddress, lastAddress, startedNanos, timeoutNanos),
                  null,
                  null,
                  ListingWindowResource.MAX_COMMENTS,
                  null));
      comments.addAll(commentPage.items());
      comments.sort(COMMENT_ORDER);
      timedOut = commentPage.scanProgress().stopReason() == ScanProgress.StopReason.TIMEOUT;
    } else {
      timedOut = true;
    }

    if (!timedOut) {
      timedOut =
          collectWindowReferences(
              units,
              symbols,
              functions,
              incomingReferences,
              outgoingReferences,
              startedNanos,
              timeoutNanos);
    }

    String nextCursor =
        timedOut && codeUnitPage.nextCursor() == null ? null : codeUnitPage.nextCursor();
    return new ListingWindowResource(
        units,
        dataUnits,
        symbols,
        functions,
        comments,
        incomingReferences,
        outgoingReferences,
        nextCursor,
        withElapsed(baseScan, startedNanos, timedOut));
  }

  private boolean collectWindowReferences(
      List<CodeUnitResource> units,
      List<SymbolResource> symbols,
      List<FunctionResource> functions,
      List<ReferenceResource> incomingReferences,
      List<ReferenceResource> outgoingReferences,
      long startedNanos,
      long timeoutNanos) {
    Set<String> targetSet = new HashSet<>();
    for (SymbolResource symbol : symbols) {
      if (symbol.address() != null && !symbol.address().isBlank()) {
        targetSet.add(symbol.address());
      }
    }
    for (FunctionResource function : functions) {
      if (function.entry() != null && !function.entry().isBlank()) {
        targetSet.add(function.entry());
      }
    }

    Set<String> instructionSet = new HashSet<>();
    for (CodeUnitResource unit : units) {
      if (unit.kind() == CodeUnitResource.Kind.INSTRUCTION && unit.address() != null) {
        instructionSet.add(unit.address());
        if (isXrefTargetMnemonic(unit.mnemonic())) {
          targetSet.add(unit.address());
        }
      }
    }

    LinkedHashSet<String> candidateAddresses = new LinkedHashSet<>();
    for (FunctionResource function : functions) {
      addCandidateAddress(candidateAddresses, function.entry());
    }
    for (SymbolResource symbol : symbols) {
      addCandidateAddress(candidateAddresses, symbol.address());
    }
    for (CodeUnitResource unit : units) {
      if (unit.kind() == CodeUnitResource.Kind.INSTRUCTION
          && isXrefSourceMnemonic(unit.mnemonic())) {
        addCandidateAddress(candidateAddresses, unit.address());
      }
    }

    for (String address : candidateAddresses) {
      if (deadlineReached(startedNanos, timeoutNanos)) {
        return true;
      }
      if (targetSet.contains(address)) {
        List<ReferenceResource> incoming =
            new ArrayList<>(
                referenceService
                    .listReferences(
                        null,
                        address,
                        null,
                        "to",
                        ListingWindowResource.MAX_INCOMING_REFERENCES_PER_ADDRESS,
                        null)
                    .items());
        incoming.sort(REFERENCE_ORDER);
        incomingReferences.addAll(incoming);
      }
      if (deadlineReached(startedNanos, timeoutNanos)) {
        return true;
      }
      if (instructionSet.contains(address)) {
        List<ReferenceResource> outgoing =
            new ArrayList<>(
                referenceService
                    .listReferences(
                        address,
                        null,
                        null,
                        "from",
                        ListingWindowResource.MAX_OUTGOING_REFERENCES_PER_ADDRESS,
                        null)
                    .items());
        outgoing.sort(REFERENCE_ORDER);
        outgoingReferences.addAll(outgoing);
      }
    }
    return false;
  }

  private static void addCandidateAddress(Set<String> candidates, String address) {
    if (address == null || address.isBlank()) return;
    if (candidates.size() >= ListingWindowResource.MAX_XREF_ADDRESSES) return;
    candidates.add(address);
  }

  private String windowEndAddress(CodeUnitResource lastUnit) {
    Address parsed = context.parseAddress(lastUnit.address());
    CodeUnit codeUnit = context.currentProgram().getListing().getCodeUnitAt(parsed);
    if (codeUnit != null && codeUnit.getMaxAddress() != null) {
      return AddressUtil.canonicalAddress(codeUnit.getMaxAddress());
    }
    int offset = Math.max(0, lastUnit.length() - 1);
    if (offset == 0) {
      return lastUnit.address();
    }
    try {
      return AddressUtil.canonicalAddress(parsed.addNoWrap(offset));
    } catch (ghidra.program.model.address.AddressOverflowException ignored) {
      return lastUnit.address();
    }
  }

  private static AddressScanOptions windowScan(
      String startAddress, String endAddress, long startedNanos, long timeoutNanos) {
    long elapsed = Math.max(0L, System.nanoTime() - startedNanos);
    long leftMillis = Math.max(1L, (timeoutNanos - elapsed) / NANOS_PER_MILLISECOND);
    int clampedMillis =
        (int) Math.min(AddressScanOptions.MAX_TIMEOUT_MS, Math.max(1L, leftMillis));
    return new AddressScanOptions(startAddress, endAddress, clampedMillis);
  }

  private static boolean deadlineReached(long startedNanos, long timeoutNanos) {
    return Math.max(0L, System.nanoTime() - startedNanos) >= timeoutNanos;
  }

  private static ScanProgress withElapsed(
      ScanProgress base, long startedNanos, boolean timedOut) {
    long elapsedMillis = Math.max(0L, (System.nanoTime() - startedNanos) / NANOS_PER_MILLISECOND);
    ScanProgress.StopReason reason =
        timedOut ? ScanProgress.StopReason.TIMEOUT : base.stopReason();
    boolean complete = reason == ScanProgress.StopReason.COMPLETED;
    return new ScanProgress(
        base.kind(),
        base.requestedStart(),
        base.requestedEnd(),
        base.scannedStart(),
        base.scannedEnd(),
        complete,
        reason,
        elapsedMillis);
  }

  private static boolean isXrefTargetMnemonic(String mnemonic) {
    if (mnemonic == null || mnemonic.isEmpty()) return false;
    String upper = mnemonic.toUpperCase(Locale.ROOT);
    return upper.startsWith("CALL")
        || upper.startsWith("J")
        || upper.startsWith("B")
        || upper.startsWith("RET")
        || upper.startsWith("ADR")
        || upper.startsWith("LEA");
  }

  private static boolean isXrefSourceMnemonic(String mnemonic) {
    if (mnemonic == null || mnemonic.isEmpty()) return false;
    String upper = mnemonic.toUpperCase(Locale.ROOT);
    return upper.startsWith("CALL")
        || upper.startsWith("J")
        || upper.startsWith("B")
        || upper.startsWith("MOV")
        || upper.startsWith("LEA");
  }
}
