package app.byteland.ghidra.service.listing;

import app.byteland.ghidra.service.ScanProgress;
import app.byteland.ghidra.service.comment.CommentResource;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.reference.ReferenceResource;
import app.byteland.ghidra.service.symbol.SymbolResource;
import java.util.List;
import java.util.Objects;

/**
 * Holds code units and overlay resources for one address window.
 */
public record ListingWindowResource(
    List<CodeUnitResource> items,
    List<DataUnitResource> dataUnits,
    List<SymbolResource> symbols,
    List<FunctionResource> functions,
    List<CommentResource> comments,
    List<ReferenceResource> incomingReferences,
    List<ReferenceResource> outgoingReferences,
    String nextCursor,
    ScanProgress scan) {
  public static final int MAX_DATA_UNITS = 400;
  public static final int MAX_SYMBOLS = 500;
  public static final int MAX_FUNCTIONS = 200;
  public static final int MAX_COMMENTS = 500;
  public static final int MAX_XREF_ADDRESSES = 64;
  public static final int MAX_INCOMING_REFERENCES_PER_ADDRESS = 25;
  public static final int MAX_OUTGOING_REFERENCES_PER_ADDRESS = 10;
  public static final int MAX_INCOMING_REFERENCES =
      MAX_XREF_ADDRESSES * MAX_INCOMING_REFERENCES_PER_ADDRESS;
  public static final int MAX_OUTGOING_REFERENCES =
      MAX_XREF_ADDRESSES * MAX_OUTGOING_REFERENCES_PER_ADDRESS;

  public ListingWindowResource {
    items = List.copyOf(Objects.requireNonNull(items, "items"));
    dataUnits = List.copyOf(Objects.requireNonNull(dataUnits, "dataUnits"));
    symbols = List.copyOf(Objects.requireNonNull(symbols, "symbols"));
    functions = List.copyOf(Objects.requireNonNull(functions, "functions"));
    comments = List.copyOf(Objects.requireNonNull(comments, "comments"));
    incomingReferences =
        List.copyOf(Objects.requireNonNull(incomingReferences, "incomingReferences"));
    outgoingReferences =
        List.copyOf(Objects.requireNonNull(outgoingReferences, "outgoingReferences"));
    Objects.requireNonNull(scan, "scan");
  }
}
