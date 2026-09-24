package app.byteland.ghidra.adapter.ghidra.comment;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.scan.AddressScanRanges;
import app.byteland.ghidra.adapter.ghidra.scan.BoundedAddressScan;
import app.byteland.ghidra.adapter.ghidra.scan.CompositeCursor;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.comment.CommentResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Listing;
import java.util.List;
import java.util.Locale;

final class CommentQueries {
  private final GhidraSession context;

  CommentQueries(GhidraSession context) {
    this.context = context;
  }

  Page<CommentResource> listComments(
      AddressScanOptions options, String type, String text, int limit, String cursor) {
    int normalizedLimit = Page.clampLimit(limit);
    CursorPosition cursorPosition = parseCursor(cursor);
    AddressScanRanges.Resolved range = AddressScanRanges.resolve(context, options, true);
    Address iterationStart = range.start();
    if (cursorPosition != null && cursorPosition.address().compareTo(iterationStart) > 0) {
      iterationStart = cursorPosition.address();
    }

    BoundedAddressScan<CommentResource> scan =
        BoundedAddressScan.start(
            normalizedLimit, options.timeoutMs(), range.startText(), range.endText());
    String normalizedText = text == null ? null : text.toLowerCase(Locale.ROOT);
    Listing listing = context.currentProgram().getListing();
    AddressSet addressesInRange =
        new AddressSet(context.currentProgram(), iterationStart, range.end());
    AddressIterator addresses =
        type == null
            ? listing.getCommentAddressIterator(addressesInRange, true)
            : listing.getCommentAddressIterator(
                CommentTypes.toGhidraType(type), addressesInRange, true);
    List<String> commentTypes =
        type == null ? CommentTypes.supportedTypes().stream().sorted().toList() : List.of(type);

    for (Address address : addresses) {
      for (String commentType : commentTypes) {
        if (cursorPosition != null && compare(address, commentType, cursorPosition) <= 0) {
          continue;
        }
        String value = listing.getComment(CommentTypes.toGhidraType(commentType), address);
        if (value == null) {
          continue;
        }
        CommentResource match =
            normalizedText == null || value.toLowerCase(Locale.ROOT).contains(normalizedText)
                ? CommentDescriptions.comment(address, commentType, value)
                : null;
        scan.visit(
            AddressUtil.canonicalAddress(address),
            CompositeCursor.key(AddressUtil.canonicalAddress(address), commentType),
            match);
        if (scan.stopped()) break;
      }
      if (scan.stopped()) break;
    }
    return scan.finish();
  }

  private Address parseAddress(String rawAddress) {
    return context.parseAddress(rawAddress);
  }

  private CursorPosition parseCursor(String cursor) {
    CompositeCursor parts = CompositeCursor.parse(cursor, "comments");
    if (parts == null) return null;
    return new CursorPosition(parseAddress(parts.address()), parts.secondary());
  }

  private static int compare(Address address, String type, CursorPosition cursor) {
    int byAddress = address.compareTo(cursor.address());
    return byAddress == 0 ? type.compareTo(cursor.type()) : byAddress;
  }

  private record CursorPosition(Address address, String type) {}
}
