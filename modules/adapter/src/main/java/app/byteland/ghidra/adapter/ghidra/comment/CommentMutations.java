package app.byteland.ghidra.adapter.ghidra.comment;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import ghidra.app.util.viewer.field.CommentUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Listing;
import java.util.Objects;

final class CommentMutations {
  private final GhidraSession context;

  CommentMutations(GhidraSession context) {
    this.context = context;
  }

  void setComment(String addressRaw, String type, String text) {
    applyCommentChange(addressRaw, type, text);
  }

  void deleteComment(String addressRaw, String type) {
    applyCommentChange(addressRaw, type, null);
  }

  private void applyCommentChange(String addressRaw, String type, String text) {
    Address address = parseAddress(addressRaw);
    applyAtExactAddress(address, type, text);
  }

  private Address parseAddress(String rawAddress) {
    return context.parseAddress(rawAddress);
  }

  private void applyAtExactAddress(Address address, String type, String text) {
    CommentType commentType = CommentTypes.toGhidraType(type);
    String sanitized = text == null ? null : CommentUtils.sanitize(text);
    Listing listing = context.currentProgram().getListing();
    listing.setComment(address, commentType, sanitized);
    String actual = listing.getComment(commentType, address);
    if (!Objects.equals(sanitized, actual)) {
      throw new IllegalStateException("comment readback did not match the requested value");
    }
  }
}
