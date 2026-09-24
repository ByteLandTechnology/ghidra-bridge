package app.byteland.ghidra.adapter.ghidra.comment;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.service.comment.CommentResource;
import ghidra.program.model.address.Address;
import java.util.Locale;

final class CommentDescriptions {
  private CommentDescriptions() {}

  static CommentResource comment(Address address, String type, String text) {
    return new CommentResource(
        AddressUtil.canonicalAddress(address),
        CommentResource.Type.valueOf(type.toUpperCase(Locale.ROOT)),
        text);
  }
}
