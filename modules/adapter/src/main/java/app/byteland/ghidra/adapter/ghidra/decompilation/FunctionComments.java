package app.byteland.ghidra.adapter.ghidra.decompilation;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.service.comment.CommentResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import java.util.ArrayList;
import java.util.List;

record FunctionComments(List<CommentResource> items, boolean complete) {
  static FunctionComments read(
      Function function, long startedAt, int timeoutMs, List<String> warnings) {
    List<CommentResource> comments = new ArrayList<>();
    try {
      Listing listing = function.getProgram().getListing();
      AddressIterator addresses =
          listing.getCommentAddressIterator(CommentType.REPEATABLE, function.getBody(), true);
      for (Address address : addresses) {
        if ((System.nanoTime() - startedAt) / 1_000_000L >= timeoutMs) {
          warnings.add("Repeatable comments are incomplete: the request time limit was reached.");
          return new FunctionComments(List.copyOf(comments), false);
        }
        String text = listing.getComment(CommentType.REPEATABLE, address);
        if (text != null) {
          comments.add(new CommentResource(
              AddressUtil.canonicalAddress(address), CommentResource.Type.REPEATABLE, text));
        }
      }
      return new FunctionComments(List.copyOf(comments), true);
    } catch (RuntimeException failure) {
      warnings.add("Repeatable comments are incomplete: " + failure.getMessage());
      return new FunctionComments(List.copyOf(comments), false);
    }
  }
}
