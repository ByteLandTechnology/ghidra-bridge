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
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;

record FunctionComments(List<CommentResource> items, boolean complete) {
  static final long POST_DECOMPILE_GRACE_NANOS = TimeUnit.MILLISECONDS.toNanos(250);

  static FunctionComments read(
      Function function,
      long startedAt,
      int timeoutMs,
      boolean decompileCompleted,
      List<String> warnings) {
    return read(function, startedAt, timeoutMs, decompileCompleted, warnings, System::nanoTime);
  }

  static FunctionComments read(
      Function function,
      long startedAt,
      int timeoutMs,
      boolean decompileCompleted,
      List<String> warnings,
      LongSupplier nanoTime) {
    List<CommentResource> comments = new ArrayList<>();
    long deadline = deadlineNanos(startedAt, timeoutMs, decompileCompleted, nanoTime.getAsLong());
    try {
      Listing listing = function.getProgram().getListing();
      AddressIterator addresses =
          listing.getCommentAddressIterator(CommentType.REPEATABLE, function.getBody(), true);
      for (Address address : addresses) {
        if (nanoTime.getAsLong() - deadline >= 0L) {
          warnings.add("Repeatable comments are incomplete: the request time limit was reached.");
          return new FunctionComments(List.copyOf(comments), false);
        }
        String text = listing.getComment(CommentType.REPEATABLE, address);
        if (text != null) {
          comments.add(
              new CommentResource(
                  AddressUtil.canonicalAddress(address), CommentResource.Type.REPEATABLE, text));
        }
      }
      return new FunctionComments(List.copyOf(comments), true);
    } catch (RuntimeException failure) {
      warnings.add("Repeatable comments are incomplete: " + failure.getMessage());
      return new FunctionComments(List.copyOf(comments), false);
    }
  }

  private static long deadlineNanos(
      long startedAt, int timeoutMs, boolean decompileCompleted, long readStartedAt) {
    long budgetDeadline = GhidraTimeout.deadlineNanos(startedAt, timeoutMs);
    if (!decompileCompleted) {
      return budgetDeadline;
    }
    long graceDeadline = readStartedAt + POST_DECOMPILE_GRACE_NANOS;
    return graceDeadline - budgetDeadline > 0L ? graceDeadline : budgetDeadline;
  }
}
