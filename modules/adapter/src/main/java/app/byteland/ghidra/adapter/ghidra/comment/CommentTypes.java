package app.byteland.ghidra.adapter.ghidra.comment;

import ghidra.program.model.listing.CommentType;
import java.util.List;

final class CommentTypes {
  private static final List<String> SUPPORTED_TYPES =
      List.of("plate", "pre", "eol", "repeatable", "post");

  private CommentTypes() {}

  static List<String> supportedTypes() {
    return SUPPORTED_TYPES;
  }

  static CommentType toGhidraType(String type) {
    return switch (type) {
      case "plate" -> CommentType.PLATE;
      case "pre" -> CommentType.PRE;
      case "eol" -> CommentType.EOL;
      case "repeatable" -> CommentType.REPEATABLE;
      case "post" -> CommentType.POST;
      default -> throw new IllegalArgumentException("unsupported comment type: " + type);
    };
  }
}
