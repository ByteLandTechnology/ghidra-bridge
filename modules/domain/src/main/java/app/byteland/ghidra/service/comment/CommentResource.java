package app.byteland.ghidra.service.comment;

/**
 * Represents a listing comment at a program address.
 *
 * @param address canonical memory address
 * @param type comment placement type
 * @param text comment body text
 */
public record CommentResource(String address, Type type, String text) {
  /** Listing comment placement categories. */
  public enum Type {
    /** Block header plate comment. */
    PLATE,
    /** Pre-instruction comment. */
    PRE,
    /** End-of-line comment. */
    EOL,
    /** Repeatable cross-reference comment. */
    REPEATABLE,
    /** Post-instruction comment. */
    POST
  }
}
