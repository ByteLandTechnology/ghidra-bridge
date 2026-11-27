package app.byteland.ghidra.service.comment;

/**
 * Represents a program comment at a canonical memory address.
 *
 * @param address canonical memory address
 * @param type comment placement category
 * @param text comment body text
 */
public record CommentResource(String address, Type type, String text) {
  /**
   * Ghidra comment placement categories.
   */
  public enum Type {
    /** Banner comment shown above an address block. */
    PLATE,
    /** Comment shown immediately before a code unit. */
    PRE,
    /** End-of-line comment shown beside a code unit. */
    EOL,
    /** Comment repeated at cross-reference sites. */
    REPEATABLE,
    /** Comment shown immediately after a code unit. */
    POST
  }
}
