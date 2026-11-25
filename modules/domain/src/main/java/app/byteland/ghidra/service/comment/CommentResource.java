package app.byteland.ghidra.service.comment;

/**
 * Listing comment attached to a program address.
 *
 * @param address canonical comment address
 * @param type Ghidra comment placement type
 * @param text comment body text
 */
public record CommentResource(String address, Type type, String text) {
  /**
   * Placement category of a Ghidra listing comment.
   */
  public enum Type {
    /** Block banner comment displayed above an address. */
    PLATE,
    /** Comment displayed immediately before an instruction or data item. */
    PRE,
    /** End-of-line comment displayed beside an instruction or data item. */
    EOL,
    /** Comment echoed at cross-reference sites targeting this address. */
    REPEATABLE,
    /** Comment displayed immediately after an instruction or data item. */
    POST
  }
}
