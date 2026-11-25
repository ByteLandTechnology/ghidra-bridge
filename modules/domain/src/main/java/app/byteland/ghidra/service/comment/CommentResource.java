package app.byteland.ghidra.service.comment;

/**
 * Program comment attached to a memory address.
 *
 * @param address canonical comment address
 * @param type comment placement category
 * @param text comment text content
 */
public record CommentResource(String address, Type type, String text) {
  /** Ghidra listing comment placement category. */
  public enum Type {
    /** Block banner comment displayed above the address. */
    PLATE,
    /** Pre-instruction comment displayed before the code unit. */
    PRE,
    /** End-of-line comment displayed beside the code unit. */
    EOL,
    /** Repeatable comment echoed at cross-reference sites. */
    REPEATABLE,
    /** Post-instruction comment displayed after the code unit. */
    POST
  }
}
