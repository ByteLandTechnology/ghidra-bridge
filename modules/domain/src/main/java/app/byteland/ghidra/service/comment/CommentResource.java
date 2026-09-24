package app.byteland.ghidra.service.comment;

public record CommentResource(String address, Type type, String text) {
  public enum Type {
    PLATE,
    PRE,
    EOL,
    REPEATABLE,
    POST
  }
}
