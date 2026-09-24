package app.byteland.ghidra.service.comment;

import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;

/**
 * Manages listing comments across memory addresses.
 */
public interface CommentService {
  /**
   * Search criteria and bounds for comment queries.
   */
  record CommentQuery(
      AddressScanOptions scan, CommentResource.Type type, String text, int limit, String cursor) {
    public CommentQuery {
      if (scan == null) throw new IllegalArgumentException("scan is required");
      if (limit < 1 || limit > 1000) throw new IllegalArgumentException("limit must be in 1..1000");
    }
  }

  /**
   * Returns one page of matching comments.
   *
   * @param query the search query criteria
   * @return a page of comment resources
   */
  Page<CommentResource> listComments(CommentQuery query);

  /**
   * Sets comment text at the specified address.
   *
   * @param addressRaw target memory address
   * @param type comment classification type
   * @param text new comment text content
   */
  void setComment(String addressRaw, CommentResource.Type type, String text);

  /**
   * Deletes comment text at the specified address.
   *
   * @param addressRaw target memory address
   * @param type comment classification type to clear
   */
  void deleteComment(String addressRaw, CommentResource.Type type);
}
