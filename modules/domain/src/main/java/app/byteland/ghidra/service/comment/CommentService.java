package app.byteland.ghidra.service.comment;

import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;

/**
 * Manages comments at memory addresses.
 */
public interface CommentService {
  /**
   * Search criteria and limits for comment queries.
   *
   * @param scan address scan bounds and timeout options
   * @param type optional comment type filter
   * @param text optional case-insensitive text filter
   * @param limit maximum comments to return in {@code 1..1000}
   * @param cursor optional pagination cursor
   */
  record CommentQuery(
      AddressScanOptions scan, CommentResource.Type type, String text, int limit, String cursor) {
    /** Validates scan options and page limit bounds. */
    public CommentQuery {
      if (scan == null) throw new IllegalArgumentException("scan is required");
      if (limit < 1 || limit > 1000) throw new IllegalArgumentException("limit must be in 1..1000");
    }
  }

  /**
   * Returns one page of comments that match the query.
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
   * @param text new comment text
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
