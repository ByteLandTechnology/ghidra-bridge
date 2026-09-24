package app.byteland.ghidra.adapter.ghidra.comment;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.comment.CommentResource;
import app.byteland.ghidra.service.comment.CommentService;

public final class CommentServiceImpl implements CommentService {
  private final CommentQueries queries;
  private final CommentMutations mutations;

  public CommentServiceImpl(GhidraSession context) {
    this.queries = new CommentQueries(context);
    this.mutations = new CommentMutations(context);
  }

  @Override
  public Page<CommentResource> listComments(CommentQuery query) {
    return queries.listComments(
        query.scan(),
        query.type() == null ? null : query.type().name().toLowerCase(java.util.Locale.ROOT),
        query.text(),
        query.limit(),
        query.cursor());
  }

  @Override
  public void setComment(String addressRaw, CommentResource.Type type, String text) {
    mutations.setComment(addressRaw, type.name().toLowerCase(java.util.Locale.ROOT), text);
  }

  @Override
  public void deleteComment(String addressRaw, CommentResource.Type type) {
    mutations.deleteComment(addressRaw, type.name().toLowerCase(java.util.Locale.ROOT));
  }
}
