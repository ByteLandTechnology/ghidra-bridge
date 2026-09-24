package app.byteland.ghidra.api;

import static app.byteland.ghidra.api.ApiRegistry.NOT_FOUND_STATUS;
import static app.byteland.ghidra.api.ApiRegistry.addressScan;
import static app.byteland.ghidra.api.ApiRegistry.commentType;
import static app.byteland.ghidra.api.ApiRegistry.filter;
import static app.byteland.ghidra.api.ApiRegistry.optionalText;
import static app.byteland.ghidra.api.ApiRegistry.patch;
import static app.byteland.ghidra.api.ApiRegistry.resource;
import static app.byteland.ghidra.api.ApiRegistry.selector;
import static app.byteland.ghidra.api.ApiRegistry.text;

import app.byteland.ghidra.api.ApiMethod.MethodEffects;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.comment.CommentResource;
import app.byteland.ghidra.service.comment.CommentService;
import java.util.List;
import java.util.Map;

final class CommentMethods implements ApiMethodProvider {
  private final ApiRegistry registry;

  CommentMethods(ApiRegistry registry) {
    this.registry = registry;
  }

  @Override
  public void register() {
    Map<String, Object> commentSelector =
        WireSchema.object(
            Map.of(
                ApiVocabulary.ADDRESS, WireSchema.nonBlankString(),
                ApiVocabulary.TYPE, ApiSchemaCatalog.commentTypeSchema()),
            ApiVocabulary.ADDRESS,
            ApiVocabulary.TYPE);
    registry.read(
        "comment.get",
        ApiSchemaCatalog.selectorInput(commentSelector),
        ApiSchemaCatalog.commentFields(),
        List.of(ApiVocabulary.ADDRESS, ApiVocabulary.TYPE),
        request -> requireComment(selector(request)));
    Map<String, Object> commentFilter =
        WireSchema.object(
            ApiSchemaCatalog.props(
                ApiVocabulary.ADDRESS, WireSchema.string(),
                ApiVocabulary.END, WireSchema.string(),
                ApiVocabulary.TYPE, ApiSchemaCatalog.commentTypeSchema(),
                ApiVocabulary.TEXT, WireSchema.string()));
    registry.scanList(
        "comment.list",
        ApiSchemaCatalog.scanListInput(commentFilter),
        ApiSchemaCatalog.commentFields(),
        List.of(ApiVocabulary.ADDRESS, ApiVocabulary.TYPE),
        (request, page) -> {
          Map<String, Object> filter = filter(request);
          return registry
              .services()
              .commentService()
              .listComments(
                  new CommentService.CommentQuery(
                      addressScan(request, ApiVocabulary.ADDRESS, ApiVocabulary.END),
                      commentType(optionalText(filter, ApiVocabulary.TYPE)),
                      optionalText(filter, ApiVocabulary.TEXT),
                      page.limit(),
                      page.cursor()));
        });
    Map<String, Object> commentResource =
        WireSchema.object(
            ApiSchemaCatalog.props(
                ApiVocabulary.ADDRESS, WireSchema.nonBlankString(),
                ApiVocabulary.TYPE, ApiSchemaCatalog.commentTypeSchema(),
                ApiVocabulary.TEXT, WireSchema.nonBlankString()),
            ApiVocabulary.ADDRESS,
            ApiVocabulary.TYPE,
            ApiVocabulary.TEXT);
    registry.writeResource(
        "comment.create",
        MethodEffects.mutation(false, false),
        ApiSchemaCatalog.input(
            ApiSchemaCatalog.props(ApiVocabulary.RESOURCE, commentResource),
            ApiVocabulary.RESOURCE),
        ApiSchemaCatalog.commentFields(),
        List.of(ApiVocabulary.ADDRESS, ApiVocabulary.TYPE),
        request -> {
          writeComment(request, false);
          return requireComment(resource(request));
        });
    registry.writeResource(
        "comment.patch",
        MethodEffects.mutation(true, true),
        ApiSchemaCatalog.input(
            ApiSchemaCatalog.props(
                ApiVocabulary.SELECTOR,
                commentSelector,
                ApiVocabulary.PATCH,
                WireSchema.object(
                    Map.of(ApiVocabulary.TEXT, WireSchema.nonBlankString()), ApiVocabulary.TEXT)),
            ApiVocabulary.SELECTOR,
            ApiVocabulary.PATCH),
        ApiSchemaCatalog.commentFields(),
        List.of(ApiVocabulary.ADDRESS, ApiVocabulary.TYPE),
        request -> {
          patchComment(request);
          return requireComment(selector(request));
        });
    registry.writeResource(
        "comment.upsert",
        MethodEffects.mutation(true, true),
        ApiSchemaCatalog.input(
            ApiSchemaCatalog.props(ApiVocabulary.RESOURCE, commentResource),
            ApiVocabulary.RESOURCE),
        ApiSchemaCatalog.commentFields(),
        List.of(ApiVocabulary.ADDRESS, ApiVocabulary.TYPE),
        request -> {
          writeComment(request, true);
          return requireComment(resource(request));
        });
    registry.writeResult(
        "comment.delete",
        MethodEffects.mutation(true, true),
        ApiSchemaCatalog.selectorOnlyInput(commentSelector),
        ApiSchemaCatalog.DELETED_RECEIPT_SCHEMA,
        request -> {
          requireComment(selector(request));
          registry
              .services()
              .commentService()
              .deleteComment(
                  text(selector(request), ApiVocabulary.ADDRESS),
                  commentType(text(selector(request), ApiVocabulary.TYPE)));
          return Map.of(ApiVocabulary.DELETED, true);
        });
  }

  private CommentResource requireComment(Map<String, Object> selected) {
    Page<CommentResource> page =
        registry
            .services()
            .commentService()
            .listComments(
                new CommentService.CommentQuery(
                    new AddressScanOptions(
                        text(selected, ApiVocabulary.ADDRESS),
                        text(selected, ApiVocabulary.ADDRESS),
                        AddressScanOptions.DEFAULT_TIMEOUT_MS),
                    commentType(text(selected, ApiVocabulary.TYPE)),
                    null,
                    2,
                    null));
    if (page.items().isEmpty()) {
      throw new ApiException(404, "comment_not_found", "comment not found", "/selector");
    }
    return page.items().getFirst();
  }

  private void writeComment(Map<String, Object> request, boolean upsert) {
    Map<String, Object> resource = resource(request);
    if (!upsert) {
      try {
        requireComment(resource);
        throw new ApiException(409, "comment_exists", "comment already exists", "/resource");
      } catch (ApiException error) {
        if (error.status() != NOT_FOUND_STATUS) throw error;
      }
    }
    registry
        .services()
        .commentService()
        .setComment(
            text(resource, ApiVocabulary.ADDRESS),
            commentType(text(resource, ApiVocabulary.TYPE)),
            text(resource, ApiVocabulary.TEXT));
  }

  private void patchComment(Map<String, Object> request) {
    requireComment(selector(request));
    registry
        .services()
        .commentService()
        .setComment(
            text(selector(request), ApiVocabulary.ADDRESS),
            commentType(text(selector(request), ApiVocabulary.TYPE)),
            text(patch(request), ApiVocabulary.TEXT));
  }
}
