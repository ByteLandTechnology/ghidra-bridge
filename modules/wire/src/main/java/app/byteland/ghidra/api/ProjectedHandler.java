package app.byteland.ghidra.api;

import java.util.Set;

@FunctionalInterface
interface ProjectedHandler<Request, Response> extends ApiMethod.Handler<Request, Response> {
  Response handleProjected(Request request, Set<String> selectedFields) throws Exception;

  @Override
  default Response handle(Request request) throws Exception {
    return handleProjected(request, null);
  }
}
