package app.byteland.ghidra.adapter.ghidra.reference;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.reference.ReferenceResource;
import app.byteland.ghidra.service.reference.ReferenceService;

public final class ReferenceServiceImpl implements ReferenceService {
  private final ReferenceListQueries listQueries;

  public ReferenceServiceImpl(GhidraSession context) {
    this.listQueries = new ReferenceListQueries(context);
  }

  @Override
  public Page<ReferenceResource> listReferences(ReferenceQuery query) {
    return listQueries.listReferences(query);
  }
}
