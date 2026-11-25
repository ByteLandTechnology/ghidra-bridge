package app.byteland.ghidra.adapter.ghidra.reference;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.reference.ReferenceContextResource;
import app.byteland.ghidra.service.reference.ReferenceResource;
import app.byteland.ghidra.service.reference.ReferenceService;

public final class ReferenceServiceImpl implements ReferenceService {
  private final ReferenceListQueries listQueries;
  private final ReferenceContextQueries contextQueries;

  public ReferenceServiceImpl(GhidraSession context) {
    this.listQueries = new ReferenceListQueries(context);
    this.contextQueries = new ReferenceContextQueries(context);
  }

  @Override
  public Page<ReferenceResource> listReferences(
      String fromRaw, String toRaw, String type, String direction, int limit, String cursor) {
    return listQueries.listReferences(fromRaw, toRaw, type, direction, limit, cursor);
  }

  @Override
  public Page<ReferenceContextResource> listReferenceContext(
      String toRaw,
      String entryRaw,
      String symbolIdRaw,
      String type,
      AddressScanOptions scan,
      int limit,
      String cursor) {
    return contextQueries.listReferenceContext(
        toRaw, entryRaw, symbolIdRaw, type, scan, limit, cursor);
  }
}
