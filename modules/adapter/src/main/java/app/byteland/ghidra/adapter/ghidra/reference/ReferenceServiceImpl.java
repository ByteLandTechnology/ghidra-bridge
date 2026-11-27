package app.byteland.ghidra.adapter.ghidra.reference;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.scan.AddressScopeResolver;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.listing.FlowOverrideScope;
import app.byteland.ghidra.service.reference.ReferenceResource;
import app.byteland.ghidra.service.reference.ReferenceService;

public final class ReferenceServiceImpl implements ReferenceService {
  private final ReferenceListQueries listQueries;

  public ReferenceServiceImpl(GhidraSession context) {
    this.listQueries = new ReferenceListQueries(context, new AddressScopeResolver(context));
  }

  @Override
  public Page<ReferenceResource> listReferences(
      String fromRaw,
      String toRaw,
      String type,
      String direction,
      FlowOverrideScope scope,
      AddressScanOptions scan,
      int limit,
      String cursor) {
    return listQueries.listReferences(
        fromRaw, toRaw, type, direction, scope, scan, limit, cursor);
  }
}
