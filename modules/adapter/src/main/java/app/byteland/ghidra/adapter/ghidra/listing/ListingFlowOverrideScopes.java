package app.byteland.ghidra.adapter.ghidra.listing;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.scan.AddressScopeResolver;
import app.byteland.ghidra.service.listing.FlowOverrideScope;
import ghidra.program.model.address.AddressSetView;

final class ListingFlowOverrideScopes {
  record ResolvedScope(AddressSetView addresses) {}

  private final AddressScopeResolver resolver;

  ListingFlowOverrideScopes(GhidraSession context) {
    this.resolver = new AddressScopeResolver(context);
  }

  ResolvedScope resolve(FlowOverrideScope scope) {
    return new ResolvedScope(resolver.resolve(scope));
  }
}
