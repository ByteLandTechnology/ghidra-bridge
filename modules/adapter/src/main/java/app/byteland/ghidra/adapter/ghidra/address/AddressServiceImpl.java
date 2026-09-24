package app.byteland.ghidra.adapter.ghidra.address;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.address.AddressResource;
import app.byteland.ghidra.service.address.AddressService;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import java.util.Objects;

public final class AddressServiceImpl implements AddressService {
  private final GhidraSession context;

  public AddressServiceImpl(GhidraSession context) {
    this.context = Objects.requireNonNull(context, "context");
  }

  @Override
  public AddressResource resolveAddress(String rawAddress) {
    Address address = context.parseAddress(rawAddress);
    MemoryBlock block = context.script().getMemoryBlock(address);
    Function function = context.script().getFunctionContaining(address);
    Symbol symbol = context.script().getSymbolAt(address);
    return new AddressResource(
        AddressUtil.canonicalAddress(address),
        true,
        block != null,
        block == null
            ? null
            : new AddressResource.MemoryBlockSummary(
                block.getName(),
                AddressUtil.canonicalAddress(block.getStart()),
                AddressUtil.canonicalAddress(block.getEnd()),
                block.getSize(),
                block.isRead(),
                block.isWrite(),
                block.isExecute()),
        function == null
            ? null
            : new AddressResource.FunctionSummary(
                AddressUtil.canonicalAddress(function.getEntryPoint()), function.getName()),
        symbol == null
            ? null
            : new AddressResource.SymbolSummary(
                String.valueOf(symbol.getID()),
                symbol.getName(),
                symbol.getSymbolType().toString()));
  }
}
