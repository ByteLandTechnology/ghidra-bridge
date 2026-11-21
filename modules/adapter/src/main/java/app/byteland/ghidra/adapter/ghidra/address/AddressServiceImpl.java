package app.byteland.ghidra.adapter.ghidra.address;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.FieldProjections;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.address.AddressResource;
import app.byteland.ghidra.service.address.AddressService;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import java.util.Objects;
import java.util.Set;

public final class AddressServiceImpl implements AddressService {
  private final GhidraSession context;

  public AddressServiceImpl(GhidraSession context) {
    this.context = Objects.requireNonNull(context, "context");
  }

  @Override
  public AddressResource resolveAddress(String rawAddress) {
    return resolveAddress(rawAddress, null);
  }

  @Override
  public AddressResource resolveAddress(String rawAddress, Set<String> fields) {
    Address address = context.parseAddress(rawAddress);
    boolean needInMemory = FieldProjections.allows(fields, "in_memory");
    boolean needMemoryBlock = FieldProjections.allows(fields, "memory_block");
    boolean needFunction = FieldProjections.allows(fields, "function");
    boolean needSymbol = FieldProjections.allows(fields, "symbol");
    boolean needCodeUnit = FieldProjections.allows(fields, "code_unit");
    MemoryBlock block =
        needInMemory || needMemoryBlock ? context.script().getMemoryBlock(address) : null;
    Function function = needFunction ? context.script().getFunctionContaining(address) : null;
    Symbol symbol = needSymbol ? context.script().getSymbolAt(address) : null;
    CodeUnit unit =
        needCodeUnit ? context.currentProgram().getListing().getCodeUnitContaining(address) : null;
    return new AddressResource(
        AddressUtil.canonicalAddress(address),
        true,
        needInMemory && block != null,
        block == null || !needMemoryBlock
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
                symbol.getSymbolType().toString()),
        unit == null
            ? null
            : new AddressResource.CodeUnitSummary(
                AddressUtil.canonicalAddress(unit.getMinAddress()),
                AddressUtil.canonicalAddress(unit.getMaxAddress())));
  }
}
