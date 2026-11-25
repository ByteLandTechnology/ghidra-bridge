package app.byteland.ghidra.adapter.ghidra.listing;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.listing.AddressOrRangeScope;
import app.byteland.ghidra.service.listing.CodeUnitClearReceipt;
import app.byteland.ghidra.service.listing.CodeUnitResource;
import app.byteland.ghidra.service.listing.DataUnitResource;
import app.byteland.ghidra.service.listing.FlowOverrideScope;
import app.byteland.ghidra.service.listing.FlowOverrideValue;
import app.byteland.ghidra.service.listing.InstructionResource;
import app.byteland.ghidra.service.listing.ListingService;
import java.util.List;

public final class ListingServiceImpl implements ListingService {
  private final ListingCodeUnitQueries codeUnitQueries;
  private final ListingCodeUnitMutations codeUnitMutations;
  private final ListingInstructionQueries instructionQueries;
  private final ListingInstructionMutations instructionMutations;
  private final ListingDataQueries dataQueries;
  private final ListingFlowOverrideQueries flowOverrideQueries;
  private final ListingFlowOverrideMutations flowOverrideMutations;

  public ListingServiceImpl(GhidraSession context) {
    this.codeUnitQueries = new ListingCodeUnitQueries(context);
    this.codeUnitMutations = new ListingCodeUnitMutations(context);
    this.instructionQueries = new ListingInstructionQueries(context);
    this.instructionMutations =
        new ListingInstructionMutations(context, new ListingAssemblerCache());
    this.dataQueries = new ListingDataQueries(context);
    ListingFlowOverrideScopes flowOverrideScopes = new ListingFlowOverrideScopes(context);
    this.flowOverrideQueries = new ListingFlowOverrideQueries(context, flowOverrideScopes);
    this.flowOverrideMutations = new ListingFlowOverrideMutations(context, flowOverrideScopes);
  }

  @Override
  public Page<CodeUnitResource> listCodeUnits(
      AddressScanOptions scan, int limit, String kind, String cursor) {
    return codeUnitQueries.listCodeUnits(scan, limit, kind, cursor);
  }

  @Override
  public CodeUnitClearReceipt clearCodeUnits(AddressOrRangeScope scope, boolean clearContext) {
    return codeUnitMutations.clearCodeUnits(scope, clearContext);
  }

  @Override
  public Page<InstructionResource> listInstructions(
      AddressScanOptions scan, int limit, String cursor) {
    return instructionQueries.listInstructions(scan, limit, cursor);
  }

  @Override
  public InstructionResource getInstruction(String rawAddress) {
    return instructionQueries.getInstruction(rawAddress);
  }

  @Override
  public List<InstructionResource> assembleInstructions(
      String rawAddress, List<String> instructions, boolean padNop) {
    return instructionMutations.assembleInstructions(rawAddress, instructions, padNop);
  }

  @Override
  public List<InstructionResource> disassembleInstructions(
      AddressOrRangeScope scope, boolean followFlow) {
    return instructionMutations.disassembleInstructions(scope, followFlow);
  }

  @Override
  public Page<DataUnitResource> listDataUnits(AddressScanOptions scan, int limit, String cursor) {
    return dataQueries.listDataUnits(scan, limit, cursor);
  }

  @Override
  public Page<InstructionResource> getFlowOverrides(
      FlowOverrideScope scope,
      List<FlowOverrideValue> flowOverrides,
      AddressScanOptions scan,
      int limit,
      String cursor) {
    return flowOverrideQueries.getFlowOverrides(scope, flowOverrides, scan, limit, cursor);
  }

  @Override
  public void setFlowOverrides(
      FlowOverrideScope scope,
      List<FlowOverrideValue> expectedFlowOverrides,
      FlowOverrideValue flowOverride) {
    flowOverrideMutations.setFlowOverrides(scope, expectedFlowOverrides, flowOverride);
  }
}
