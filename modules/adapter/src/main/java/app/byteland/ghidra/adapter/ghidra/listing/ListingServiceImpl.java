package app.byteland.ghidra.adapter.ghidra.listing;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.listing.CodeUnitResource;
import app.byteland.ghidra.service.listing.DataUnitResource;
import app.byteland.ghidra.service.listing.FlowOverrideScope;
import app.byteland.ghidra.service.listing.FlowOverrideValue;
import app.byteland.ghidra.service.listing.InstructionResource;
import app.byteland.ghidra.service.listing.ListingService;
import java.util.List;

public final class ListingServiceImpl implements ListingService {
  private final ListingCodeUnitQueries codeUnitQueries;
  private final ListingInstructionQueries instructionQueries;
  private final ListingDataQueries dataQueries;
  private final ListingFlowOverrideQueries flowOverrideQueries;
  private final ListingFlowOverrideMutations flowOverrideMutations;

  public ListingServiceImpl(GhidraSession context) {
    this.codeUnitQueries = new ListingCodeUnitQueries(context);
    this.instructionQueries = new ListingInstructionQueries(context);
    this.dataQueries = new ListingDataQueries(context);
    ListingFlowOverrideScopes flowOverrideScopes = new ListingFlowOverrideScopes(context);
    this.flowOverrideQueries = new ListingFlowOverrideQueries(context, flowOverrideScopes);
    this.flowOverrideMutations = new ListingFlowOverrideMutations(context, flowOverrideScopes);
  }

  @Override
  public Page<CodeUnitResource> listCodeUnits(
      AddressScanOptions scan, int limit, String kind, String direction, String cursor) {
    return codeUnitQueries.listCodeUnits(scan, limit, kind, direction, cursor);
  }

  @Override
  public Page<InstructionResource> listInstructions(
      AddressScanOptions scan, int limit, String direction, String cursor) {
    return instructionQueries.listInstructions(scan, limit, direction, cursor);
  }

  @Override
  public InstructionResource getInstruction(String rawAddress) {
    return instructionQueries.getInstruction(rawAddress);
  }

  @Override
  public Page<DataUnitResource> listDataUnits(
      AddressScanOptions scan, int limit, String direction, String cursor) {
    return dataQueries.listDataUnits(scan, limit, direction, cursor);
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
