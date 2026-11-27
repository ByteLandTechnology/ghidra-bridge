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
import java.util.Set;

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
      AddressScanOptions scan, int limit, String kind, String cursor) {
    return listCodeUnits(scan, limit, kind, cursor, null);
  }

  @Override
  public Page<CodeUnitResource> listCodeUnits(
      AddressScanOptions scan, int limit, String kind, String cursor, Set<String> fields) {
    return codeUnitQueries.listCodeUnits(scan, limit, kind, cursor, fields);
  }

  @Override
  public Page<InstructionResource> listInstructions(
      AddressScanOptions scan, int limit, String cursor) {
    return listInstructions(scan, limit, cursor, null);
  }

  @Override
  public Page<InstructionResource> listInstructions(
      AddressScanOptions scan, int limit, String cursor, Set<String> fields) {
    return instructionQueries.listInstructions(scan, limit, cursor, fields);
  }

  @Override
  public InstructionResource getInstruction(String rawAddress) {
    return getInstruction(rawAddress, null);
  }

  @Override
  public InstructionResource getInstruction(String rawAddress, Set<String> fields) {
    return instructionQueries.getInstruction(rawAddress, fields);
  }

  @Override
  public Page<DataUnitResource> listDataUnits(AddressScanOptions scan, int limit, String cursor) {
    return listDataUnits(scan, limit, cursor, null);
  }

  @Override
  public Page<DataUnitResource> listDataUnits(
      AddressScanOptions scan, int limit, String cursor, Set<String> fields) {
    return dataQueries.listDataUnits(scan, limit, cursor, fields);
  }

  @Override
  public Page<InstructionResource> getFlowOverrides(
      FlowOverrideScope scope,
      List<FlowOverrideValue> flowOverrides,
      AddressScanOptions scan,
      int limit,
      String cursor) {
    return getFlowOverrides(scope, flowOverrides, scan, limit, cursor, null);
  }

  @Override
  public Page<InstructionResource> getFlowOverrides(
      FlowOverrideScope scope,
      List<FlowOverrideValue> flowOverrides,
      AddressScanOptions scan,
      int limit,
      String cursor,
      Set<String> fields) {
    return flowOverrideQueries.getFlowOverrides(scope, flowOverrides, scan, limit, cursor, fields);
  }

  @Override
  public void setFlowOverrides(
      FlowOverrideScope scope,
      List<FlowOverrideValue> expectedFlowOverrides,
      FlowOverrideValue flowOverride) {
    flowOverrideMutations.setFlowOverrides(scope, expectedFlowOverrides, flowOverride);
  }
}
