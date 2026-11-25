package app.byteland.ghidra.service.listing;

import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import java.util.List;
import java.util.Set;

/**
 * Inspects and modifies code units, instructions, and flow overrides.
 */
public interface ListingService {
  /**
   * Returns one page of code units.
   */
  Page<CodeUnitResource> listCodeUnits(
      AddressScanOptions scan, int limit, String kind, String cursor);

  /**
   * Returns one page of code units with an optional field projection.
   */
  default Page<CodeUnitResource> listCodeUnits(
      AddressScanOptions scan, int limit, String kind, String cursor, Set<String> fields) {
    return listCodeUnits(scan, limit, kind, cursor);
  }

  /**
   * Returns one page of instructions.
   */
  Page<InstructionResource> listInstructions(AddressScanOptions scan, int limit, String cursor);

  /**
   * Returns one page of instructions with an optional field projection.
   */
  default Page<InstructionResource> listInstructions(
      AddressScanOptions scan, int limit, String cursor, Set<String> fields) {
    return listInstructions(scan, limit, cursor);
  }

  /**
   * Returns the metadata for one instruction by address.
   */
  InstructionResource getInstruction(String rawAddress);

  /**
   * Returns the metadata for one instruction by address with an optional field projection.
   */
  default InstructionResource getInstruction(String rawAddress, Set<String> fields) {
    return getInstruction(rawAddress);
  }

  /**
   * Returns one page of defined data units.
   */
  Page<DataUnitResource> listDataUnits(AddressScanOptions scan, int limit, String cursor);

  /**
   * Returns one page of defined data units with an optional field projection.
   */
  default Page<DataUnitResource> listDataUnits(
      AddressScanOptions scan, int limit, String cursor, Set<String> fields) {
    return listDataUnits(scan, limit, cursor);
  }

  /**
   * Returns instructions that have active flow overrides.
   */
  Page<InstructionResource> getFlowOverrides(
      FlowOverrideScope scope,
      List<FlowOverrideValue> flowOverrides,
      AddressScanOptions scan,
      int limit,
      String cursor);

  /**
   * Returns instructions that have active flow overrides with an optional field projection.
   */
  default Page<InstructionResource> getFlowOverrides(
      FlowOverrideScope scope,
      List<FlowOverrideValue> flowOverrides,
      AddressScanOptions scan,
      int limit,
      String cursor,
      Set<String> fields) {
    return getFlowOverrides(scope, flowOverrides, scan, limit, cursor);
  }

  /**
   * Sets or clears instruction flow overrides.
   */
  void setFlowOverrides(
      FlowOverrideScope scope,
      List<FlowOverrideValue> expectedFlowOverrides,
      FlowOverrideValue flowOverride);
}
