package app.byteland.ghidra.service.listing;

import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import java.util.List;

/**
 * Inspects and modifies code units, instructions, and flow overrides.
 */
public interface ListingService {
  /**
   * Returns one page of code units.
   */
  Page<CodeUnitResource> listCodeUnits(
      AddressScanOptions scan, int limit, String kind, String direction, String cursor);

  /**
   * Returns one page of instructions.
   */
  Page<InstructionResource> listInstructions(
      AddressScanOptions scan, int limit, String direction, String cursor);

  /**
   * Returns the metadata for one instruction by address.
   */
  InstructionResource getInstruction(String rawAddress);

  /**
   * Returns one page of defined data units.
   */
  Page<DataUnitResource> listDataUnits(
      AddressScanOptions scan, int limit, String direction, String cursor);

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
   * Returns code units and overlay resources for one address window.
   */
  default ListingWindowResource getListingWindow(
      AddressScanOptions scan, int limit, String kind, String cursor) {
    throw new UnsupportedOperationException("getListingWindow");
  }

  /**
   * Sets or clears instruction flow overrides.
   */
  void setFlowOverrides(
      FlowOverrideScope scope,
      List<FlowOverrideValue> expectedFlowOverrides,
      FlowOverrideValue flowOverride);
}
