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
   *
   * @param scan address scan bounds and timeout options
   * @param limit maximum code units to return
   * @param kind optional code unit kind filter
   * @param cursor optional pagination cursor
   * @return page of code unit resources
   */
  Page<CodeUnitResource> listCodeUnits(
      AddressScanOptions scan, int limit, String kind, String cursor);

  /**
   * Returns one page of instructions.
   *
   * @param scan address scan bounds and timeout options
   * @param limit maximum instructions to return
   * @param cursor optional pagination cursor
   * @return page of instruction resources
   */
  Page<InstructionResource> listInstructions(AddressScanOptions scan, int limit, String cursor);

  /**
   * Returns the metadata for one instruction by address.
   *
   * @param rawAddress target instruction address
   * @return instruction resource
   */
  InstructionResource getInstruction(String rawAddress);

  /**
   * Returns one page of defined data units.
   *
   * @param scan address scan bounds and timeout options
   * @param limit maximum data units to return
   * @param cursor optional pagination cursor
   * @return page of defined data unit resources
   */
  Page<DataUnitResource> listDataUnits(AddressScanOptions scan, int limit, String cursor);

  /**
   * Returns instructions that have active flow overrides.
   *
   * @param scope address, function, or range scope to inspect
   * @param flowOverrides optional filter of flow override values to match
   * @param scan address scan bounds and timeout options
   * @param limit maximum instructions to return
   * @param cursor optional pagination cursor
   * @return page of matched instruction resources
   */
  Page<InstructionResource> getFlowOverrides(
      FlowOverrideScope scope,
      List<FlowOverrideValue> flowOverrides,
      AddressScanOptions scan,
      int limit,
      String cursor);

  /**
   * Sets or clears instruction flow overrides.
   *
   * @param scope address, function, or range scope to modify
   * @param expectedFlowOverrides optional precondition filter on current flow overrides
   * @param flowOverride replacement flow override value
   */
  void setFlowOverrides(
      FlowOverrideScope scope,
      List<FlowOverrideValue> expectedFlowOverrides,
      FlowOverrideValue flowOverride);
}
