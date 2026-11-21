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
   * @param scan address range and timeout options
   * @param limit maximum items per page
   * @param kind optional code unit kind filter
   * @param direction traversal direction ({@code "forward"} or {@code "backward"})
   * @param cursor optional pagination cursor
   * @return page of code unit resources
   */
  Page<CodeUnitResource> listCodeUnits(
      AddressScanOptions scan, int limit, String kind, String direction, String cursor);

  /**
   * Returns one page of instructions.
   *
   * @param scan address range and timeout options
   * @param limit maximum items per page
   * @param direction traversal direction ({@code "forward"} or {@code "backward"})
   * @param cursor optional pagination cursor
   * @return page of instruction resources
   */
  Page<InstructionResource> listInstructions(
      AddressScanOptions scan, int limit, String direction, String cursor);

  /**
   * Returns the metadata for one instruction by address.
   *
   * @param rawAddress instruction address
   * @return instruction resource
   */
  InstructionResource getInstruction(String rawAddress);

  /**
   * Returns one page of defined data units.
   *
   * @param scan address range and timeout options
   * @param limit maximum items per page
   * @param direction traversal direction ({@code "forward"} or {@code "backward"})
   * @param cursor optional pagination cursor
   * @return page of data unit resources
   */
  Page<DataUnitResource> listDataUnits(
      AddressScanOptions scan, int limit, String direction, String cursor);

  /**
   * Returns instructions that have active flow overrides.
   *
   * @param scope address, function, or range scope to inspect
   * @param flowOverrides optional filter of flow override values
   * @param scan address scan timeout options
   * @param limit maximum items per page
   * @param cursor optional pagination cursor
   * @return page of matching instruction resources
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
   * @param expectedFlowOverrides optional precondition filter of current override values
   * @param flowOverride replacement flow override value
   */
  void setFlowOverrides(
      FlowOverrideScope scope,
      List<FlowOverrideValue> expectedFlowOverrides,
      FlowOverrideValue flowOverride);
}
