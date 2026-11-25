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
   * @param scan bounded address-scan options
   * @param limit maximum items per page
   * @param kind optional code unit kind filter
   * @param direction traversal direction ({@code forward} or {@code backward})
   * @param cursor pagination cursor, or {@code null}
   * @return page of listing code units
   */
  Page<CodeUnitResource> listCodeUnits(
      AddressScanOptions scan, int limit, String kind, String direction, String cursor);

  /**
   * Returns one page of instructions.
   *
   * @param scan bounded address-scan options
   * @param limit maximum items per page
   * @param direction traversal direction ({@code forward} or {@code backward})
   * @param cursor pagination cursor, or {@code null}
   * @return page of disassembled instructions
   */
  Page<InstructionResource> listInstructions(
      AddressScanOptions scan, int limit, String direction, String cursor);

  /**
   * Returns the metadata for one instruction by address.
   *
   * @param rawAddress instruction start address
   * @return instruction resource
   */
  InstructionResource getInstruction(String rawAddress);

  /**
   * Returns one page of defined data units.
   *
   * @param scan bounded address-scan options
   * @param limit maximum items per page
   * @param direction traversal direction ({@code forward} or {@code backward})
   * @param cursor pagination cursor, or {@code null}
   * @return page of defined data units
   */
  Page<DataUnitResource> listDataUnits(
      AddressScanOptions scan, int limit, String direction, String cursor);

  /**
   * Returns instructions that have active flow overrides.
   *
   * @param scope address, function, or range scope to inspect
   * @param flowOverrides optional flow override values to match
   * @param scan bounded address-scan options
   * @param limit maximum items per page
   * @param cursor pagination cursor, or {@code null}
   * @return page of instructions matching the flow override filter
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
   * @param scope address, function, or range scope to update
   * @param expectedFlowOverrides optional precondition filter on current flow overrides
   * @param flowOverride flow override value to apply
   */
  void setFlowOverrides(
      FlowOverrideScope scope,
      List<FlowOverrideValue> expectedFlowOverrides,
      FlowOverrideValue flowOverride);
}
