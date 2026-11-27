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
      AddressScanOptions scan, int limit, String kind, String cursor);

  /**
   * Returns one page of instructions.
   */
  Page<InstructionResource> listInstructions(AddressScanOptions scan, int limit, String cursor);

  /**
   * Returns the metadata for one instruction by address.
   */
  InstructionResource getInstruction(String rawAddress);

  /**
   * Query parameters for string filters.
   */
  record StringQuery(
      AddressScanOptions scan,
      String query,
      String regex,
      boolean caseSensitive,
      Integer minLength,
      String encoding,
      boolean includeCandidates,
      int limit,
      String cursor) {
    public StringQuery {
      if (scan == null) throw new IllegalArgumentException("scan is required");
      if (limit < 1 || limit > Page.MAX_LIMIT) {
        throw new IllegalArgumentException("limit must be in 1.." + Page.MAX_LIMIT);
      }
      if (minLength != null && minLength < 1) {
        throw new IllegalArgumentException("min_length must be positive");
      }
    }
  }

  /**
   * Returns one page of defined data units.
   */
  Page<DataUnitResource> listDataUnits(AddressScanOptions scan, int limit, String cursor);

  /**
   * Returns one page of decoded strings.
   */
  Page<StringResource> listStrings(StringQuery query);

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
   * Sets or clears instruction flow overrides.
   */
  void setFlowOverrides(
      FlowOverrideScope scope,
      List<FlowOverrideValue> expectedFlowOverrides,
      FlowOverrideValue flowOverride);
}
