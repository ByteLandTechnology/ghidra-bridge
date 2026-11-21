package app.byteland.ghidra.service.listing;

import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import java.util.List;
import java.util.Objects;

/**
 * Inspects and modifies code units, instructions, and flow overrides.
 */
public interface ListingService {
  /**
   * Filter and pagination options for instruction list scans.
   */
  record InstructionListQuery(
      AddressScanOptions scan,
      int limit,
      String direction,
      String cursor,
      String mnemonic,
      String flowType,
      String function) {
    public InstructionListQuery {
      Objects.requireNonNull(scan, "scan");
    }
  }

  /**
   * Filter and pagination options for defined data unit list scans.
   */
  record DataUnitListQuery(
      AddressScanOptions scan,
      int limit,
      String direction,
      String cursor,
      String dataType,
      boolean stringOnly,
      String valueContains,
      boolean caseSensitive) {
    public DataUnitListQuery {
      Objects.requireNonNull(scan, "scan");
    }
  }

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
   * Returns one page of instructions that match the specified filters.
   */
  default Page<InstructionResource> listInstructions(InstructionListQuery query) {
    return listInstructions(query.scan(), query.limit(), query.direction(), query.cursor());
  }

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
   * Returns one page of defined data units that match the specified filters.
   */
  default Page<DataUnitResource> listDataUnits(DataUnitListQuery query) {
    return listDataUnits(query.scan(), query.limit(), query.direction(), query.cursor());
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
   * Sets or clears instruction flow overrides.
   */
  void setFlowOverrides(
      FlowOverrideScope scope,
      List<FlowOverrideValue> expectedFlowOverrides,
      FlowOverrideValue flowOverride);
}
