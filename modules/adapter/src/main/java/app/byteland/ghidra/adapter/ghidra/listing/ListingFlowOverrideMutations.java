package app.byteland.ghidra.adapter.ghidra.listing;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.listing.FlowOverrideScope;
import app.byteland.ghidra.service.listing.FlowOverrideValue;
import ghidra.app.cmd.disassemble.SetFlowOverrideCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Set;

final class ListingFlowOverrideMutations {
  private static final int MAX_MATCHED_INSTRUCTIONS = 1_000;

  private final GhidraSession context;
  private final ListingFlowOverrideScopes scopes;

  ListingFlowOverrideMutations(GhidraSession context, ListingFlowOverrideScopes scopes) {
    this.context = context;
    this.scopes = scopes;
  }

  void setFlowOverrides(
      FlowOverrideScope scope,
      List<FlowOverrideValue> expectedValues,
      FlowOverrideValue targetValue) {
    Set<FlowOverride> expected = flowOverrides(expectedValues);
    List<String> candidates = candidates(scope, expected);
    FlowOverride target = flowOverride(targetValue);
    for (String address : candidates) patchOne(address, expected, target);
  }

  private List<String> candidates(FlowOverrideScope selected, Set<FlowOverride> expected) {
    if (selected instanceof FlowOverrideScope.AddressScope address) {
      return List.of(AddressUtil.canonicalAddress(context.parseAddress(address.address())));
    }
    ListingFlowOverrideScopes.ResolvedScope scope = scopes.resolve(selected);
    List<String> candidates = new ArrayList<>();
    for (Instruction instruction :
        context.currentProgram().getListing().getInstructions(scope.addresses(), true)) {
      if (!expected.contains(instruction.getFlowOverride())) continue;
      if (candidates.size() >= MAX_MATCHED_INSTRUCTIONS) {
        throw new IllegalArgumentException(
            "selected scope matches more than " + MAX_MATCHED_INSTRUCTIONS + " instructions");
      }
      candidates.add(AddressUtil.canonicalAddress(instruction.getAddress()));
    }
    return List.copyOf(candidates);
  }

  private void patchOne(String rawAddress, Set<FlowOverride> expected, FlowOverride target) {
    Address address = context.parseAddress(rawAddress);
    Instruction instruction = context.currentProgram().getListing().getInstructionAt(address);
    if (instruction == null) throw new NoSuchElementException("no instruction at address");
    FlowOverride current = instruction.getFlowOverride();
    if (!expected.contains(current)) {
      throw ListingFlowOverrideErrors.conflict(
          "expected one of " + expected + " but found " + current.name());
    }
    if (current == target) return;
    boolean hadExplicitFallThrough = instruction.isFallThroughOverridden();
    Address explicitFallThrough = hadExplicitFallThrough ? instruction.getFallThrough() : null;
    try {
      context.runCommand(
          new SetFlowOverrideCmd(address, target), "unable to set instruction flow override");
    } catch (IllegalArgumentException exception) {
      throw ListingFlowOverrideErrors.updateFailed(exception.getMessage(), exception);
    }
    instruction = context.currentProgram().getListing().getInstructionAt(address);
    if (instruction == null || instruction.getFlowOverride() != target) {
      throw ListingFlowOverrideErrors.updateFailed(
          "instruction flow override did not reach " + target.name());
    }
    if (instruction.isFallThroughOverridden() != hadExplicitFallThrough
        || (hadExplicitFallThrough
            && !Objects.equals(explicitFallThrough, instruction.getFallThrough()))) {
      throw ListingFlowOverrideErrors.updateFailed(
          "explicit fallthrough override changed unexpectedly");
    }
  }

  private static Set<FlowOverride> flowOverrides(List<FlowOverrideValue> values) {
    Set<FlowOverride> result = new LinkedHashSet<>();
    for (FlowOverrideValue value : values) result.add(flowOverride(value));
    return result;
  }

  private static FlowOverride flowOverride(FlowOverrideValue value) {
    return FlowOverride.valueOf(value.name());
  }
}
