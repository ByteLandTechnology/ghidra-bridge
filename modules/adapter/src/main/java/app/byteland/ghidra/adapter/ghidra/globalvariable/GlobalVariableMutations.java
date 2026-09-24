package app.byteland.ghidra.adapter.ghidra.globalvariable;

import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.ScriptSymbolRenamer;
import app.byteland.ghidra.service.globalvariable.GlobalVariableConflictException;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService.Mutation;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService.WriteMode;
import ghidra.app.cmd.label.SetLabelPrimaryCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.InvalidInputException;
import java.util.NoSuchElementException;
import java.util.Objects;

final class GlobalVariableMutations {
  private final GhidraSession context;

  GlobalVariableMutations(GhidraSession context) {
    this.context = context;
  }

  void writeGlobalVariable(Mutation mutation, WriteMode mode) {
    Objects.requireNonNull(mutation, "mutation");
    Objects.requireNonNull(mode, "mode");
    if (mode != WriteMode.PATCH && (mutation.name() == null || mutation.dataType() == null)) {
      throw new IllegalArgumentException("create and upsert require name and dataType");
    }
    Address address = context.parseAddress(mutation.address());
    Listing listing = context.currentProgram().getListing();
    Data existing = listing.getDefinedDataAt(address);
    if (mode == WriteMode.CREATE && existing != null) {
      throw new GlobalVariableConflictException(
          "global_variable_exists",
          "/resource/address",
          "defined data already exists at " + mutation.address());
    }
    if (mode == WriteMode.PATCH && existing == null) {
      throw new NoSuchElementException("global variable not found: " + mutation.address());
    }

    if (mutation.dataType() != null) {
      DataType dataType =
          GhidraDataTypeReferences.resolve(
              context.currentProgram().getDataTypeManager(), mutation.dataType());
      applyData(address, dataType, existing == null, mode);
    }
    if (mutation.name() != null) applyName(address, mutation.name());
  }

  void deleteGlobalVariable(String rawAddress, boolean deleteSymbol) {
    Address address = context.parseAddress(rawAddress);
    Listing listing = context.currentProgram().getListing();
    Data data = listing.getDefinedDataAt(address);
    if (data == null) throw new NoSuchElementException("global variable not found: " + rawAddress);
    Symbol primary = context.currentProgram().getSymbolTable().getPrimarySymbol(address);
    listing.clearCodeUnits(data.getMinAddress(), data.getMaxAddress(), false);
    if (deleteSymbol
        && primary != null
        && !primary.isDynamic()
        && SymbolType.LABEL.equals(primary.getSymbolType())
        && !primary.delete()) {
      throw new IllegalArgumentException("unable to delete global variable symbol");
    }
  }

  private void applyData(Address address, DataType dataType, boolean create, WriteMode mode) {
    try {
      DataUtilities.createData(
          context.currentProgram(),
          address,
          dataType,
          -1,
          create
              ? DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA
              : DataUtilities.ClearDataMode.CHECK_FOR_SPACE);
    } catch (CodeUnitInsertionException failure) {
      throw new GlobalVariableConflictException(
          mode == WriteMode.CREATE ? "global_variable_exists" : "global_variable_conflict",
          mode == WriteMode.PATCH ? "/patch/data_type" : "/resource/address",
          "unable to apply global variable data type: " + failure.getMessage(),
          failure);
    }
  }

  private void applyName(Address address, String name) {
    Symbol primary = context.currentProgram().getSymbolTable().getPrimarySymbol(address);
    if (primary != null && name.equals(primary.getName())) return;
    if (primary != null
        && !primary.isDynamic()
        && SymbolType.LABEL.equals(primary.getSymbolType())) {
      ScriptSymbolRenamer.rename(context, primary, name);
      return;
    }

    Symbol added;
    try {
      added =
          context
              .currentProgram()
              .getSymbolTable()
              .createLabel(address, name, SourceType.USER_DEFINED);
    } catch (InvalidInputException failure) {
      throw new IllegalArgumentException(
          "unable to apply global variable name: " + failure.getMessage(), failure);
    }
    if (!added.isPrimary()) {
      context.runCommand(
          new SetLabelPrimaryCmd(address, name, added.getParentNamespace()),
          "unable to make global variable name primary");
    }
  }
}
