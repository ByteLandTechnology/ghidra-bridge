package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.service.function.VariableStorageReference;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.listing.VariableUtilities;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.InvalidInputException;
import java.util.List;
import java.util.Objects;

final class FunctionStorageSupport {
  private FunctionStorageSupport() {}

  static ParsedStorage parseExplicit(
      Program program, VariableStorageReference input, String field) {
    if (input == null) {
      return null;
    }
    try {
      VariableStorage storage =
          switch (input) {
            case VariableStorageReference.Serialization serialization ->
                VariableStorage.deserialize(program, serialization.serialization());
            case VariableStorageReference.Register namedRegister -> {
              Register register = program.getLanguage().getRegister(namedRegister.register());
              if (register == null) {
                throw new IllegalArgumentException(
                    field + ".register names an unknown register: " + namedRegister.register());
              }
              if (register.isProcessorContext()) {
                throw new IllegalArgumentException(
                    field + ".register must not identify a processor context register");
              }
              yield new VariableStorage(program, register);
            }
          };
      requireRealStorage(storage, field);
      return new ParsedStorage(storage, storage.getSerializationString());
    } catch (InvalidInputException ex) {
      throw new IllegalArgumentException(field + " is invalid: " + failureDetail(ex), ex);
    }
  }

  static void requireCompatible(DataType dataType, VariableStorage storage, String field) {
    if (isVoid(dataType)) {
      throw new IllegalArgumentException(field + " cannot be assigned to a void data type");
    }
    requireRealStorage(storage, field);
    int dataTypeSize = dataType.getLength();
    if (dataTypeSize <= 0) {
      throw new IllegalArgumentException(
          field + " cannot be used with unsized data type " + dataType.getName());
    }
    boolean incompatibleSize = storage.size() != dataTypeSize && !isFloat(dataType);
    if (incompatibleSize) {
      throw new IllegalArgumentException(
          field
              + " size "
              + storage.size()
              + " does not match data type "
              + dataType.getName()
              + " size "
              + dataTypeSize);
    }
  }

  static void requireValidCustomSignature(Function function) {
    if (!function.hasCustomVariableStorage()) {
      throw new IllegalArgumentException("explicit storage requires custom variable storage");
    }
    Parameter returnParameter = function.getReturn();
    if (!isVoid(returnParameter.getDataType())) {
      if (!isFloat(returnParameter.getDataType()) && !returnParameter.isValid()) {
        throw new IllegalArgumentException("custom return parameter is invalid");
      }
      requireCompatible(
          returnParameter.getDataType(), returnParameter.getVariableStorage(), "return storage");
    }
    for (Parameter parameter : function.getParameters()) {
      if (!isFloat(parameter.getDataType()) && !parameter.isValid()) {
        throw new IllegalArgumentException(
            "custom parameter " + parameter.getOrdinal() + " is invalid");
      }
      requireCompatible(
          parameter.getDataType(),
          parameter.getVariableStorage(),
          "parameter " + parameter.getOrdinal() + " storage");
    }
  }

  static void requireSignatureApplied(
      Function function, Variable expectedReturn, List<? extends Variable> expectedParameters) {
    Parameter actualReturn = function.getReturn();
    requireVariableApplied("return", expectedReturn, actualReturn);
    Parameter[] actualParameters = function.getParameters();
    if (actualParameters.length != expectedParameters.size()) {
      throw new IllegalArgumentException(
          "custom signature parameter count changed; expected "
              + expectedParameters.size()
              + " but actual count is "
              + actualParameters.length);
    }
    for (int index = 0; index < actualParameters.length; index++) {
      Parameter actual = actualParameters[index];
      if (actual.getOrdinal() != index) {
        throw new IllegalArgumentException(
            "custom parameter ordinal changed at index "
                + index
                + "; actual ordinal is "
                + actual.getOrdinal());
      }
      Variable expected = expectedParameters.get(index);
      requireVariableApplied("parameter " + index, expected, actual);
      if (!Objects.equals(expected.getName(), actual.getName())
          && !SymbolUtilities.isDefaultParameterName(expected.getName())
          && !SymbolUtilities.isDefaultParameterName(actual.getName())) {
        throw new IllegalArgumentException(
            "custom parameter "
                + index
                + " name changed; expected "
                + expected.getName()
                + " but actual name is "
                + actual.getName());
      }
      if (!Objects.equals(expected.getComment(), actual.getComment())) {
        throw new IllegalArgumentException(
            "custom parameter " + index + " comment changed unexpectedly");
      }
    }
  }

  private static void requireVariableApplied(String field, Variable expected, Variable actual) {
    DataType expectedDataType = expected.getDataType();
    DataType actualDataType = actual.getDataType();
    boolean exactParameterIdentityRequired =
        expected instanceof Parameter expectedParameter
            && expectedParameter.getOrdinal() >= 0
            && actual instanceof Parameter actualParameter
            && actualParameter.getOrdinal() >= 0;
    if (exactParameterIdentityRequired) {
      expectedDataType = signatureDataType(expected);
      actualDataType = signatureDataType(actual);
    }
    boolean sameDataType =
        exactParameterIdentityRequired
            ? GhidraDataTypeReferences.toReference(expectedDataType)
                .equals(GhidraDataTypeReferences.toReference(actualDataType))
            : expectedDataType.isEquivalent(actualDataType);
    if (!sameDataType) {
      throw new IllegalArgumentException(
          field
              + " data type changed; expected "
              + expectedDataType.getPathName()
              + " but actual type is "
              + actualDataType.getPathName());
    }
    String expectedStorage = expected.getVariableStorage().getSerializationString();
    String actualStorage = actual.getVariableStorage().getSerializationString();
    if (!expectedStorage.equals(actualStorage)) {
      throw new IllegalArgumentException(
          field
              + " storage changed; expected "
              + expectedStorage
              + " but actual storage is "
              + actualStorage);
    }
  }

  private static DataType signatureDataType(Variable variable) {
    if (variable instanceof Parameter parameter) {
      return parameter.getFormalDataType();
    }
    return variable.getDataType();
  }

  static ReturnParameterImpl createReturn(
      Program program, DataType dataType, VariableStorage storage) {
    if (isVoid(dataType)) {
      try {
        return new ReturnParameterImpl(dataType, VariableStorage.VOID_STORAGE, program);
      } catch (InvalidInputException ex) {
        throw constructionFailure("return parameter", ex);
      }
    }
    VariableStorage resolvedStorage = plainStorage(program, storage, "return storage");
    requireCompatible(dataType, resolvedStorage, "return storage");
    try {
      return new ReturnParameterImpl(dataType, resolvedStorage, false, program);
    } catch (InvalidInputException ex) {
      throw constructionFailure("return parameter", ex);
    }
  }

  static VariableStorage resizeStorage(
      Function function, DataType dataType, VariableStorage storage, String field) {
    VariableStorage resized;
    try {
      resized = VariableUtilities.resizeStorage(storage, dataType, true, function);
    } catch (InvalidInputException ex) {
      throw new IllegalArgumentException(
          "unable to resize " + field + " for " + dataType.getName() + ": " + failureDetail(ex),
          ex);
    }
    requireCompatible(dataType, resized, field);
    return resized;
  }

  static ReturnParameterImpl createDynamicReturn(Program program, DataType dataType) {
    try {
      return new ReturnParameterImpl(dataType, program);
    } catch (InvalidInputException ex) {
      throw constructionFailure("return parameter", ex);
    }
  }

  static ParameterImpl copyParameter(
      Program program,
      Parameter parameter,
      String name,
      DataType dataType,
      VariableStorage storage) {
    SourceType source = parameter.getSource();
    if (source == null) {
      source = SourceType.USER_DEFINED;
    }
    ParameterImpl copy =
        createParameter(
            program, name, parameter.getOrdinal(), dataType, storage, source, "parameter");
    copy.setComment(parameter.getComment());
    return copy;
  }

  static ParameterImpl createParameter(
      Program program,
      String name,
      int ordinal,
      DataType dataType,
      VariableStorage storage,
      SourceType source,
      String field) {
    VariableStorage resolvedStorage = plainStorage(program, storage, field + " storage");
    requireCompatible(dataType, resolvedStorage, field + " storage");
    try {
      return new ParameterImpl(name, ordinal, dataType, resolvedStorage, false, program, source);
    } catch (InvalidInputException ex) {
      throw constructionFailure(field, ex);
    }
  }

  static boolean isVoid(DataType dataType) {
    return baseType(dataType) instanceof VoidDataType;
  }

  private static boolean isFloat(DataType dataType) {
    return dataType instanceof AbstractFloatDataType;
  }

  private static DataType baseType(DataType dataType) {
    DataType baseType = dataType;
    while (baseType instanceof TypeDef typeDef) {
      baseType = typeDef.getBaseDataType();
    }
    return baseType;
  }

  private static void requireRealStorage(VariableStorage storage, String field) {
    if (storage == null
        || !storage.isValid()
        || storage.isBadStorage()
        || storage.isUnassignedStorage()
        || storage.isVoidStorage()) {
      throw new IllegalArgumentException(
          field + " must identify assigned, non-void variable storage");
    }
    if (storage.isAutoStorage() || storage.isForcedIndirect()) {
      throw new IllegalArgumentException(field + " must not use dynamic storage markers");
    }
    Varnode[] varnodes = storage.getVarnodes();
    if (varnodes.length == 0) {
      throw new IllegalArgumentException(field + " must contain at least one varnode");
    }
    for (Varnode varnode : varnodes) {
      Address address = varnode.getAddress();
      if (!address.isRegisterAddress() && !address.isStackAddress() && !address.isMemoryAddress()) {
        throw new IllegalArgumentException(
            field + " uses unsupported address space " + address.getAddressSpace().getName());
      }
    }
  }

  private static VariableStorage plainStorage(
      Program program, VariableStorage storage, String field) {
    try {
      return storage == null ? null : storage.clone(program);
    } catch (InvalidInputException ex) {
      throw new IllegalArgumentException("unable to clone " + field + ": " + failureDetail(ex), ex);
    }
  }

  private static IllegalArgumentException constructionFailure(
      String field, InvalidInputException ex) {
    return new IllegalArgumentException(
        "unable to construct " + field + ": " + failureDetail(ex), ex);
  }

  private static String failureDetail(InvalidInputException ex) {
    String detail = ex.getMessage();
    if (detail == null || detail.isBlank()) {
      detail = ex.getClass().getSimpleName();
    }
    return detail;
  }

  record ParsedStorage(VariableStorage storage, String serialization) {}
}
