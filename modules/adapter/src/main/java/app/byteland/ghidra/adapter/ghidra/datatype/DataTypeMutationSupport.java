package app.byteland.ghidra.adapter.ghidra.datatype;

import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.service.datatype.DataTypeMutationValidationException;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.util.exception.DuplicateNameException;
import java.util.NoSuchElementException;
import java.util.function.Function;

final class DataTypeMutationSupport {
  private DataTypeMutationSupport() {}

  static DataType resolveFieldDataType(
      DataTypeReference reference,
      Function<DataTypeReference, DataType> resolver,
      String target) {
    DataTypeReference selected = reference == null ? DataTypeReference.named("byte") : reference;
    return requireDataType(resolver, selected, target);
  }

  static DataType requireDataType(
      Function<DataTypeReference, DataType> resolver,
      DataTypeReference reference,
      String target) {
    try {
      DataType dataType = resolver.apply(reference);
      if (dataType == null) {
        throw new DataTypeMutationValidationException(target, "unknown data type: " + reference);
      }
      requireCompositeValueType(dataType, target);
      return dataType;
    } catch (DataTypeMutationValidationException error) {
      throw error;
    } catch (IllegalArgumentException | NoSuchElementException error) {
      throw new DataTypeMutationValidationException(
          target,
          error.getMessage() == null || error.getMessage().isBlank()
              ? "invalid data type"
              : error.getMessage(),
          error);
    }
  }

  static int fieldLength(
      DataType dataType, Integer explicitLength, Integer fallback, String itemTarget) {
    requireCompositeValueType(dataType, itemTarget + "/data_type");
    if (explicitLength != null) {
      if (dataType instanceof Array) {
        throw new DataTypeMutationValidationException(
            itemTarget + "/length", "array data_type and length are mutually exclusive");
      }
      if (explicitLength <= 0) {
        throw new DataTypeMutationValidationException(
            itemTarget + "/length", "length must be positive");
      }
      return explicitLength;
    }
    if (fallback != null && fallback > 0) return fallback;
    return dataType.getLength() > 0 ? dataType.getLength() : 1;
  }

  private static void requireCompositeValueType(DataType dataType, String target) {
    if (GhidraDataTypeReferences.isBareFunctionDefinition(dataType)) {
      throw new DataTypeMutationValidationException(
          target, target + " must use kind=pointer for a function definition");
    }
  }

  static void applyMetadataPatch(
      DataTypeComponent component, String newName, String newComment, String newNameTarget) {
    if (newName != null && !newName.equals(component.getFieldName())) {
      try {
        component.setFieldName(newName);
      } catch (Exception exception) {
        if (exception instanceof DuplicateNameException) {
          throw new DataTypeMutationValidationException(
              newNameTarget, "duplicate field name: " + newName, exception);
        }
        if (exception instanceof RuntimeException runtime) throw runtime;
        throw new IllegalStateException("cannot rename data type field", exception);
      }
    }
    if (!String.valueOf(component.getComment()).equals(String.valueOf(newComment))) {
      component.setComment(newComment);
    }
  }
}
