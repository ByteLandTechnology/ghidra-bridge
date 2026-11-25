package app.byteland.ghidra.adapter.ghidra.datatype;

import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.service.datatype.DataTypeMutationValidationException;
import app.byteland.ghidra.service.datatype.DataTypePatch;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeResource;
import app.byteland.ghidra.service.datatype.FunctionSignature;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeDependencyException;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.util.exception.InvalidInputException;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.function.Function;

final class DataTypeMutations {
  private static final String CALLING_CONVENTION_TARGET = "signature.callingConvention";

  private DataTypeMutations() {}

  static void createDataType(
      DataTypeManager manager,
      String categoryPath,
      DataTypeResource.Kind kind,
      String name,
      DataTypeReference baseType,
      int size,
      FunctionSignature signature,
      Function<DataTypeReference, DataType> resolver) {
    createDataType(
        manager, categoryPath, kind, name, baseType, size, null, null, signature, resolver);
  }

  static void createDataType(
      DataTypeManager manager,
      String categoryPath,
      DataTypeResource.Kind kind,
      String name,
      DataTypeReference baseType,
      int size,
      List<DataTypePatch.CompositeField> fields,
      List<DataTypePatch.EnumValue> values,
      FunctionSignature signature,
      Function<DataTypeReference, DataType> resolver) {
    String normalizedCategoryPath =
        categoryPath == null || categoryPath.isBlank() ? "/" : categoryPath;
    CategoryPath path = new CategoryPath(normalizedCategoryPath);
    String exactPath = path.getPath(name);
    DataType existing = GhidraDataTypeReferences.findByPath(manager, exactPath);
    if (existing != null) {
      requireMatchingKind(existing, kind, exactPath);
    }
    switch (kind) {
      case STRUCT -> upsertStruct(manager, path, name, exactPath, existing, size, fields, resolver);
      case UNION -> upsertUnion(manager, path, name, exactPath, existing, fields, resolver);
      case ENUM -> upsertEnum(manager, path, name, exactPath, existing, size, values);
      case TYPEDEF -> upsertTypedef(manager, path, name, exactPath, existing, baseType, resolver);
      case FUNCTION -> upsertFunction(manager, path, name, exactPath, existing, signature, resolver);
      default -> throw new IllegalArgumentException("unsupported create kind: " + kind);
    }
  }

  static void replaceTypedef(
      DataTypeManager manager,
      TypeDef existing,
      DataTypeReference baseTypeRef,
      Function<DataTypeReference, DataType> resolver) {
    if (baseTypeRef == null) {
      throw new DataTypeMutationValidationException("patch.baseType", "typedef requires base_type");
    }
    DataType base = resolveReferencedType(resolver, baseTypeRef, "patch.baseType");
    requireAcyclicTypedef(existing, base, "patch.baseType");
    TypedefDataType candidate =
        new TypedefDataType(existing.getCategoryPath(), existing.getName(), base, manager);
    replaceExistingDataType(manager, existing, candidate, "patch.baseType");
  }

  private static void upsertStruct(
      DataTypeManager manager,
      CategoryPath path,
      String name,
      String exactPath,
      DataType existing,
      int size,
      List<DataTypePatch.CompositeField> fields,
      Function<DataTypeReference, DataType> resolver) {
    if (size < 0) {
      throw new DataTypeMutationValidationException("resource.size", "size must be non-negative");
    }
    DataType target = existing;
    boolean createdShell = false;
    if (target == null && fields != null && !fields.isEmpty()) {
      target = addNewDataType(manager, new StructureDataType(path, name, 0, manager), exactPath);
      createdShell = true;
    }
    try {
      StructureDataType candidate = new StructureDataType(path, name, 0, manager);
      boolean hasExplicitOffsets =
          fields != null && fields.stream().anyMatch(field -> field.offset() != null);
      if (target instanceof Structure existingStruct
          && existingStruct.isPackingEnabled()
          && size <= 0
          && !hasExplicitOffsets) {
        copyCompositePackingAndAlignment(existingStruct, candidate);
      }
      populateStructFields(candidate, fields, target, resolver);
      DataTypeMutationSupport.growToFit(candidate, size);
      if (target != null) {
        replaceExistingDataType(manager, target, candidate, "resource");
      } else {
        addNewDataType(manager, candidate, exactPath);
      }
    } catch (RuntimeException error) {
      if (createdShell) {
        manager.remove(target);
      }
      throw error;
    }
  }

  private static void populateStructFields(
      StructureDataType candidate,
      List<DataTypePatch.CompositeField> fields,
      DataType targetForCycles,
      Function<DataTypeReference, DataType> resolver) {
    if (fields == null) return;
    for (int index = 0; index < fields.size(); index++) {
      DataTypePatch.CompositeField field = fields.get(index);
      String fieldTarget = "resource.fields[" + index + "]";
      DataType fieldType =
          resolveCompositeFieldType(resolver, field.dataType(), fieldTarget + ".dataType");
      if (targetForCycles != null && containsByValue(fieldType, targetForCycles)) {
        throw new DataTypeMutationValidationException(
            fieldTarget + ".dataType",
            "recursive struct field cannot embed '" + targetForCycles.getPathName() + "' by value");
      }
      int length = resolveFieldLength(fieldType, field.length(), fieldTarget + ".length");
      String fieldName = DataTypeMutationSupport.normalizedFieldName(field.name());
      String comment = DataTypeMutationSupport.normalizedComment(field.comment());
      try {
        if (field.offset() == null) {
          candidate.add(fieldType, length, fieldName, comment);
        } else {
          int offset = field.offset();
          DataTypeMutationSupport.ensureNoDefinedOverlap(
              candidate, offset, length, null, fieldTarget + ".offset");
          DataTypeMutationSupport.growToFit(candidate, offset + length);
          candidate.replaceAtOffset(offset, fieldType, length, fieldName, comment);
        }
      } catch (DataTypeMutationValidationException error) {
        throw error;
      } catch (IllegalArgumentException error) {
        throw validation(fieldTarget, error);
      }
    }
  }

  private static void upsertUnion(
      DataTypeManager manager,
      CategoryPath path,
      String name,
      String exactPath,
      DataType existing,
      List<DataTypePatch.CompositeField> fields,
      Function<DataTypeReference, DataType> resolver) {
    DataType target = existing;
    boolean createdShell = false;
    if (target == null && fields != null && !fields.isEmpty()) {
      target = addNewDataType(manager, new UnionDataType(path, name, manager), exactPath);
      createdShell = true;
    }
    try {
      UnionDataType candidate = new UnionDataType(path, name, manager);
      if (target instanceof Union existingUnion && existingUnion.isPackingEnabled()) {
        copyCompositePackingAndAlignment(existingUnion, candidate);
      }
      if (fields != null) {
        for (int index = 0; index < fields.size(); index++) {
          DataTypePatch.CompositeField field = fields.get(index);
          String fieldTarget = "resource.fields[" + index + "]";
          if (field.offset() != null) {
            throw new DataTypeMutationValidationException(
                fieldTarget + ".offset", "union fields do not support offset");
          }
          DataType fieldType =
              resolveCompositeFieldType(resolver, field.dataType(), fieldTarget + ".dataType");
          if (target != null && containsByValue(fieldType, target)) {
            throw new DataTypeMutationValidationException(
                fieldTarget + ".dataType",
                "recursive union field cannot embed '" + target.getPathName() + "' by value");
          }
          int length = resolveFieldLength(fieldType, field.length(), fieldTarget + ".length");
          String fieldName = DataTypeMutationSupport.normalizedFieldName(field.name());
          String comment = DataTypeMutationSupport.normalizedComment(field.comment());
          try {
            candidate.add(fieldType, length, fieldName, comment);
          } catch (IllegalArgumentException error) {
            throw validation(fieldTarget, error);
          }
        }
      }
      if (target != null) {
        replaceExistingDataType(manager, target, candidate, "resource");
      } else {
        addNewDataType(manager, candidate, exactPath);
      }
    } catch (RuntimeException error) {
      if (createdShell) {
        manager.remove(target);
      }
      throw error;
    }
  }

  private static void upsertEnum(
      DataTypeManager manager,
      CategoryPath path,
      String name,
      String exactPath,
      DataType existing,
      int size,
      List<DataTypePatch.EnumValue> values) {
    EnumDataType candidate;
    try {
      candidate = new EnumDataType(path, name, size > 0 ? size : 4, manager);
    } catch (IllegalArgumentException error) {
      throw validation("resource.size", error);
    }
    if (values != null) {
      for (int index = 0; index < values.size(); index++) {
        DataTypePatch.EnumValue entry = values.get(index);
        String entryTarget = "resource.values[" + index + "]";
        if (entry.name() == null || entry.name().isBlank()) {
          throw new DataTypeMutationValidationException(
              entryTarget + ".name", "enum value requires a non-blank name");
        }
        if (entry.value() == null) {
          throw new DataTypeMutationValidationException(
              entryTarget + ".value", "enum value requires a numeric value");
        }
        String comment = DataTypeMutationSupport.normalizedComment(entry.comment());
        try {
          if (comment == null) {
            candidate.add(entry.name(), entry.value());
          } else {
            candidate.add(entry.name(), entry.value(), comment);
          }
        } catch (IllegalArgumentException error) {
          throw validation(entryTarget, error);
        }
      }
    }
    if (existing != null) {
      replaceExistingDataType(manager, existing, candidate, "resource");
    } else {
      addNewDataType(manager, candidate, exactPath);
    }
  }

  private static void upsertTypedef(
      DataTypeManager manager,
      CategoryPath path,
      String name,
      String exactPath,
      DataType existing,
      DataTypeReference baseType,
      Function<DataTypeReference, DataType> resolver) {
    if (baseType == null) {
      throw new IllegalArgumentException("typedef requires base_type");
    }
    DataType base = resolveReferencedType(resolver, baseType, "resource.baseType");
    if (existing != null) {
      requireAcyclicTypedef(existing, base, "resource.baseType");
    }
    TypedefDataType candidate = new TypedefDataType(path, name, base, manager);
    if (existing != null) {
      replaceExistingDataType(manager, existing, candidate, "resource.baseType");
    } else {
      addNewDataType(manager, candidate, exactPath);
    }
  }

  private static void upsertFunction(
      DataTypeManager manager,
      CategoryPath path,
      String name,
      String exactPath,
      DataType existing,
      FunctionSignature signature,
      Function<DataTypeReference, DataType> resolver) {
    if (signature == null) throw new IllegalArgumentException("function requires a signature");
    FunctionDefinition prototype = buildFunctionDefinition(path, name, signature, manager, resolver);
    if (existing instanceof FunctionDefinition existingFunction) {
      overwriteFunctionDefinition(existingFunction, prototype);
    } else {
      addNewDataType(manager, prototype, exactPath);
    }
  }

  private static void requireMatchingKind(
      DataType existing, DataTypeResource.Kind expectedKind, String exactPath) {
    DataTypeResource.Kind existingKind = DataTypeDescriptions.classifyKind(existing);
    if (existingKind == expectedKind) return;
    if (expectedKind == DataTypeResource.Kind.FUNCTION) {
      throw new IllegalArgumentException(
          "function data type path collides with a non-function data type: " + exactPath);
    }
    throw new IllegalArgumentException(
        expectedKind.name().toLowerCase(Locale.ROOT)
            + " data type path collides with existing "
            + existingKind.name().toLowerCase(Locale.ROOT)
            + " data type: "
            + exactPath);
  }

  private static DataType addNewDataType(
      DataTypeManager manager, DataType candidate, String exactPath) {
    DataType resolved = manager.addDataType(candidate, DataTypeConflictHandler.DEFAULT_HANDLER);
    if (resolved != null
        && resolved.getPathName() != null
        && !exactPath.equals(resolved.getPathName())) {
      manager.remove(resolved);
      throw new IllegalArgumentException("unable to create data type at exact path: " + exactPath);
    }
    return resolved;
  }

  private static void replaceExistingDataType(
      DataTypeManager manager, DataType existing, DataType candidate, String target) {
    try {
      manager.replaceDataType(existing, candidate, true);
    } catch (DataTypeDependencyException | IllegalArgumentException error) {
      String message = error.getMessage();
      throw new DataTypeMutationValidationException(
          target, message == null || message.isBlank() ? "cyclic data type dependency" : message, error);
    }
  }

  private static void requireAcyclicTypedef(DataType existing, DataType base, String target) {
    if (sameOrEquivalentPath(base, existing)
        || base.dependsOn(existing)
        || containsByValue(base, existing)) {
      throw new DataTypeMutationValidationException(
          target, "cyclic typedef dependency on '" + existing.getPathName() + "'");
    }
  }

  private static boolean containsByValue(DataType candidate, DataType target) {
    return containsByValue(candidate, target, new IdentityHashMap<>());
  }

  private static boolean containsByValue(
      DataType candidate, DataType target, Map<DataType, Boolean> visited) {
    if (candidate == null || target == null || candidate instanceof Pointer) {
      return false;
    }
    if (sameOrEquivalentPath(candidate, target)) {
      return true;
    }
    if (visited.put(candidate, Boolean.TRUE) != null) {
      return false;
    }
    if (candidate instanceof TypeDef typeDef) {
      return containsByValue(typeDef.getDataType(), target, visited);
    }
    if (candidate instanceof Array array) {
      return containsByValue(array.getDataType(), target, visited);
    }
    if (candidate instanceof Composite composite) {
      for (DataTypeComponent component : composite.getDefinedComponents()) {
        if (containsByValue(component.getDataType(), target, visited)) {
          return true;
        }
      }
    }
    return false;
  }

  private static boolean sameOrEquivalentPath(DataType left, DataType right) {
    if (left == right || left.equals(right)) return true;
    return left.getDataTypeManager() != null
        && left.getDataTypeManager() == right.getDataTypeManager()
        && left.getPathName() != null
        && left.getPathName().equals(right.getPathName());
  }

  private static void copyCompositePackingAndAlignment(Composite source, Composite destination) {
    destination.setToDefaultPacking();
    switch (source.getPackingType()) {
      case EXPLICIT -> destination.setExplicitPackingValue(source.getExplicitPackingValue());
      case DEFAULT -> destination.setToDefaultPacking();
      case DISABLED -> destination.setPackingEnabled(false);
    }
    switch (source.getAlignmentType()) {
      case DEFAULT -> destination.setToDefaultAligned();
      case MACHINE -> destination.setToMachineAligned();
      case EXPLICIT -> destination.setExplicitMinimumAlignment(source.getExplicitMinimumAlignment());
    }
  }

  private static DataType resolveReferencedType(
      Function<DataTypeReference, DataType> resolver, DataTypeReference reference, String target) {
    try {
      DataType resolved = resolver.apply(reference);
      if (resolved == null) {
        throw new DataTypeMutationValidationException(target, "unknown data type: " + reference);
      }
      return resolved;
    } catch (DataTypeMutationValidationException error) {
      throw error;
    } catch (IllegalArgumentException | NoSuchElementException error) {
      throw validation(target, error);
    }
  }

  private static DataType resolveCompositeFieldType(
      Function<DataTypeReference, DataType> resolver, DataTypeReference reference, String target) {
    if (reference == null) {
      throw new DataTypeMutationValidationException(target, "field requires data_type");
    }
    DataType resolved = resolveReferencedType(resolver, reference, target);
    if (GhidraDataTypeReferences.isBareFunctionDefinition(resolved)) {
      throw new DataTypeMutationValidationException(
          target, target + " must use kind=pointer for a function definition");
    }
    return resolved;
  }

  private static int resolveFieldLength(DataType fieldType, Integer explicitLength, String target) {
    try {
      return DataTypeMutationSupport.fieldLength(fieldType, explicitLength, null);
    } catch (IllegalArgumentException error) {
      throw validation(target, error);
    }
  }

  private static FunctionDefinition buildFunctionDefinition(
      CategoryPath categoryPath,
      String name,
      FunctionSignature signature,
      DataTypeManager manager,
      Function<DataTypeReference, DataType> resolver) {
    requireKnownCallingConvention(manager, signature.callingConvention());
    DataType returnType =
        resolveFunctionValueType(resolver, signature.returnType(), "signature.returnType");
    ParameterDefinition[] arguments = new ParameterDefinition[signature.parameters().size()];
    for (int index = 0; index < arguments.length; index++) {
      FunctionSignature.Parameter parameter = signature.parameters().get(index);
      String target = "signature.parameters[" + index + "].dataType";
      DataType parameterType = resolveFunctionValueType(resolver, parameter.dataType(), target);
      try {
        arguments[index] = new ParameterDefinitionImpl(parameter.name(), parameterType, null);
      } catch (IllegalArgumentException error) {
        throw validation(target, error);
      }
    }
    FunctionDefinitionDataType prototype =
        new FunctionDefinitionDataType(categoryPath, name, manager);
    try {
      prototype.setReturnType(returnType);
      prototype.setArguments(arguments);
      prototype.setCallingConvention(signature.callingConvention());
    } catch (IllegalArgumentException error) {
      throw validation("signature", error);
    } catch (InvalidInputException error) {
      throw new DataTypeMutationValidationException(
          CALLING_CONVENTION_TARGET, "invalid function callingConvention", error);
    }
    prototype.setVarArgs(signature.hasVarArgs());
    prototype.setNoReturn(signature.hasNoReturn());
    return prototype;
  }

  private static void overwriteFunctionDefinition(
      FunctionDefinition target, FunctionDefinition prototype) {
    target.setReturnType(prototype.getReturnType());
    target.setArguments(prototype.getArguments());
    try {
      target.setCallingConvention(prototype.getCallingConventionName());
    } catch (InvalidInputException error) {
      throw new DataTypeMutationValidationException(
          CALLING_CONVENTION_TARGET, "invalid function callingConvention", error);
    }
    target.setVarArgs(prototype.hasVarArgs());
    target.setNoReturn(prototype.hasNoReturn());
  }

  private static void requireKnownCallingConvention(
      DataTypeManager manager, String callingConvention) {
    if (CompilerSpec.CALLING_CONVENTION_unknown.equalsIgnoreCase(callingConvention)) {
      throw new DataTypeMutationValidationException(
          CALLING_CONVENTION_TARGET, "function callingConvention must not be unknown");
    }
    if (!CompilerSpec.CALLING_CONVENTION_default.equals(callingConvention)
        && !manager.getKnownCallingConventionNames().contains(callingConvention)) {
      throw new DataTypeMutationValidationException(
          CALLING_CONVENTION_TARGET,
          "function callingConvention is not known by the target program: " + callingConvention);
    }
  }

  private static DataType resolveFunctionValueType(
      Function<DataTypeReference, DataType> resolver, DataTypeReference reference, String target) {
    try {
      DataType dataType = resolver.apply(reference);
      if (dataType == null) {
        throw new DataTypeMutationValidationException(target, target + " was not found");
      }
      if (GhidraDataTypeReferences.isBareFunctionDefinition(dataType)) {
        throw new DataTypeMutationValidationException(
            target, target + " must use kind=pointer for a function definition");
      }
      return dataType;
    } catch (DataTypeMutationValidationException error) {
      throw error;
    } catch (IllegalArgumentException | NoSuchElementException error) {
      throw validation(target, error);
    }
  }

  private static DataTypeMutationValidationException validation(
      String target, RuntimeException error) {
    String message = error.getMessage();
    return new DataTypeMutationValidationException(
        target, message == null || message.isBlank() ? "invalid data type" : message, error);
  }
}
