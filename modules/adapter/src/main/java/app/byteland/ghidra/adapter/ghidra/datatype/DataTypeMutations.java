package app.byteland.ghidra.adapter.ghidra.datatype;

import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.service.datatype.DataTypeMutationValidationException;
import app.byteland.ghidra.service.datatype.DataTypePatch;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeResource;
import app.byteland.ghidra.service.datatype.FunctionSignature;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeDependencyException;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.util.exception.InvalidInputException;
import java.util.List;
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
      List<DataTypePatch.CompositeField> fields,
      List<DataTypePatch.EnumValue> values,
      Function<DataTypeReference, DataType> resolver) {
    String normalizedCategoryPath =
        categoryPath == null || categoryPath.isBlank() ? "/" : categoryPath;
    CategoryPath path = new CategoryPath(normalizedCategoryPath);
    DataType candidate;
    switch (kind) {
      case STRUCT -> candidate = new StructureDataType(path, name, Math.max(size, 0), manager);
      case ENUM -> candidate = new EnumDataType(path, name, size > 0 ? size : 4, manager);
      case UNION -> candidate = new UnionDataType(path, name, manager);
      case TYPEDEF -> {
        DataType base = requireTypedefBaseType(baseType, resolver);
        String exactPath = path.getPath(name);
        DataType existing = manager.getDataType(path, name);
        if (existing instanceof TypeDef existingTypedef) {
          replaceTypedef(manager, existingTypedef, base);
        } else if (existing != null) {
          throw new IllegalArgumentException(
              "typedef data type path collides with a non-typedef data type: " + exactPath);
        } else {
          DataType resolved =
              manager.addDataType(
                  new TypedefDataType(path, name, base, manager),
                  DataTypeConflictHandler.DEFAULT_HANDLER);
          if (!exactPath.equals(resolved.getPathName())) {
            throw new IllegalArgumentException(
                "unable to create typedef data type at exact path: " + exactPath);
          }
        }
        return;
      }
      case FUNCTION -> {
        if (signature == null) throw new IllegalArgumentException("function requires a signature");
        FunctionDefinition prototype =
            buildFunctionDefinition(path, name, signature, manager, resolver);
        String exactPath = path.getPath(name);
        DataType existing = manager.getDataType(path, name);
        if (existing instanceof FunctionDefinition existingFunction) {
          overwriteFunctionDefinition(existingFunction, prototype);
        } else if (existing != null) {
          throw new IllegalArgumentException(
              "function data type path collides with a non-function data type: " + exactPath);
        } else {
          DataType resolved =
              manager.addDataType(prototype, DataTypeConflictHandler.DEFAULT_HANDLER);
          if (!exactPath.equals(resolved.getPathName())) {
            throw new IllegalArgumentException(
                "unable to create function data type at exact path: " + exactPath);
          }
        }
        return;
      }
      default -> throw new IllegalArgumentException("unsupported create kind: " + kind);
    }
    DataType resolved = manager.addDataType(candidate, DataTypeConflictHandler.DEFAULT_HANDLER);
    try {
      applyInitialMembers(resolved, fields, values, resolver);
    } catch (RuntimeException error) {
      manager.remove(resolved);
      throw error;
    }
  }

  static void replaceTypedef(
      DataTypeManager manager,
      TypeDef existingTypedef,
      DataTypeReference baseType,
      Function<DataTypeReference, DataType> resolver) {
    replaceTypedef(manager, existingTypedef, requireTypedefBaseType(baseType, resolver));
  }

  private static DataType requireTypedefBaseType(
      DataTypeReference baseType, Function<DataTypeReference, DataType> resolver) {
    if (baseType == null) throw new IllegalArgumentException("typedef requires base_type");
    DataType base = resolver.apply(baseType);
    if (base == null) throw new NoSuchElementException("base type not found: " + baseType);
    return base;
  }

  private static void replaceTypedef(
      DataTypeManager manager, TypeDef existingTypedef, DataType base) {
    TypedefDataType replacement =
        new TypedefDataType(
            existingTypedef.getCategoryPath(), existingTypedef.getName(), base, manager);
    if (replacement.dependsOn(existingTypedef)) {
      throw new IllegalArgumentException(
          "cyclic typedef dependency: " + existingTypedef.getPathName());
    }
    try {
      manager.replaceDataType(existingTypedef, replacement, true);
    } catch (DataTypeDependencyException error) {
      String message = error.getMessage();
      throw new IllegalArgumentException(
          message == null || message.isBlank()
              ? "cyclic typedef dependency: " + existingTypedef.getPathName()
              : message,
          error);
    }
  }

  private static void applyInitialMembers(
      DataType created,
      List<DataTypePatch.CompositeField> fields,
      List<DataTypePatch.EnumValue> values,
      Function<DataTypeReference, DataType> resolver) {
    if (fields != null && !fields.isEmpty()) {
      if (created instanceof Structure structure) {
        StructMutations.edit(
            structure, new DataTypePatch.Struct(fields, null, null, null), resolver);
      } else if (created instanceof Union union) {
        UnionMutations.edit(union, new DataTypePatch.Union(fields, null, null, null), resolver);
      } else {
        throw new IllegalArgumentException("fields are only supported for struct or union");
      }
    }
    if (values != null && !values.isEmpty()) {
      if (created instanceof ghidra.program.model.data.Enum enumType) {
        EnumMutations.edit(enumType, new DataTypePatch.EnumPatch(values, null, null, null));
      } else {
        throw new IllegalArgumentException("values are only supported for enum");
      }
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
