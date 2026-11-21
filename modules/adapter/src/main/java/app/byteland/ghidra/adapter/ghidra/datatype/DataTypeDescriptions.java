package app.byteland.ghidra.adapter.ghidra.datatype;

import app.byteland.ghidra.adapter.ghidra.FieldProjections;
import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeResource;
import app.byteland.ghidra.service.datatype.FunctionSignature;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.BuiltInDataType;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Set;

final class DataTypeDescriptions {
  private DataTypeDescriptions() {}

  static DataTypeResource summarize(DataType dataType) {
    return describe(dataType, false, null);
  }

  static DataTypeResource summarize(DataType dataType, Set<String> selectedFields) {
    return describe(dataType, false, selectedFields);
  }

  static DataTypeResource detail(DataType dataType) {
    return describe(dataType, true, null);
  }

  static DataTypeResource detail(DataType dataType, Set<String> selectedFields) {
    return describe(dataType, true, selectedFields);
  }

  private static DataTypeResource describe(
      DataType dataType, boolean detail, Set<String> selectedFields) {
    boolean needPath = FieldProjections.allows(selectedFields, "path");
    boolean needName = FieldProjections.allows(selectedFields, "name");
    boolean needCategory = FieldProjections.allows(selectedFields, "category_path");
    String path = needPath || needCategory ? dataType.getPathName() : null;
    String name = needName || needCategory ? dataType.getName() : null;
    Integer size = null;
    List<DataTypeResource.Field> fields = null;
    List<DataTypeResource.EnumValue> values = null;
    FunctionSignature signature = null;
    DataTypeReference baseType = null;
    if (detail && dataType instanceof Structure structure) {
      if (FieldProjections.allows(selectedFields, "size")) {
        size = knownLength(structure.getLength());
      }
      if (FieldProjections.allows(selectedFields, "fields")) {
        fields = compositeFields(structure);
      }
    } else if (detail && dataType instanceof Union union) {
      if (FieldProjections.allows(selectedFields, "size")) {
        size = knownLength(union.getLength());
      }
      if (FieldProjections.allows(selectedFields, "fields")) {
        fields = compositeFields(union);
      }
    } else if (detail && dataType instanceof ghidra.program.model.data.Enum enumType) {
      if (FieldProjections.allows(selectedFields, "size")) {
        size = knownLength(enumType.getLength());
      }
      if (FieldProjections.allows(selectedFields, "values")) {
        values = enumValues(enumType);
      }
    } else if (detail
        && dataType instanceof FunctionDefinition function
        && FieldProjections.allows(selectedFields, "signature")) {
      signature = functionSignature(function, selectedFields);
    } else if (detail
        && dataType instanceof TypeDef typeDef
        && FieldProjections.allows(selectedFields, "base_type")) {
      baseType = GhidraDataTypeReferences.toReference(typeDef.getBaseDataType());
    }
    String description = null;
    if (FieldProjections.allows(selectedFields, "description")) {
      String rawDescription = dataType.getDescription();
      description = rawDescription == null ? "" : rawDescription;
    }
    return new DataTypeResource(
        needPath ? path : null,
        needName ? name : null,
        needCategory ? categoryFromPath(path, name) : null,
        FieldProjections.allows(selectedFields, "kind") ? classifyKind(dataType) : null,
        FieldProjections.allows(selectedFields, "length")
            ? knownLength(dataType.getLength())
            : null,
        description,
        size,
        fields,
        values,
        signature,
        baseType);
  }

  private static Integer knownLength(int length) {
    return length < 0 ? null : length;
  }

  private static FunctionSignature functionSignature(
      FunctionDefinition function, Set<String> selectedFields) {
    DataTypeReference returnType;
    if (FieldProjections.allowsSubfield(selectedFields, "signature", "return_type")) {
      DataType rawReturnType = function.getReturnType();
      if (rawReturnType == null) {
        throw new IllegalArgumentException(
            "function definition has no return type: " + function.getPathName());
      }
      returnType = GhidraDataTypeReferences.toReference(rawReturnType);
    } else {
      returnType = DataTypeReference.named("void");
    }
    List<FunctionSignature.Parameter> parameters = new ArrayList<>();
    if (FieldProjections.allowsSubfield(selectedFields, "signature", "parameters")) {
      for (ParameterDefinition parameter : function.getArguments()) {
        if (parameter.getDataType() == null) {
          throw new IllegalArgumentException(
              "function definition parameter has no data type: " + function.getPathName());
        }
        parameters.add(
            new FunctionSignature.Parameter(
                normalizedOptional(parameter.getName()),
                GhidraDataTypeReferences.toReference(parameter.getDataType())));
      }
    }
    String callingConvention = "default";
    if (FieldProjections.allowsSubfield(selectedFields, "signature", "calling_convention")) {
      String rawConvention = normalizedOptional(function.getCallingConventionName());
      if (rawConvention != null && !"unknown".equalsIgnoreCase(rawConvention)) {
        callingConvention = rawConvention;
      }
    }
    return new FunctionSignature(
        returnType,
        parameters,
        callingConvention,
        FieldProjections.allowsSubfield(selectedFields, "signature", "has_var_args")
            && function.hasVarArgs(),
        FieldProjections.allowsSubfield(selectedFields, "signature", "has_no_return")
            && function.hasNoReturn());
  }

  private static List<DataTypeResource.Field> compositeFields(Composite composite) {
    List<DataTypeResource.Field> fields = new ArrayList<>();
    for (int index = 0; index < composite.getNumComponents(); index++) {
      DataTypeComponent component = composite.getComponent(index);
      DataType componentType = component.getDataType();
      fields.add(
          new DataTypeResource.Field(
              component.getOrdinal(),
              component.getFieldName() == null ? "" : component.getFieldName(),
              component.getOffset(),
              component.getEndOffset(),
              classifyKind(componentType),
              component.getLength(),
              component.getComment(),
              component.isUndefined(),
              GhidraDataTypeReferences.toReference(componentType)));
    }
    return List.copyOf(fields);
  }

  private static List<DataTypeResource.EnumValue> enumValues(
      ghidra.program.model.data.Enum enumType) {
    List<DataTypeResource.EnumValue> values = new ArrayList<>();
    for (String name : enumType.getNames()) {
      values.add(
          new DataTypeResource.EnumValue(name, enumType.getValue(name), enumType.getComment(name)));
    }
    values.sort(Comparator.comparingLong(DataTypeResource.EnumValue::value));
    return List.copyOf(values);
  }

  static DataTypeResource.Kind classifyKind(DataType dataType) {
    if (dataType instanceof Structure) return DataTypeResource.Kind.STRUCT;
    if (dataType instanceof ghidra.program.model.data.Enum) return DataTypeResource.Kind.ENUM;
    if (dataType instanceof TypeDef) return DataTypeResource.Kind.TYPEDEF;
    if (dataType instanceof Union) return DataTypeResource.Kind.UNION;
    if (dataType instanceof Pointer) return DataTypeResource.Kind.POINTER;
    if (dataType instanceof Array) return DataTypeResource.Kind.ARRAY;
    if (dataType instanceof FunctionDefinition) return DataTypeResource.Kind.FUNCTION;
    if (dataType instanceof BuiltInDataType) return DataTypeResource.Kind.BUILTIN;
    return DataTypeResource.Kind.OTHER;
  }

  static String categoryFromPath(String path, String name) {
    if (path == null || path.isBlank() || name == null || name.isBlank()) return "/";
    String suffix = "/" + name;
    if (path.endsWith(suffix)) {
      String category = path.substring(0, path.length() - suffix.length());
      return category.isBlank() ? "/" : category;
    }
    int separator = path.lastIndexOf('/');
    return separator <= 0 ? "/" : path.substring(0, separator);
  }

  private static String normalizedOptional(String value) {
    if (value == null) return null;
    String normalized = value.trim();
    return normalized.isEmpty() ? null : normalized;
  }
}
