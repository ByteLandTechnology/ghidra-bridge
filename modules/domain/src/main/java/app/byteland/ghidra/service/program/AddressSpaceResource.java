package app.byteland.ghidra.service.program;

public record AddressSpaceResource(
    String name, Kind kind, int size, String minAddress, String maxAddress, boolean isDefault) {
  public enum Kind {
    RAM,
    NON_LOADED,
    REGISTER,
    STACK,
    EXTERNAL,
    CONSTANT,
    UNIQUE,
    OTHER
  }
}
