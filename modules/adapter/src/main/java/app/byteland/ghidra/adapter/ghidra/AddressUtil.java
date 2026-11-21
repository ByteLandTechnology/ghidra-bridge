package app.byteland.ghidra.adapter.ghidra;

import app.byteland.ghidra.service.InvalidAddressException;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.address.AddressSpace;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Utility methods that parse and format Ghidra addresses.
 */
public final class AddressUtil {
  private AddressUtil() {}

  public static Address parseAddress(GhidraScript script, String rawAddress) {
    return parseAddress(script, rawAddress, null);
  }

  public static Address parseAddress(GhidraScript script, String rawAddress, String target) {
    if (script == null) {
      throw new IllegalArgumentException("script is required");
    }
    if (rawAddress == null || rawAddress.isBlank()) {
      List<String> spaces = validSpaces(script);
      throw new InvalidAddressException(
          "address is required" + formatSpacesSuffix(spaces), target, spaces, null);
    }
    String value = rawAddress.trim();
    Address address = toAddress(script, value);
    if (address == null) {
      address = toAddress(script, "0x" + value);
    }
    if (address == null) {
      address = tryAddressWithDefaultSpace(script.getAddressFactory(), value);
    }
    if (address == null) {
      List<String> spaces = validSpaces(script);
      throw new InvalidAddressException(
          "unable to parse address: " + rawAddress + formatSpacesSuffix(spaces),
          target,
          spaces,
          rawAddress);
    }
    return address;
  }

  private static List<String> validSpaces(GhidraScript script) {
    AddressFactory addressFactory = script.getAddressFactory();
    if (addressFactory == null) {
      return List.of();
    }
    AddressSpace[] spaces = addressFactory.getAddressSpaces();
    if (spaces == null || spaces.length == 0) {
      return List.of();
    }
    return Arrays.stream(spaces)
        .filter(Objects::nonNull)
        .map(AddressSpace::getName)
        .filter(Objects::nonNull)
        .distinct()
        .sorted()
        .toList();
  }

  private static String formatSpacesSuffix(List<String> spaces) {
    return spaces.isEmpty() ? "" : " (valid spaces: [" + String.join(", ", spaces) + "])";
  }

  public static String canonicalAddress(Address address) {
    if (address == null) {
      return null;
    }
    String space = address.getAddressSpace().getName();
    return canonicalAddress(space, address.toString());
  }

  public static String canonicalAddress(String addressSpace, String offsetHex) {
    return addressSpace + ":" + normalizeOffset(offsetHex);
  }

  public static String addressSpace(Address address) {
    if (address == null) {
      return null;
    }
    return address.getAddressSpace().getName();
  }

  public static String offset(Address address) {
    if (address == null) {
      return null;
    }
    return "0x" + address.toString();
  }

  private static String normalizeOffset(String offset) {
    if (offset == null) {
      return null;
    }
    String value = offset.trim();
    if (value.startsWith("0x") || value.startsWith("0X")) {
      value = value.substring(2);
    }
    return value.toLowerCase(Locale.ROOT);
  }

  private static Address tryAddressWithDefaultSpace(AddressFactory addressFactory, String value) {
    if (addressFactory == null) {
      return null;
    }
    AddressSpace addressSpace = addressFactory.getDefaultAddressSpace();
    if (addressSpace == null) {
      return null;
    }
    int idx = value.indexOf(':');
    if (idx <= 0) {
      try {
        return addressSpace.getAddress(normalizeOffset(value));
      } catch (AddressFormatException ignored) {
        return null;
      }
    }
    try {
      AddressSpace namedSpace = addressFactory.getAddressSpace(value.substring(0, idx));
      return namedSpace == null
          ? null
          : namedSpace.getAddress(normalizeOffset(value.substring(idx + 1)));
    } catch (AddressFormatException ignored) {
      return null;
    }
  }

  private static Address toAddress(GhidraScript script, String value) {
    return script.toAddr(value);
  }
}
