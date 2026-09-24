package app.byteland.ghidra.adapter.ghidra;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.address.AddressSpace;
import java.util.Locale;

/**
 * Utility methods for parsing and formatting Ghidra addresses.
 */
public final class AddressUtil {
  private AddressUtil() {}

  public static Address parseAddress(GhidraScript script, String rawAddress) {
    if (script == null) {
      throw new IllegalArgumentException("script is required");
    }
    if (rawAddress == null || rawAddress.isBlank()) {
      throw new IllegalArgumentException("address is required");
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
      throw new IllegalArgumentException("unable to parse address: " + rawAddress);
    }
    return address;
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
