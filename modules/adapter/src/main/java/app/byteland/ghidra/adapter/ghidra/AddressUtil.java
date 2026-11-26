package app.byteland.ghidra.adapter.ghidra;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.util.AddressEvaluator;
import java.util.Locale;

/**
 * Utility methods that parse and format Ghidra addresses.
 */
public final class AddressUtil {
  private AddressUtil() {}

  public static Address parseAddress(Program program, String rawAddress) {
    if (program == null) {
      throw new IllegalArgumentException("program is required");
    }
    if (rawAddress == null || rawAddress.isBlank()) {
      throw new IllegalArgumentException("address is required");
    }
    String value = rawAddress.trim();
    Address address = AddressEvaluator.evaluate(program, value);
    if (address == null) {
      address = AddressEvaluator.evaluate(program, "0x" + value);
    }
    if (address == null) {
      address = tryAddressWithDefaultSpace(program.getAddressFactory(), value);
    }
    if (address == null) {
      throw new IllegalArgumentException("unable to parse address: " + rawAddress);
    }
    return address;
  }

  public static Address parseAddress(GhidraScript script, String rawAddress) {
    if (script == null) {
      throw new IllegalArgumentException("script is required");
    }
    Program program = script.getCurrentProgram();
    if (program != null) {
      return parseAddress(program, rawAddress);
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
    String fast = formatGenericAddress(address);
    if (fast != null) {
      return fast;
    }
    String space = address.getAddressSpace().getName();
    return canonicalAddress(space, address.toString());
  }

  public static String canonicalAddress(String addressSpace, String offsetHex) {
    return addressSpace + ":" + normalizeOffset(offsetHex);
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

  private static final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();

  private static String formatGenericAddress(Address address) {
    if (address.getClass() != ghidra.program.model.address.GenericAddress.class) {
      return null;
    }
    AddressSpace space = address.getAddressSpace();
    if (space == null
        || space.isStackSpace()
        || space.showSpaceName()
        || space.getAddressableUnitSize() != 1) {
      return null;
    }
    int spaceBits = space.getSize();
    if (spaceBits <= 0) {
      return null;
    }
    int minDigits = Math.min(8, ((spaceBits - 1) / 4) + 1);
    long offset = address.getOffset();
    int rawDigits = offset == 0L ? 1 : ((67 - Long.numberOfLeadingZeros(offset)) >>> 2);
    int digits = Math.max(minDigits, rawDigits);
    String spaceName = space.getName();
    int prefixLen = spaceName.length();
    char[] chars = new char[prefixLen + 1 + digits];
    spaceName.getChars(0, prefixLen, chars, 0);
    chars[prefixLen] = ':';
    long value = offset;
    for (int idx = chars.length - 1; idx > prefixLen; idx--) {
      chars[idx] = HEX_DIGITS[(int) (value & 0xFL)];
      value >>>= 4;
    }
    return new String(chars);
  }
}
