package app.byteland.ghidra.adapter.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.api.ApiFailures;
import app.byteland.ghidra.service.DomainException;
import app.byteland.ghidra.service.InvalidAddressException;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.DefaultAddressFactory;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Program;
import java.lang.reflect.Proxy;
import java.util.List;
import org.junit.jupiter.api.Test;

class AddressUtilTest {
  static final class StubScript extends GhidraScript {
    StubScript(AddressFactory factory) {
      this.currentProgram = stubProgram(factory);
    }

    @Override
    protected void run() {}
  }

  private static Program stubProgram(AddressFactory factory) {
    return (Program)
        Proxy.newProxyInstance(
            Program.class.getClassLoader(),
            new Class<?>[] {Program.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getAddressFactory" -> factory;
                  case "equals" -> proxy == args[0];
                  case "hashCode" -> System.identityHashCode(proxy);
                  case "toString" -> "StubProgram";
                  default -> stubReturnValue(method.getReturnType());
                });
  }

  private static Object stubReturnValue(Class<?> returnType) {
    if (returnType == List.class) {
      return List.of();
    }
    if (returnType.isInterface()) {
      return Proxy.newProxyInstance(
          returnType.getClassLoader(),
          new Class<?>[] {returnType},
          (proxy, method, args) ->
              switch (method.getName()) {
                case "equals" -> proxy == args[0];
                case "hashCode" -> System.identityHashCode(proxy);
                case "toString" -> "Stub" + returnType.getSimpleName();
                default -> defaultReturnValue(method.getReturnType());
              });
    }
    return defaultReturnValue(returnType);
  }

  private static Object defaultReturnValue(Class<?> returnType) {
    if (returnType == List.class) {
      return List.of();
    }
    if (!returnType.isPrimitive()) {
      return null;
    }
    if (returnType == boolean.class) {
      return false;
    }
    if (returnType == byte.class) {
      return (byte) 0;
    }
    if (returnType == short.class) {
      return (short) 0;
    }
    if (returnType == int.class) {
      return 0;
    }
    if (returnType == long.class) {
      return 0L;
    }
    if (returnType == float.class) {
      return 0.0f;
    }
    if (returnType == double.class) {
      return 0.0d;
    }
    if (returnType == char.class) {
      return '\0';
    }
    return null;
  }

  private static AddressFactory sampleAddressFactory() {
    GenericAddressSpace ram =
        new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);
    GenericAddressSpace overlay =
        new GenericAddressSpace("overlay", 64, AddressSpace.TYPE_RAM, 1);
    GenericAddressSpace data =
        new GenericAddressSpace("data", 64, AddressSpace.TYPE_RAM, 2);
    DefaultAddressFactory factory =
        new DefaultAddressFactory(new AddressSpace[] {ram, overlay, data}, ram);
    ram.setShowSpaceName(false);
    return factory;
  }

  @Test
  void parseAddressPreservesTargetAndSortedAddressSpaces() {
    GhidraSession session = new GhidraSession(new StubScript(sampleAddressFactory()));

    Address parsed = session.parseAddress("0x1000", "/selector/address");
    assertEquals("ram:00001000", AddressUtil.canonicalAddress(parsed));

    InvalidAddressException invalid =
        assertThrows(
            InvalidAddressException.class,
            () -> session.parseAddress("unknown_space:1000", "/selector/address"));
    assertInstanceOf(IllegalArgumentException.class, invalid);
    assertInstanceOf(DomainException.class, invalid);
    assertEquals(400, invalid.status());
    assertEquals("invalid_request", invalid.code());
    assertEquals("/selector/address", invalid.target());
    assertEquals(List.of("data", "overlay", "ram"), invalid.details().get("valid_spaces"));
    assertTrue(invalid.getMessage().contains("[data, overlay, ram]"));

    var normalized = ApiFailures.normalize(invalid);
    assertEquals(400, normalized.status());
    assertEquals("invalid_request", normalized.error().code());
    assertEquals("/selector/address", normalized.error().target());
    assertEquals(
        List.of("data", "overlay", "ram"), normalized.error().details().get("valid_spaces"));
  }

  @Test
  void legacyOverloadAndBlankAddressesIncludeValidSpaces() {
    StubScript script = new StubScript(sampleAddressFactory());

    InvalidAddressException legacy =
        assertThrows(
            InvalidAddressException.class, () -> AddressUtil.parseAddress(script, "0xZZZZ"));
    assertNull(legacy.target());
    assertEquals(List.of("data", "overlay", "ram"), legacy.details().get("valid_spaces"));

    InvalidAddressException blank =
        assertThrows(
            InvalidAddressException.class,
            () -> AddressUtil.parseAddress(script, "   ", "/filter/entry"));
    assertEquals("/filter/entry", blank.target());
    assertEquals(List.of("data", "overlay", "ram"), blank.details().get("valid_spaces"));
    assertTrue(blank.getMessage().contains("address is required"));
  }
}
