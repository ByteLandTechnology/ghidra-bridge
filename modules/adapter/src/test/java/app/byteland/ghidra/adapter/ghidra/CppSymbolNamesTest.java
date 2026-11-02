package app.byteland.ghidra.adapter.ghidra;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class CppSymbolNamesTest {
  @Test
  void detectsItaniumAndMicrosoftNames() {
    assertTrue(CppSymbolNames.isMangled("_ZN3foo3barEv"));
    assertTrue(CppSymbolNames.isMangled("__ZN3foo3barEv"));
    assertTrue(CppSymbolNames.isMangled("?bar@foo@@QEAAXXZ"));
    assertFalse(CppSymbolNames.isMangled("main"));
    assertFalse(CppSymbolNames.isMangled("FUN_00101000"));
    assertFalse(CppSymbolNames.isMangled(null));
  }

  @Test
  void skipsTheDemanglerForPlainNames() {
    assertNull(CppSymbolNames.demangled(null, "main", null));
  }
}
