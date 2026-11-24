package app.byteland.ghidra.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import app.byteland.ghidra.service.function.FunctionCallResource;
import java.util.List;
import org.junit.jupiter.api.Test;

class PageTest {
  @Test
  void compositePaginationPreservesMultipleCallSitesForOneEntry() {
    List<FunctionCallResource> rows =
        List.of(
            new FunctionCallResource(
                "ram:00401000",
                "callee_a",
                "ram:00402010",
                FunctionCallResource.Direction.CALLEES,
                "Global",
                null),
            new FunctionCallResource(
                "ram:00401000",
                "callee_a",
                "ram:00402024",
                FunctionCallResource.Direction.CALLEES,
                "Global",
                null),
            new FunctionCallResource(
                "ram:00401000_ext",
                "callee_ext",
                "ram:00402004",
                FunctionCallResource.Direction.CALLEES,
                "Global",
                null));

    Page<FunctionCallResource> first =
        Page.paginate(
            rows, 1, null, FunctionCallResource::entry, FunctionCallResource::callSite);
    assertEquals(1, first.items().size());
    assertEquals("ram:00402010", first.items().getFirst().callSite());
    assertNotNull(first.nextCursor());

    Page<FunctionCallResource> second =
        Page.paginate(
            rows,
            1,
            first.nextCursor(),
            FunctionCallResource::entry,
            FunctionCallResource::callSite);
    assertEquals(1, second.items().size());
    assertEquals("ram:00401000", second.items().getFirst().entry());
    assertEquals("ram:00402024", second.items().getFirst().callSite());
    assertNotNull(second.nextCursor());

    Page<FunctionCallResource> third =
        Page.paginate(
            rows,
            1,
            second.nextCursor(),
            FunctionCallResource::entry,
            FunctionCallResource::callSite);
    assertEquals(1, third.items().size());
    assertEquals("ram:00401000_ext", third.items().getFirst().entry());
    assertEquals("ram:00402004", third.items().getFirst().callSite());
    assertNull(third.nextCursor());
  }

  @Test
  void compositeKeyHandlesNullSecondaryAndRejectsInvalidComponents() {
    String nullSecondary = Page.compositeKey("ram:00401000", null);
    String nonNullSecondary = Page.compositeKey("ram:00401000", "ram:00402000");
    assertEquals(true, nullSecondary.compareTo(nonNullSecondary) < 0);

    assertThrows(IllegalArgumentException.class, () -> Page.compositeKey(null, "ram:00402000"));
    assertThrows(
        IllegalArgumentException.class, () -> Page.compositeKey("ram:00401000\n", "ram:00402000"));
    assertThrows(
        IllegalArgumentException.class,
        () -> Page.compositeKey("ram:00401000", "ram:00402000\u0000"));
  }
}
