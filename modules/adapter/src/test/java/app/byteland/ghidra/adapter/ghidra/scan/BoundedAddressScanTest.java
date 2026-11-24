package app.byteland.ghidra.adapter.ghidra.scan;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.ScanProgress;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class BoundedAddressScanTest {

  @Test
  void anchorsStartAndCompletedEndWithoutAlteringItemsOrCursors() {
    AtomicLong clock = new AtomicLong(0L);
    BoundedAddressScan<String> scan =
        new BoundedAddressScan<>(10, 100, "ram:00001000", "ram:00001fff", clock::get);

    scan.anchorStart("ram:00001000");
    clock.set(5_000_000L);
    scan.visit("ram:00001100", "ram:00001100", "inst_1");
    scan.anchorCompletedEnd("ram:00001fff");

    Page<String> page = scan.finish();
    assertEquals(List.of("inst_1"), page.items());
    assertNull(page.nextCursor());
    assertEquals("ram:00001000", page.scanProgress().scannedStart());
    assertEquals("ram:00001fff", page.scanProgress().scannedEnd());
    assertTrue(page.scanProgress().complete());
    assertEquals(ScanProgress.StopReason.COMPLETED, page.scanProgress().stopReason());
    assertEquals(5L, page.scanProgress().elapsedMs());
  }

  @Test
  void preservesStoppedCursorAndRejectsCompletedEndAnchorAfterLimitOrTimeout() {
    AtomicLong clock = new AtomicLong(0L);
    BoundedAddressScan<String> timeoutScan =
        new BoundedAddressScan<>(10, 100, "ram:00001000", "ram:00001fff", clock::get);

    timeoutScan.anchorStart("ram:00001000");
    clock.set(100_000_000L);
    timeoutScan.visit("ram:00001080", "ram:00001080", "inst_1");
    assertTrue(timeoutScan.stopped());
    assertThrows(IllegalStateException.class, () -> timeoutScan.anchorCompletedEnd("ram:00001fff"));

    Page<String> page = timeoutScan.finish();
    assertEquals(List.of("inst_1"), page.items());
    assertEquals("ram:00001080", page.nextCursor());
    assertEquals("ram:00001000", page.scanProgress().scannedStart());
    assertEquals("ram:00001080", page.scanProgress().scannedEnd());
    assertFalse(page.scanProgress().complete());
    assertEquals(ScanProgress.StopReason.TIMEOUT, page.scanProgress().stopReason());
  }
}
