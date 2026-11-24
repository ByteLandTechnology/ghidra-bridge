package app.byteland.ghidra.adapter.ghidra.decompilation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

class GhidraTimeoutTest {
  @Test
  void roundsMillisecondsUpToWholeSeconds() {
    assertEquals(1, GhidraTimeout.secondsForMilliseconds(100));
    assertEquals(1, GhidraTimeout.secondsForMilliseconds(999));
    assertEquals(1, GhidraTimeout.secondsForMilliseconds(1_000));
    assertEquals(2, GhidraTimeout.secondsForMilliseconds(1_001));
    assertEquals(2, GhidraTimeout.secondsForMilliseconds(1_200));
    assertEquals(30, GhidraTimeout.secondsForMilliseconds(30_000));
    assertEquals(300, GhidraTimeout.secondsForMilliseconds(300_000));
  }

  @Test
  void convertsRoundedSecondsToNanosecondDeadlinesWithoutFalseTimeoutWindow() {
    long startedAt = 10_000_000_000L;
    long deadline = GhidraTimeout.deadlineNanos(startedAt, 1_200);

    assertEquals(TimeUnit.SECONDS.toNanos(2), GhidraTimeout.budgetNanos(1_200));
    assertEquals(startedAt + TimeUnit.SECONDS.toNanos(2), deadline);

    // At 1,500 ms (inside the 800 ms rounding window above 1,200 ms), deadline has not elapsed.
    long at1500Ms = startedAt + TimeUnit.MILLISECONDS.toNanos(1_500);
    assertFalse(at1500Ms - deadline >= 0L);

    // At 2,000 ms (exact rounded decompiler budget), deadline is reached.
    long at2000Ms = startedAt + TimeUnit.MILLISECONDS.toNanos(2_000);
    assertTrue(at2000Ms - deadline >= 0L);
  }

  @Test
  void preservesTwoComplementDifferenceAcrossNanoTimeWrapAround() {
    long startedAt = Long.MAX_VALUE - TimeUnit.MILLISECONDS.toNanos(500);
    long deadline = GhidraTimeout.deadlineNanos(startedAt, 1_200);

    long beforeDeadline = startedAt + TimeUnit.MILLISECONDS.toNanos(1_999);
    long atDeadline = startedAt + TimeUnit.MILLISECONDS.toNanos(2_000);

    assertFalse(beforeDeadline - deadline >= 0L);
    assertTrue(atDeadline - deadline >= 0L);
  }
}
