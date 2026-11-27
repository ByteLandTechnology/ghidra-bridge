package app.byteland.ghidra.adapter.ghidra.listing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.listing.ListingService.StringQuery;
import app.byteland.ghidra.service.listing.StringResource;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class StringFilterMatcherTest {
  private static final AddressScanOptions SCAN = new AddressScanOptions(null, null, 1000);

  @Test
  void filtersByQueryRegexCaseLengthAndEncoding() {
    StringResource item =
        new StringResource(
            "ram:00100000",
            24,
            "https://api.example.test",
            "UTF-16LE",
            true,
            DataTypeReference.named("unicode"));

    StringFilterMatcher insensitive =
        StringFilterMatcher.compile(
            new StringQuery(SCAN, "EXAMPLE", "^https://", false, 10, "UTF-16", false, 50, null));
    assertEquals(10, insensitive.minCandidateLength());
    assertTrue(insensitive.matches(item, () -> 0L, 1_000_000L));

    StringFilterMatcher sensitiveMismatch =
        StringFilterMatcher.compile(
            new StringQuery(SCAN, "EXAMPLE", null, true, null, null, false, 50, null));
    assertEquals(StringFilterMatcher.DEFAULT_CANDIDATE_MIN_LENGTH,
        sensitiveMismatch.minCandidateLength());
    assertFalse(sensitiveMismatch.matches(item, () -> 0L, 1_000_000L));

    StringFilterMatcher asciiFilter =
        StringFilterMatcher.compile(
            new StringQuery(SCAN, null, null, false, null, "ASCII", false, 50, null));
    assertFalse(asciiFilter.matches(item, () -> 0L, 1_000_000L));
    StringResource asciiItem =
        new StringResource(
            "ram:00100100", 6, "hello", "US-ASCII", true, DataTypeReference.named("string"));
    assertTrue(asciiFilter.matches(asciiItem, () -> 0L, 1_000_000L));
  }

  @Test
  void rejectsInvalidFilterSyntaxBeforeScan() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            StringFilterMatcher.compile(
                new StringQuery(SCAN, null, "[unclosed", false, null, null, false, 50, null)));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            StringFilterMatcher.compile(
                new StringQuery(SCAN, null, "   ", false, null, null, false, 50, null)));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            StringFilterMatcher.compile(
                new StringQuery(SCAN, null, null, false, null, "---", false, 50, null)));
  }

  @Test
  void stopsCatastrophicBacktrackingRegexAtDeadline() {
    StringFilterMatcher matcher =
        StringFilterMatcher.compile(
            new StringQuery(SCAN, null, "(a+)+$", true, null, null, false, 50, null));
    StringResource evilInput =
        new StringResource(
            "ram:00100200", 33, "a".repeat(32) + "!", "US-ASCII", true, null);
    AtomicLong clock = new AtomicLong(0L);
    assertThrows(
        StringFilterMatcher.RegexTimeoutException.class,
        () -> matcher.matches(evilInput, () -> clock.addAndGet(100L), 500L));
    assertTrue(clock.get() >= 500L);
  }
}
