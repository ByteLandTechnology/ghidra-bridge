package app.byteland.ghidra.adapter.ghidra.decompilation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.comment.CommentResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class FunctionCommentsTest {
  @Test
  void completesInsideRoundedDecompilerBudgetAboveUnroundedTimeout() {
    Map<Address, String> repeatable = new LinkedHashMap<>();
    repeatable.put(address("ram", "00101000"), "first repeatable note");
    repeatable.put(address("ram", "00101004"), "second repeatable note");
    Function function = functionWithComments(repeatable, null);

    long startedAt = 1_000_000_000L;
    // 1,500 ms elapsed: past unrounded 1,200 ms, but within 2,000 ms rounded budget.
    AtomicLong clock = new AtomicLong(startedAt + TimeUnit.MILLISECONDS.toNanos(1_500));
    List<String> warnings = new ArrayList<>();

    FunctionComments result =
        FunctionComments.read(function, startedAt, 1_200, true, warnings, clock::get);

    assertTrue(result.complete());
    assertEquals(List.of(), warnings);
    assertEquals(
        List.of(
            new CommentResource("ram:00101000", CommentResource.Type.REPEATABLE,
                "first repeatable note"),
            new CommentResource("ram:00101004", CommentResource.Type.REPEATABLE,
                "second repeatable note")),
        result.items());
  }

  @Test
  void grantsPostDecompileGraceWindowWhenDecompileCompletedAfterRoundedBudget() {
    Map<Address, String> repeatable = new LinkedHashMap<>();
    repeatable.put(address("ram", "00102000"), "grace window comment");
    repeatable.put(address("ram", "00102008"), "second grace comment");
    Function function = functionWithComments(repeatable, null);

    long startedAt = 5_000_000_000L;
    // Decompile completed right after the 2,000 ms rounded budget at 2,020 ms.
    AtomicLong clock = new AtomicLong(startedAt + TimeUnit.MILLISECONDS.toNanos(2_020));
    List<String> warnings = new ArrayList<>();

    FunctionComments result = FunctionComments.read(
        function, startedAt, 1_200, true, warnings,
        () -> clock.getAndAdd(TimeUnit.MILLISECONDS.toNanos(5)));

    assertTrue(result.complete());
    assertEquals(List.of(), warnings);
    assertEquals(2, result.items().size());
  }

  @Test
  void boundsPostDecompileGraceWindowWhenCommentScanStalls() {
    Map<Address, String> repeatable = new LinkedHashMap<>();
    repeatable.put(address("ram", "00103000"), "before stall");
    repeatable.put(address("ram", "00103004"), "after grace expires");
    Function function = functionWithComments(repeatable, null);

    long startedAt = 5_000_000_000L;
    long readStart = startedAt + TimeUnit.MILLISECONDS.toNanos(2_020);
    long[] samples = {
      readStart,
      readStart + FunctionComments.POST_DECOMPILE_GRACE_NANOS - 1L,
      readStart + FunctionComments.POST_DECOMPILE_GRACE_NANOS
    };
    int[] index = {0};
    List<String> warnings = new ArrayList<>();

    FunctionComments result = FunctionComments.read(
        function, startedAt, 1_200, true, warnings,
        () -> samples[Math.min(index[0]++, samples.length - 1)]);

    assertFalse(result.complete());
    assertEquals(1, result.items().size());
    assertEquals("before stall", result.items().getFirst().text());
    assertEquals(
        List.of("Repeatable comments are incomplete: the request time limit was reached."),
        warnings);
  }

  @Test
  void skipsGraceWindowWhenDecompileDidNotComplete() {
    Map<Address, String> repeatable = new LinkedHashMap<>();
    repeatable.put(address("ram", "00104000"), "should not be read after timeout");
    Function function = functionWithComments(repeatable, null);

    long startedAt = 8_000_000_000L;
    // Decompile timed out at the 2,000 ms rounded budget with decompileCompleted = false.
    AtomicLong clock = new AtomicLong(startedAt + TimeUnit.SECONDS.toNanos(2));
    List<String> warnings = new ArrayList<>();

    FunctionComments result =
        FunctionComments.read(function, startedAt, 1_200, false, warnings, clock::get);

    assertFalse(result.complete());
    assertEquals(List.of(), result.items());
    assertEquals(
        List.of("Repeatable comments are incomplete: the request time limit was reached."),
        warnings);
  }

  @Test
  void recordsIncompleteWarningOnListingRuntimeFailure() {
    Function function =
        functionWithComments(Map.of(), new IllegalStateException("database closed"));
    List<String> warnings = new ArrayList<>();

    FunctionComments result =
        FunctionComments.read(function, 0L, 1_000, true, warnings, () -> 0L);

    assertFalse(result.complete());
    assertEquals(List.of(), result.items());
    assertEquals(List.of("Repeatable comments are incomplete: database closed"), warnings);
  }

  static Address address(String spaceName, String hexOffset) {
    AddressSpace space = (AddressSpace) Proxy.newProxyInstance(
        AddressSpace.class.getClassLoader(),
        new Class<?>[] {AddressSpace.class},
        (proxy, method, args) -> switch (method.getName()) {
          case "getName" -> spaceName;
          case "equals" -> proxy == args[0];
          case "hashCode" -> spaceName.hashCode();
          default -> throw new AssertionError(method.getName());
        });
    return (Address) Proxy.newProxyInstance(
        Address.class.getClassLoader(),
        new Class<?>[] {Address.class},
        (proxy, method, args) -> switch (method.getName()) {
          case "getAddressSpace" -> space;
          case "toString" -> hexOffset;
          case "equals" -> proxy == args[0];
          case "hashCode" -> hexOffset.hashCode();
          default -> throw new AssertionError(method.getName());
        });
  }

  private static Function functionWithComments(
      Map<Address, String> comments, RuntimeException failure) {
    Iterator<Address> backing = comments.keySet().iterator();
    AddressIterator addressIterator = (AddressIterator) Proxy.newProxyInstance(
        AddressIterator.class.getClassLoader(),
        new Class<?>[] {AddressIterator.class},
        (proxy, method, args) -> switch (method.getName()) {
          case "iterator" -> proxy;
          case "hasNext" -> backing.hasNext();
          case "next" -> backing.next();
          default -> throw new AssertionError(method.getName());
        });
    Listing listing = (Listing) Proxy.newProxyInstance(
        Listing.class.getClassLoader(),
        new Class<?>[] {Listing.class},
        (proxy, method, args) -> {
          if (failure != null) {
            throw failure;
          }
          return switch (method.getName()) {
            case "getCommentAddressIterator" -> {
              assertEquals(CommentType.REPEATABLE, args[0]);
              yield addressIterator;
            }
            case "getComment" -> {
              assertEquals(CommentType.REPEATABLE, args[0]);
              yield comments.get((Address) args[1]);
            }
            default -> throw new AssertionError(method.getName());
          };
        });
    Program program = (Program) Proxy.newProxyInstance(
        Program.class.getClassLoader(),
        new Class<?>[] {Program.class},
        (proxy, method, args) -> switch (method.getName()) {
          case "getListing" -> listing;
          default -> throw new AssertionError(method.getName());
        });
    return (Function) Proxy.newProxyInstance(
        Function.class.getClassLoader(),
        new Class<?>[] {Function.class},
        (proxy, method, args) -> switch (method.getName()) {
          case "getProgram" -> program;
          case "getBody" -> null;
          default -> throw new AssertionError(method.getName());
        });
  }
}
