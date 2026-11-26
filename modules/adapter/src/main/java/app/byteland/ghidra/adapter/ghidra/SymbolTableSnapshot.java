package app.byteland.ghidra.adapter.ghidra;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.LongSupplier;

/**
 * Immutable address-ordered memory-symbol snapshot tracked by program modification number.
 */
public final class SymbolTableSnapshot {
  static final int MAX_SCAN_STEPS_PER_LOCK = 1024;

  /** Detached memory-symbol row ordered by {@code (address, id)} for {@code symbol.list} scans. */
  public record Row(
      long id,
      String idText,
      Address address,
      String canonicalAddress,
      String name,
      String namespace,
      String symbolType,
      String sourceType,
      boolean primary) {}

  enum Outcome {
    BUILT,
    SKIPPED,
    MODIFIED,
    ABORTED
  }

  private record RawRow(
      long id,
      Address address,
      String name,
      String namespace,
      String symbolType,
      String sourceType,
      boolean primary) {}

  private final WeakReference<Program> programRef;
  private final long modificationNumber;
  private final AddressSpace singleAddressSpace;
  private final List<Row> symbols;

  private SymbolTableSnapshot(
      Program program,
      long modificationNumber,
      AddressSpace singleAddressSpace,
      List<Row> symbols) {
    this.programRef = new WeakReference<>(program);
    this.modificationNumber = modificationNumber;
    this.singleAddressSpace = singleAddressSpace;
    this.symbols = List.copyOf(symbols);
  }

  public List<Row> symbols() {
    return symbols;
  }

  public int lowerBound(Address target) {
    int low = 0;
    int high = symbols.size();
    while (low < high) {
      int mid = (low + high) >>> 1;
      if (symbols.get(mid).address().compareTo(target) < 0) {
        low = mid + 1;
      } else {
        high = mid;
      }
    }
    return low;
  }

  boolean isCurrentFor(GhidraSession session, Program program, Address iterationStart) {
    return program != null
        && iterationStart != null
        && iterationStart.isMemoryAddress()
        && session.canCacheSnapshots(program)
        && isCurrentForModification(program, program.getModificationNumber())
        && (singleAddressSpace == null
            || singleAddressSpace.equals(iterationStart.getAddressSpace()));
  }

  boolean isCurrentForModification(Program program, long expectedMod) {
    return program != null
        && programRef.refersTo(program)
        && modificationNumber == expectedMod;
  }

  static Outcome build(
      GhidraSession session,
      Program program,
      long expectedMod,
      LongSupplier invalidationEpochSupplier,
      CppSymbolIndexConfig config,
      CppSymbolCache cache,
      BooleanSupplier cancelled,
      Consumer<SymbolTableSnapshot> publisher,
      Runnable clearSnapshot) {
    if (!session.canCacheSnapshots(program)) {
      clearSnapshot.run();
      return Outcome.SKIPPED;
    }

    long startEpoch = invalidationEpochSupplier.getAsLong();
    SnapshotCursor cursor = new SnapshotCursor();
    IdentityHashMap<Namespace, String> namespaceNames = new IdentityHashMap<>();
    HashMap<String, String> sharedStrings = new HashMap<>(64);
    List<Row> built = new ArrayList<>(256);
    long runningBytes = 64L;

    while (!cancelled.getAsBoolean() && !cursor.finished) {
      if (session.isPausedForPrewarm(program)) {
        return Outcome.ABORTED;
      }
      if (!session.canCacheSnapshots(program)) {
        clearSnapshot.run();
        return Outcome.SKIPPED;
      }
      if (invalidationEpochSupplier.getAsLong() != startEpoch
          || program.getModificationNumber() != expectedMod) {
        clearSnapshot.run();
        return Outcome.MODIFIED;
      }

      SnapshotBatch batch =
          session.tryCollectForPrewarm(
              program,
              () ->
                  collectBatchLocked(
                      program,
                      expectedMod,
                      startEpoch,
                      invalidationEpochSupplier,
                      cursor,
                      namespaceNames,
                      sharedStrings),
              SnapshotBatch.PAUSED);
      if (batch.status == BatchStatus.PAUSED) {
        return Outcome.ABORTED;
      }
      if (batch.status == BatchStatus.MODIFIED) {
        clearSnapshot.run();
        return Outcome.MODIFIED;
      }
      if (!cursor.supported) {
        clearSnapshot.run();
        return Outcome.SKIPPED;
      }

      for (RawRow raw : batch.rows) {
        if (cancelled.getAsBoolean()) {
          return Outcome.ABORTED;
        }
        if (built.size() + 1 > config.maxEntries()) {
          clearSnapshot.run();
          return Outcome.SKIPPED;
        }
        String canonicalAddress = AddressUtil.canonicalAddress(raw.address());
        String idText = Long.toString(raw.id());
        long rowBytes =
            56L
                + CppSymbolCache.stringBytes(canonicalAddress)
                + CppSymbolCache.stringBytes(idText)
                + (cache.contains(raw.name()) ? 0L : CppSymbolCache.stringBytes(raw.name()));
        runningBytes += rowBytes;
        if (!cache.fitsSnapshotBudget(runningBytes)) {
          clearSnapshot.run();
          return Outcome.SKIPPED;
        }
        built.add(
            new Row(
                raw.id(),
                idText,
                raw.address(),
                canonicalAddress,
                raw.name(),
                raw.namespace(),
                raw.symbolType(),
                raw.sourceType(),
                raw.primary()));
      }
    }

    if (cancelled.getAsBoolean() || !cursor.finished) {
      return Outcome.ABORTED;
    }
    final AddressSpace resolvedSpace = cursor.singleSpace;
    final long snapshotBytes = runningBytes;
    return session.tryCollectForPrewarm(
        program,
        () -> {
          if (cancelled.getAsBoolean()) {
            return Outcome.ABORTED;
          }
          if (!session.canCacheSnapshots(program)) {
            clearSnapshot.run();
            return Outcome.SKIPPED;
          }
          if (invalidationEpochSupplier.getAsLong() != startEpoch
              || program.getModificationNumber() != expectedMod) {
            clearSnapshot.run();
            return Outcome.MODIFIED;
          }
          if (!cache.reserveSnapshotBytes(snapshotBytes, built.size())) {
            clearSnapshot.run();
            return Outcome.SKIPPED;
          }
          publisher.accept(new SymbolTableSnapshot(program, expectedMod, resolvedSpace, built));
          return Outcome.BUILT;
        },
        Outcome.ABORTED);
  }

  private static SnapshotBatch collectBatchLocked(
      Program program,
      long expectedMod,
      long expectedEpoch,
      LongSupplier invalidationEpochSupplier,
      SnapshotCursor cursor,
      IdentityHashMap<Namespace, String> namespaceNames,
      HashMap<String, String> sharedStrings) {
    if (invalidationEpochSupplier.getAsLong() != expectedEpoch
        || program.getModificationNumber() != expectedMod) {
      return SnapshotBatch.MODIFIED;
    }
    Address startAddress = cursor.lastAddress;
    if (startAddress == null) {
      startAddress = program.getMinAddress();
      if (startAddress == null) {
        AddressSpace defaultSpace =
            program.getAddressFactory() == null
                ? null
                : program.getAddressFactory().getDefaultAddressSpace();
        startAddress = defaultSpace == null ? null : defaultSpace.getMinAddress();
      }
      if (startAddress == null) {
        cursor.finished = true;
        return SnapshotBatch.EMPTY;
      }
    }
    SymbolTable symbolTable = program.getSymbolTable();
    SymbolIterator iterator;
    try {
      iterator = symbolTable.getSymbolIterator(startAddress, true);
    } catch (RuntimeException unsupported) {
      cursor.supported = false;
      cursor.finished = true;
      return SnapshotBatch.EMPTY;
    }
    if (iterator == null) {
      cursor.finished = true;
      return SnapshotBatch.EMPTY;
    }

    List<RawRow> rows = new ArrayList<>(Math.min(MAX_SCAN_STEPS_PER_LOCK, 256));
    int steps = 0;
    boolean exhausted = true;
    while (iterator.hasNext()) {
      Symbol symbol = iterator.next();
      if (symbol == null) {
        continue;
      }
      Address address = symbol.getAddress();
      if (address == null || !address.isMemoryAddress()) {
        cursor.supported = false;
        cursor.finished = true;
        return SnapshotBatch.EMPTY;
      }
      AddressSpace space = address.getAddressSpace();
      if (cursor.singleSpace == null) {
        cursor.singleSpace = space;
      } else if (!cursor.singleSpace.equals(space)) {
        cursor.supported = false;
        cursor.finished = true;
        return SnapshotBatch.EMPTY;
      }
      long id = symbol.getID();
      if (cursor.lastAddress != null) {
        int byAddr = address.compareTo(cursor.lastAddress);
        if (byAddr < 0 || (byAddr == 0 && id <= cursor.lastId)) {
          if (cursor.resumingFromPreviousBatch && byAddr == 0 && id <= cursor.lastId) {
            continue;
          }
          cursor.supported = false;
          cursor.finished = true;
          return SnapshotBatch.EMPTY;
        }
        cursor.resumingFromPreviousBatch = false;
      }
      cursor.lastAddress = address;
      cursor.lastId = id;

      Namespace parent = symbol.getParentNamespace();
      String nsName = null;
      if (parent != null) {
        nsName = namespaceNames.get(parent);
        if (nsName == null) {
          String computed = parent.getName(true);
          nsName = computed == null ? null : sharedStrings.computeIfAbsent(computed, k -> k);
          if (nsName != null) {
            namespaceNames.put(parent, nsName);
          }
        }
      }
      String typeText =
          symbol.getSymbolType() == null
              ? null
              : sharedStrings.computeIfAbsent(symbol.getSymbolType().toString(), k -> k);
      String sourceText =
          sharedStrings.computeIfAbsent(String.valueOf(symbol.getSource()), k -> k);

      rows.add(
          new RawRow(
              id, address, symbol.getName(), nsName, typeText, sourceText, symbol.isPrimary()));
      steps++;
      if (steps >= MAX_SCAN_STEPS_PER_LOCK) {
        cursor.resumingFromPreviousBatch = true;
        exhausted = false;
        break;
      }
    }
    if (exhausted) {
      cursor.finished = true;
    }
    return new SnapshotBatch(BatchStatus.COLLECTED, rows);
  }

  private enum BatchStatus {
    COLLECTED,
    PAUSED,
    MODIFIED
  }

  private static final class SnapshotBatch {
    static final SnapshotBatch PAUSED = new SnapshotBatch(BatchStatus.PAUSED, List.of());
    static final SnapshotBatch MODIFIED = new SnapshotBatch(BatchStatus.MODIFIED, List.of());
    static final SnapshotBatch EMPTY = new SnapshotBatch(BatchStatus.COLLECTED, List.of());

    final BatchStatus status;
    final List<RawRow> rows;

    private SnapshotBatch(BatchStatus status, List<RawRow> rows) {
      this.status = status;
      this.rows = rows;
    }
  }

  private static final class SnapshotCursor {
    AddressSpace singleSpace;
    Address lastAddress;
    long lastId;
    boolean resumingFromPreviousBatch;
    boolean supported = true;
    boolean finished;
  }
}
