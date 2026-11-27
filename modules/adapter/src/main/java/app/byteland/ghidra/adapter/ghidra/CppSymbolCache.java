package app.byteland.ghidra.adapter.ghidra;

import app.byteland.ghidra.adapter.ghidra.CppSymbolNames.DecodedSymbol;
import app.byteland.ghidra.adapter.ghidra.CppSymbolNames.NameCandidate;
import ghidra.app.util.demangler.Demangled;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Stores decoded C++ symbol metadata within configurable entry and byte limits.
 */
final class CppSymbolCache {
  private record CachedEntry(DecodedSymbol symbol, long bytes) {}

  private final CppSymbolIndexConfig config;
  private final Object lock = new Object();
  private final LinkedHashMap<String, CachedEntry> entries =
      new LinkedHashMap<>(256, 0.75f, true);
  private final ConcurrentHashMap<String, CachedEntry> readView =
      new ConcurrentHashMap<>(256);
  private long usedBytes;
  private long snapshotBytes;
  private boolean closed;
  private volatile boolean evictionActive;

  CppSymbolCache(CppSymbolIndexConfig config) {
    this.config = Objects.requireNonNull(config, "config");
  }

  DecodedSymbol get(String name) {
    if (!evictionActive) {
      CachedEntry hit = readView.get(name);
      return hit == null ? null : hit.symbol();
    }
    synchronized (lock) {
      if (closed) {
        return null;
      }
      CachedEntry hit = entries.get(name);
      return hit == null ? null : hit.symbol();
    }
  }

  boolean contains(String name) {
    return readView.containsKey(name);
  }

  boolean isEvictionActive() {
    return evictionActive;
  }

  void markEvictionActive() {
    evictionActive = true;
  }

  boolean isAtCapacity() {
    synchronized (lock) {
      return closed
          || entries.size() >= config.maxEntries()
          || usedBytes >= config.maxBytes();
    }
  }

  boolean putFromPrewarm(String name, DecodedSymbol symbol) {
    long entryBytes = estimateEntryBytes(name, symbol);
    synchronized (lock) {
      if (closed) {
        return false;
      }
      if (entries.containsKey(name)) {
        return true;
      }
      if (entries.size() >= config.maxEntries() || usedBytes + entryBytes > config.maxBytes()) {
        return false;
      }
      CachedEntry cached = new CachedEntry(symbol, entryBytes);
      entries.put(name, cached);
      readView.put(name, cached);
      usedBytes += entryBytes;
      return entries.size() < config.maxEntries() && usedBytes < config.maxBytes();
    }
  }

  boolean putOnDemand(String name, DecodedSymbol symbol, Runnable onDropSnapshot) {
    long entryBytes = estimateEntryBytes(name, symbol);
    if (entryBytes > config.maxBytes()) {
      return false;
    }
    boolean freedSpace = false;
    boolean droppedSnapshot = false;
    synchronized (lock) {
      if (closed) {
        return false;
      }
      CachedEntry previous = entries.remove(name);
      if (previous != null) {
        readView.remove(name);
        usedBytes -= previous.bytes();
      }
      if (snapshotBytes > 0L && usedBytes + entryBytes > config.maxBytes()) {
        usedBytes = Math.max(0L, usedBytes - snapshotBytes);
        snapshotBytes = 0L;
        droppedSnapshot = true;
      }
      Iterator<Map.Entry<String, CachedEntry>> iterator = entries.entrySet().iterator();
      while (iterator.hasNext()
          && (entries.size() >= config.maxEntries()
              || usedBytes + entryBytes > config.maxBytes())) {
        Map.Entry<String, CachedEntry> eldest = iterator.next();
        CachedEntry evicted = eldest.getValue();
        readView.remove(eldest.getKey());
        iterator.remove();
        usedBytes -= evicted.bytes();
        freedSpace = true;
      }
      if (freedSpace) {
        evictionActive = true;
      }
      CachedEntry cached = new CachedEntry(symbol, entryBytes);
      entries.put(name, cached);
      readView.put(name, cached);
      usedBytes += entryBytes;
    }
    if (droppedSnapshot && onDropSnapshot != null) {
      onDropSnapshot.run();
    }
    return freedSpace;
  }

  boolean fitsSnapshotBudget(long candidateSnapshotBytes) {
    synchronized (lock) {
      if (closed) {
        return false;
      }
      long cppOnlyBytes = Math.max(0L, usedBytes - snapshotBytes);
      return cppOnlyBytes + candidateSnapshotBytes <= config.maxBytes();
    }
  }

  boolean reserveSnapshotBytes(long bytes, int rowCount) {
    synchronized (lock) {
      if (closed) {
        return false;
      }
      long cppOnlyBytes = Math.max(0L, usedBytes - snapshotBytes);
      if (cppOnlyBytes + bytes > config.maxBytes() || rowCount > config.maxEntries()) {
        usedBytes = cppOnlyBytes;
        snapshotBytes = 0L;
        return false;
      }
      usedBytes = cppOnlyBytes + bytes;
      snapshotBytes = bytes;
      return true;
    }
  }

  void releaseSnapshotBytes() {
    synchronized (lock) {
      if (snapshotBytes != 0L) {
        usedBytes = Math.max(0L, usedBytes - snapshotBytes);
        snapshotBytes = 0L;
      }
    }
  }

  int entryCount() {
    synchronized (lock) {
      return entries.size();
    }
  }

  long estimatedBytes() {
    synchronized (lock) {
      return usedBytes;
    }
  }

  void reset() {
    synchronized (lock) {
      if (closed) {
        return;
      }
      entries.clear();
      readView.clear();
      snapshotBytes = 0L;
      usedBytes = 0L;
      evictionActive = false;
    }
  }

  void close() {
    synchronized (lock) {
      closed = true;
      entries.clear();
      readView.clear();
      snapshotBytes = 0L;
      usedBytes = 0L;
    }
  }

  static long estimateEntryBytes(String key, DecodedSymbol symbol) {
    long total = 96L + stringBytes(key) + stringBytes(symbol.signature());
    for (NameCandidate candidate : symbol.candidates()) {
      total +=
          48L
              + stringBytes(candidate.originalDemangled())
              + stringBytes(candidate.name())
              + namespaceBytes(candidate.namespace());
    }
    return Math.max(64L, total);
  }

  static long stringBytes(String text) {
    return text == null ? 0L : 40L + (2L * text.length());
  }

  private static long namespaceBytes(Demangled namespace) {
    long total = 0L;
    for (Demangled cursor = namespace; cursor != null; cursor = cursor.getNamespace()) {
      total += 32L + stringBytes(cursor.getNamespaceName());
    }
    return total;
  }
}
