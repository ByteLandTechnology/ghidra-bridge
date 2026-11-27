package app.byteland.ghidra.adapter.ghidra;

import ghidra.app.util.demangler.Demangled;
import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.app.util.demangler.MangledContext;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolTable;
import java.lang.ref.Reference;
import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReferenceArray;
import java.util.concurrent.locks.ReentrantLock;

/** Reads C++ names without changes to the program or its symbol IDs. */
public final class CppSymbolNames {
  static final int MIN_CAPACITY = 4_096;
  static final int MAX_CAPACITY = 65_536;
  private static final int READ_BUFFER_SIZE = 128;
  private static final int READ_BUFFER_MASK = READ_BUFFER_SIZE - 1;

  private static final ReferenceQueue<Program> STALE_PROGRAMS = new ReferenceQueue<>();
  private static final ConcurrentHashMap<Object, ProgramCache> CACHES = new ConcurrentHashMap<>();
  private static volatile LastProgramCache lastProgramCache;

  private CppSymbolNames() {}

  public static String demangled(Program program, String name, Address address) {
    return decode(program, name, address).signature();
  }

  public static DecodedSymbol decode(Program program, String name, Address address) {
    if (program == null || !isMangled(name)) return DecodedSymbol.EMPTY;
    ProgramCache cache = cacheFor(program);
    DecodedSymbol cached = cache.get(name);
    if (cached != null) return cached;
    // The demangler can use an external process. Do not hold the lock during the call.
    DecodedSymbol decoded = runDemangler(program, name, address);
    int refreshedCapacity =
        cache.needsCapacityRefresh() ? targetCapacity(program) : cache.capacity();
    return cache.putIfAbsent(name, decoded, refreshedCapacity);
  }

  public static boolean isMangled(String name) {
    return name != null
        && (name.startsWith("_Z") || name.startsWith("__Z") || name.startsWith("?"));
  }

  static int targetCapacity(Program program) {
    if (program == null) return MIN_CAPACITY;
    try {
      SymbolTable symbolTable = program.getSymbolTable();
      if (symbolTable == null) return MIN_CAPACITY;
      long symbolCount = symbolTable.getNumSymbols();
      if (symbolCount <= 0) return MIN_CAPACITY;
      long scaled = symbolCount + (symbolCount >>> 2);
      return Math.clamp(scaled, MIN_CAPACITY, MAX_CAPACITY);
    } catch (RuntimeException ignored) {
      return MIN_CAPACITY;
    }
  }

  static Demangled detachNamespace(Demangled source) {
    if (source == null) return null;
    if (source instanceof DetachedNamespace detached) return detached;
    return new DetachedNamespace(
        source.getMangledString(),
        source.getOriginalDemangled(),
        source.getName(),
        source.getDemangledName(),
        source.getNamespaceName(),
        source.getNamespaceString(),
        source.getSignature(),
        detachNamespace(source.getNamespace()));
  }

  private static ProgramCache cacheFor(Program program) {
    LastProgramCache recent = lastProgramCache;
    if (recent != null && recent.programRef.get() == program) return recent.cache;
    expungeStalePrograms();
    ProgramCache existing = CACHES.get(new LookupKey(program));
    if (existing != null) {
      lastProgramCache = new LastProgramCache(new WeakReference<>(program), existing);
      return existing;
    }
    ProgramCache created = new ProgramCache(targetCapacity(program));
    WeakProgramKey key = new WeakProgramKey(program, STALE_PROGRAMS);
    ProgramCache raced = CACHES.putIfAbsent(key, created);
    if (raced != null) {
      key.clear();
      lastProgramCache = new LastProgramCache(new WeakReference<>(program), raced);
      return raced;
    }
    lastProgramCache = new LastProgramCache(new WeakReference<>(program), created);
    return created;
  }

  private static void expungeStalePrograms() {
    LastProgramCache recent = lastProgramCache;
    if (recent != null && recent.programRef.get() == null) {
      lastProgramCache = null;
    }
    Reference<? extends Program> reference;
    while ((reference = STALE_PROGRAMS.poll()) != null) {
      CACHES.remove(reference);
    }
  }

  private static DecodedSymbol runDemangler(Program program, String name, Address address) {
    List<DemangledObject> objects = DemanglerUtil.demangle(program, name, address);
    if (objects == null || objects.isEmpty()) return DecodedSymbol.EMPTY;
    String signature = null;
    List<NameCandidate> candidates = new ArrayList<>(objects.size());
    for (DemangledObject object : objects) {
      if (object == null) continue;
      if (signature == null) {
        String candidate = object.getSignature(false);
        if (candidate != null && !candidate.isBlank() && !candidate.equals(name)) {
          signature = candidate;
        }
      }
      candidates.add(
          new NameCandidate(
              object.getOriginalDemangled(), object.getName(), object.getNamespace()));
    }
    if (signature == null && candidates.isEmpty()) return DecodedSymbol.EMPTY;
    return new DecodedSymbol(signature, candidates);
  }

  public record DecodedSymbol(String signature, List<NameCandidate> candidates) {
    static final DecodedSymbol EMPTY = new DecodedSymbol(null, List.of());

    public DecodedSymbol {
      candidates = candidates == null || candidates.isEmpty() ? List.of() : List.copyOf(candidates);
    }
  }

  public record NameCandidate(String originalDemangled, String name, Demangled namespace) {
    public NameCandidate {
      namespace = detachNamespace(namespace);
    }
  }

  private record DetachedNamespace(
      String mangled,
      String originalDemangled,
      String name,
      String demangledName,
      String namespaceName,
      String namespaceString,
      String signature,
      Demangled parent)
      implements Demangled {
    @Override
    public MangledContext getMangledContext() {
      return null;
    }

    @Override
    public void setMangledContext(MangledContext mangledContextValue) {}

    @Override
    public String getMangledString() {
      return mangled;
    }

    @Override
    public String getOriginalDemangled() {
      return originalDemangled;
    }

    @Override
    public String getName() {
      return name;
    }

    @Override
    public void setName(String newName) {
      throw new UnsupportedOperationException("DetachedNamespace is immutable");
    }

    @Override
    public String getDemangledName() {
      return demangledName;
    }

    @Override
    public Demangled getNamespace() {
      return parent;
    }

    @Override
    public void setNamespace(Demangled newNamespace) {
      throw new UnsupportedOperationException("DetachedNamespace is immutable");
    }

    @Override
    public String getNamespaceString() {
      return namespaceString;
    }

    @Override
    public String getNamespaceName() {
      return namespaceName;
    }

    @Override
    public String getSignature() {
      return signature;
    }

    @Override
    public String toString() {
      return namespaceString != null ? namespaceString : "";
    }
  }

  private record LastProgramCache(WeakReference<Program> programRef, ProgramCache cache) {}

  private record LookupKey(Program program) {
    @Override
    public int hashCode() {
      return System.identityHashCode(program);
    }

    @Override
    public boolean equals(Object other) {
      if (other instanceof WeakProgramKey weak) return weak.get() == program;
      if (other instanceof LookupKey lookup) return lookup.program == program;
      return false;
    }
  }

  private static final class WeakProgramKey extends WeakReference<Program> {
    private final int hash;

    WeakProgramKey(Program program, ReferenceQueue<Program> queue) {
      super(program, queue);
      this.hash = System.identityHashCode(program);
    }

    @Override
    public int hashCode() {
      return hash;
    }

    @Override
    public boolean equals(Object other) {
      if (this == other) return true;
      Program target = get();
      if (target == null) return false;
      if (other instanceof WeakProgramKey weak) return weak.get() == target;
      if (other instanceof LookupKey lookup) return lookup.program == target;
      return false;
    }
  }

  static final class ProgramCache {
    private static final byte UNLINKED = 0;
    private static final byte PROBATION = 1;
    private static final byte PROTECTED_COLD = 2;
    private static final byte PROTECTED_HOT = 3;
    private static final byte REMOVED = 4;

    private final ConcurrentHashMap<String, CacheNode> entries = new ConcurrentHashMap<>(64);
    private final ReentrantLock evictionLock = new ReentrantLock();
    private final SegmentList probation = new SegmentList();
    private final SegmentList protectedCold = new SegmentList();
    private final SegmentList protectedHot = new SegmentList();
    private final AtomicReferenceArray<CacheNode> readBuffer =
        new AtomicReferenceArray<>(READ_BUFFER_SIZE);
    private final AtomicInteger readBufferIndex = new AtomicInteger();
    private volatile boolean readBufferDirty;
    private volatile int capacity;
    private int protectedLimit;
    private int hotLimit;

    ProgramCache(int initialCapacity) {
      int bounded = Math.clamp(initialCapacity, 2, MAX_CAPACITY);
      this.capacity = bounded;
      this.protectedLimit = protectedLimitFor(bounded);
      this.hotLimit = Math.max(1, this.protectedLimit >>> 1);
    }

    int capacity() {
      return capacity;
    }

    boolean needsCapacityRefresh() {
      int current = capacity;
      return current < MAX_CAPACITY && entries.size() >= current;
    }

    DecodedSymbol get(String key) {
      CacheNode node = entries.get(key);
      if (node == null) return null;
      if (node.state == PROTECTED_HOT && !readBufferDirty) return node.value;
      if (evictionLock.tryLock()) {
        try {
          if (readBufferDirty) drainReadBufferLocked();
          onHitLocked(node);
        } finally {
          evictionLock.unlock();
        }
      } else {
        recordDeferredHit(node);
      }
      return node.value;
    }

    DecodedSymbol putIfAbsent(String key, DecodedSymbol value, int refreshedCapacity) {
      evictionLock.lock();
      try {
        if (refreshedCapacity > capacity) {
          int raised = Math.min(MAX_CAPACITY, refreshedCapacity);
          if (raised > capacity) {
            capacity = raised;
            protectedLimit = protectedLimitFor(raised);
            hotLimit = Math.max(1, protectedLimit >>> 1);
          }
        }
        if (readBufferDirty) drainReadBufferLocked();
        CacheNode existing = entries.get(key);
        if (existing != null) {
          onHitLocked(existing);
          return existing.value;
        }
        CacheNode created = new CacheNode(key, value);
        created.state = PROBATION;
        probation.addFirst(created);
        entries.put(key, created);
        evictIfNeededLocked();
        return value;
      } finally {
        evictionLock.unlock();
      }
    }

    private void recordDeferredHit(CacheNode node) {
      int slot = readBufferIndex.getAndIncrement() & READ_BUFFER_MASK;
      readBuffer.set(slot, node);
      readBufferDirty = true;
    }

    private void drainReadBufferLocked() {
      readBufferDirty = false;
      for (int i = 0; i < READ_BUFFER_SIZE; i++) {
        CacheNode buffered = readBuffer.getAndSet(i, null);
        if (buffered != null) onHitLocked(buffered);
      }
    }

    private void onHitLocked(CacheNode node) {
      byte currentState = node.state;
      if (currentState == PROBATION) {
        probation.remove(node);
        node.state = PROTECTED_HOT;
        protectedHot.addFirst(node);
        rebalanceProtectedLocked();
      } else if (currentState == PROTECTED_COLD) {
        protectedCold.remove(node);
        node.state = PROTECTED_HOT;
        protectedHot.addFirst(node);
        rebalanceProtectedLocked();
      } else if (currentState == PROTECTED_HOT) {
        protectedHot.moveToFirst(node);
      }
    }

    private void rebalanceProtectedLocked() {
      if (protectedHot.size() + protectedCold.size() > protectedLimit) {
        while (protectedHot.size() > hotLimit) {
          CacheNode cooled = protectedHot.removeLast();
          if (cooled == null) break;
          cooled.state = PROTECTED_COLD;
          protectedCold.addFirst(cooled);
        }
      }
      while (protectedHot.size() + protectedCold.size() > protectedLimit) {
        CacheNode demoted = protectedCold.removeLast();
        if (demoted == null) demoted = protectedHot.removeLast();
        if (demoted == null) break;
        demoted.state = PROBATION;
        probation.addFirst(demoted);
      }
    }

    private void evictIfNeededLocked() {
      while (probation.size() + protectedHot.size() + protectedCold.size() > capacity) {
        CacheNode victim = probation.removeLast();
        if (victim == null) victim = protectedCold.removeLast();
        if (victim == null) victim = protectedHot.removeLast();
        if (victim == null) break;
        victim.state = REMOVED;
        entries.remove(victim.key, victim);
      }
    }

    private static int protectedLimitFor(int totalCapacity) {
      return Math.max(1, totalCapacity - Math.max(1, totalCapacity / 5));
    }
  }

  private static final class CacheNode {
    final String key;
    final DecodedSymbol value;
    CacheNode prev;
    CacheNode next;
    volatile byte state = ProgramCache.UNLINKED;

    CacheNode(String key, DecodedSymbol value) {
      this.key = key;
      this.value = value;
    }
  }

  private static final class SegmentList {
    private final CacheNode head = new CacheNode(null, null);
    private final CacheNode tail = new CacheNode(null, null);
    private int size;

    SegmentList() {
      head.next = tail;
      tail.prev = head;
    }

    int size() {
      return size;
    }

    void addFirst(CacheNode node) {
      CacheNode first = head.next;
      node.prev = head;
      node.next = first;
      head.next = node;
      first.prev = node;
      size++;
    }

    void remove(CacheNode node) {
      CacheNode previous = node.prev;
      CacheNode following = node.next;
      previous.next = following;
      following.prev = previous;
      node.prev = null;
      node.next = null;
      size--;
    }

    void moveToFirst(CacheNode node) {
      if (head.next == node) return;
      CacheNode previous = node.prev;
      CacheNode following = node.next;
      previous.next = following;
      following.prev = previous;
      CacheNode first = head.next;
      node.prev = head;
      node.next = first;
      head.next = node;
      first.prev = node;
    }

    CacheNode removeLast() {
      CacheNode last = tail.prev;
      if (last == head) return null;
      remove(last);
      return last;
    }
  }
}
