package app.byteland.ghidra.adapter.ghidra.decompilation;

import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Supplier;

final class LeasePool<T> implements AutoCloseable {
  private static final long WAIT_POLL_MS = 50L;

  interface Lease<T> extends AutoCloseable {
    T value();

    @Override
    void close();
  }

  private final int capacity;
  private final Supplier<T> factory;
  private final Consumer<T> destroyer;
  private final BlockingQueue<T> available;
  private final AtomicInteger created = new AtomicInteger();
  private volatile boolean closed;

  LeasePool(int maxSize, Supplier<T> factory) {
    this(maxSize, factory, value -> {});
  }

  LeasePool(int maxSize, Supplier<T> factory, Consumer<T> destroyer) {
    this.capacity = Math.max(1, maxSize);
    this.factory = Objects.requireNonNull(factory, "factory");
    this.destroyer = Objects.requireNonNull(destroyer, "destroyer");
    this.available = new ArrayBlockingQueue<>(capacity, true);
  }

  Lease<T> acquire() {
    while (true) {
      if (closed) {
        throw new IllegalStateException("resource pool is closed");
      }
      T existing = available.poll();
      if (existing != null) {
        if (closed) {
          created.decrementAndGet();
          destroyQuietly(existing);
          throw new IllegalStateException("resource pool is closed");
        }
        return new PooledLease(existing);
      }

      int current = created.get();
      if (current < capacity) {
        if (!created.compareAndSet(current, current + 1)) {
          continue;
        }
        boolean handedOff = false;
        T createdValue = null;
        try {
          createdValue = factory.get();
          if (closed) {
            throw new IllegalStateException("resource pool is closed");
          }
          PooledLease lease = new PooledLease(createdValue);
          handedOff = true;
          return lease;
        } finally {
          if (!handedOff) {
            created.decrementAndGet();
            if (createdValue != null) {
              destroyQuietly(createdValue);
            }
          }
        }
      }

      try {
        T waited = available.poll(WAIT_POLL_MS, TimeUnit.MILLISECONDS);
        if (waited != null) {
          if (closed) {
            created.decrementAndGet();
            destroyQuietly(waited);
            throw new IllegalStateException("resource pool is closed");
          }
          return new PooledLease(waited);
        }
      } catch (InterruptedException ex) {
        Thread.currentThread().interrupt();
        throw new IllegalStateException("Interrupted while waiting for pooled resource", ex);
      }
    }
  }

  int maxSize() {
    return capacity;
  }

  int createdCount() {
    return created.get();
  }

  @Override
  public void close() {
    closed = true;
    drainAvailable();
  }

  private void drainAvailable() {
    T resource = available.poll();
    while (resource != null) {
      created.decrementAndGet();
      destroyQuietly(resource);
      resource = available.poll();
    }
  }

  private void destroyQuietly(T resource) {
    try {
      destroyer.accept(resource);
    } catch (RuntimeException ignored) {
    }
  }

  private final class PooledLease implements Lease<T> {
    private final T leasedResource;
    private final AtomicBoolean released = new AtomicBoolean();

    private PooledLease(T value) {
      this.leasedResource = Objects.requireNonNull(value, "value");
    }

    @Override
    public T value() {
      if (released.get()) {
        throw new IllegalStateException("lease already closed");
      }
      return leasedResource;
    }

    @Override
    public void close() {
      if (!released.compareAndSet(false, true)) {
        return;
      }
      if (closed) {
        created.decrementAndGet();
        destroyQuietly(leasedResource);
        return;
      }
      if (!available.offer(leasedResource)) {
        created.decrementAndGet();
        destroyQuietly(leasedResource);
        throw new IllegalStateException("resource pool overflow");
      }
      if (closed) {
        drainAvailable();
      }
    }
  }
}
