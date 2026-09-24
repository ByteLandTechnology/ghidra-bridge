package app.byteland.ghidra.adapter.ghidra.decompilation;

import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Supplier;

final class LeasePool<T> implements AutoCloseable {
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
    this.available = new ArrayBlockingQueue<>(capacity);
  }

  Lease<T> acquire() {
    if (closed) {
      throw new IllegalStateException("resource pool is closed");
    }
    T existing = available.poll();
    if (existing != null) {
      return new PooledLease(existing);
    }

    while (true) {
      int current = created.get();
      if (current < capacity && created.compareAndSet(current, current + 1)) {
        boolean success = false;
        try {
          T createdValue = factory.get();
          success = true;
          return new PooledLease(createdValue);
        } finally {
          if (!success) {
            created.decrementAndGet();
          }
        }
      }

      try {
        return new PooledLease(available.take());
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
    T resource = available.poll();
    while (resource != null) {
      created.decrementAndGet();
      destroyQuietly(resource);
      resource = available.poll();
    }
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private void destroyQuietly(T resource) {
    try {
      destroyer.accept(resource);
    } catch (RuntimeException ignored) {
    }
  }

  private final class PooledLease implements Lease<T> {
    private final T leasedResource;
    private boolean released;

    private PooledLease(T value) {
      this.leasedResource = Objects.requireNonNull(value, "value");
    }

    @Override
    public T value() {
      if (released) {
        throw new IllegalStateException("lease already closed");
      }
      return leasedResource;
    }

    @Override
    public void close() {
      if (released) {
        return;
      }
      released = true;
      if (closed) {
        created.decrementAndGet();
        destroyQuietly(leasedResource);
        return;
      }
      if (!available.offer(leasedResource)) {
        throw new IllegalStateException("resource pool overflow");
      }
    }
  }
}
