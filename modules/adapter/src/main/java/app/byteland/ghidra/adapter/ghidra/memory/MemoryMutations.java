package app.byteland.ghidra.adapter.ghidra.memory;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.TransactionExecutionException;
import app.byteland.ghidra.service.memory.MemoryBlockConflictException;
import app.byteland.ghidra.service.memory.MemoryBlockResource;
import app.byteland.ghidra.service.memory.MemoryService.MemoryBlockCreateRequest;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;

final class MemoryMutations {
  private final GhidraSession context;

  MemoryMutations(GhidraSession context) {
    this.context = context;
  }

  MemoryBlockResource createMemoryBlock(MemoryBlockCreateRequest request) {
    Objects.requireNonNull(request, "request");
    Memory memory = context.currentProgram().getMemory();
    if (memory.getBlock(request.name()) != null) {
      throw new MemoryBlockConflictException(
          "memory_block_exists",
          "/resource/name",
          "memory block already exists: " + request.name());
    }
    Address start = parseAddress(request.start());
    MemoryBlock block = allocateBlock(memory, start, request);
    block.setRead(request.read());
    block.setWrite(request.write());
    block.setExecute(request.execute());
    block.setVolatile(request.isVolatile());
    if (request.comment() != null) {
      block.setComment(request.comment());
    }
    return MemoryBlockQueries.describeMemoryBlock(block);
  }

  void patchMemory(String startRaw, ByteSequence sequence) {
    Address start = parseAddress(startRaw);
    byte[] bytes =
        MemoryEncoding.decodeBytes(
            sequence.data(), sequence.encoding().name().toLowerCase(Locale.ROOT));
    writeBytes(start, bytes);
  }

  private MemoryBlock allocateBlock(
      Memory memory, Address start, MemoryBlockCreateRequest request) {
    try {
      if (!request.initialized()) {
        return memory.createUninitializedBlock(
            request.name(), start, request.length(), request.overlay());
      }
      byte fill = (byte) (request.fillByte() != null ? request.fillByte() : 0);
      if (request.bytes() != null) {
        byte[] decoded =
            MemoryEncoding.decodeBytes(
                request.bytes().data(),
                request.bytes().encoding().name().toLowerCase(Locale.ROOT));
        if (decoded.length > request.length()) {
          throw new IllegalArgumentException("bytes length must not exceed block length");
        }
        return memory.createInitializedBlock(
            request.name(),
            start,
            paddedStream(decoded, request.length(), fill),
            request.length(),
            TaskMonitor.DUMMY,
            request.overlay());
      }
      return memory.createInitializedBlock(
          request.name(), start, request.length(), fill, TaskMonitor.DUMMY, request.overlay());
    } catch (MemoryConflictException ex) {
      throw new MemoryBlockConflictException(
          "memory_block_conflict",
          "/resource/start",
          "memory block overlaps another block: " + ex.getMessage(),
          ex);
    } catch (AddressOverflowException ex) {
      throw new MemoryBlockConflictException(
          "address_overflow",
          "/resource/length",
          "memory block overflows address space: " + ex.getMessage(),
          ex);
    } catch (LockException ex) {
      throw new MemoryBlockConflictException(
          "lock_conflict",
          "/resource",
          "memory block creation requires exclusive access: " + ex.getMessage(),
          ex);
    } catch (IllegalStateException ex) {
      throw new MemoryBlockConflictException(
          "memory_block_conflict",
          "/resource/length",
          "memory block creation failed: " + ex.getMessage(),
          ex);
    } catch (CancelledException ex) {
      throw new TransactionExecutionException(
          "memory block creation stopped early: " + ex.getMessage(), ex);
    }
  }

  private static InputStream paddedStream(byte[] prefix, long totalLength, byte fill) {
    return new InputStream() {
      private long position;

      @Override
      public int read() {
        if (position >= totalLength) {
          return -1;
        }
        int value = (position < prefix.length ? prefix[(int) position] : fill) & 0xFF;
        position++;
        return value;
      }

      @Override
      public int read(byte[] buffer, int offset, int length) {
        Objects.checkFromIndexSize(offset, length, buffer.length);
        if (length == 0) {
          return 0;
        }
        if (position >= totalLength) {
          return -1;
        }
        int count = (int) Math.min(length, totalLength - position);
        int copied = 0;
        if (position < prefix.length) {
          copied = (int) Math.min(count, prefix.length - position);
          System.arraycopy(prefix, (int) position, buffer, offset, copied);
        }
        if (copied < count) {
          Arrays.fill(buffer, offset + copied, offset + count, fill);
        }
        position += count;
        return count;
      }
    };
  }

  private Address parseAddress(String rawAddress) {
    return context.parseAddress(rawAddress);
  }

  private void writeBytes(Address start, byte[] bytes) {
    try {
      context.script().setBytes(start, bytes);
    } catch (MemoryAccessException ex) {
      throw new TransactionExecutionException("unable to write memory: " + ex.getMessage(), ex);
    }
  }
}
