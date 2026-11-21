package app.byteland.ghidra.adapter.ghidra.memory;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.scan.AddressScanRanges;
import app.byteland.ghidra.adapter.ghidra.scan.BoundedAddressScan;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.memory.MemorySearchMatchResource;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.memory.MemoryService.EncodedText;
import app.byteland.ghidra.service.memory.MemoryService.HexPattern;
import app.byteland.ghidra.service.memory.MemoryService.MaskedBytes;
import app.byteland.ghidra.service.memory.MemoryService.MemorySearchQuery;
import app.byteland.ghidra.service.memory.MemoryService.SearchTarget;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;

final class MemorySearchQueries {
  private static final int BASE_CHUNK_BYTES = 16_384;
  private static final byte FULL_MASK = (byte) 0xFF;
  private static final byte ASCII_CASE_MASK = (byte) 0xDF;

  private final GhidraSession context;

  MemorySearchQueries(GhidraSession context) {
    this.context = context;
  }

  Page<MemorySearchMatchResource> searchMemory(MemorySearchQuery query) {
    int normalizedLimit = Page.clampLimit(query.limit());
    CompiledMatcher matcher = compile(query.target());
    Address cursor =
        query.cursor() == null || query.cursor().isBlank()
            ? null
            : context.parseAddress(query.cursor());
    boolean explicitBounds = query.scan().start() != null || query.scan().end() != null;
    AddressScanRanges.Resolved explicitRange =
        explicitBounds ? AddressScanRanges.resolve(context, query.scan(), true) : null;

    List<BlockWindow> windows =
        collectInitializedWindows(explicitRange, cursor, matcher.length());
    String requestedStart =
        explicitRange != null
            ? explicitRange.startText()
            : defaultRequestedBound(context.currentProgram().getMemory().getBlocks(), true);
    String requestedEnd =
        explicitRange != null
            ? explicitRange.endText()
            : defaultRequestedBound(context.currentProgram().getMemory().getBlocks(), false);

    BoundedAddressScan<MemorySearchMatchResource> scan =
        BoundedAddressScan.start(
            normalizedLimit, query.scan().timeoutMs(), requestedStart, requestedEnd);

    int chunkCapacity = Math.max(BASE_CHUNK_BYTES, matcher.length() * 2);
    byte[] buffer = new byte[chunkCapacity];

    for (BlockWindow window : windows) {
      scanBlockWindow(window, matcher, buffer, scan);
      if (scan.stopped()) {
        break;
      }
    }
    return scan.finish();
  }

  private static void scanBlockWindow(
      BlockWindow window,
      CompiledMatcher matcher,
      byte[] buffer,
      BoundedAddressScan<MemorySearchMatchResource> scan) {
    int patternLength = matcher.length();
    long remainingBytes = window.end().subtract(window.start()) + 1L;
    if (remainingBytes < patternLength) {
      String addr = AddressUtil.canonicalAddress(window.start());
      scan.visit(addr, addr, null);
      return;
    }

    Address chunkStart = window.start();
    while (!scan.stopped()) {
      long available = window.end().subtract(chunkStart) + 1L;
      if (available < patternLength) {
        break;
      }
      int toRead = (int) Math.min(buffer.length, available);
      readBlockBytes(window.block(), chunkStart, buffer, toRead);

      int lastMatchOffset = toRead - patternLength;
      int lastVisitedOffset = -1;
      for (int offset = 0; offset <= lastMatchOffset; offset++) {
        if (matcher.matches(buffer, offset)) {
          Address matchAddr = chunkStart.add(offset);
          String canonical = AddressUtil.canonicalAddress(matchAddr);
          byte[] matched = Arrays.copyOfRange(buffer, offset, offset + patternLength);
          MemorySearchMatchResource item =
              new MemorySearchMatchResource(
                  canonical,
                  patternLength,
                  new ByteSequence(
                      ByteSequence.Encoding.HEX,
                      HexFormat.of().formatHex(matched),
                      patternLength),
                  window.block().getName());
          scan.visit(canonical, canonical, item);
          lastVisitedOffset = offset;
          if (scan.stopped()) {
            return;
          }
        }
      }

      if (lastVisitedOffset < lastMatchOffset) {
        Address progressAddr = chunkStart.add(lastMatchOffset);
        String canonical = AddressUtil.canonicalAddress(progressAddr);
        scan.visit(canonical, canonical, null);
        if (scan.stopped()) {
          return;
        }
      }

      if (toRead >= available) {
        break;
      }
      long step = (long) toRead - (patternLength - 1);
      chunkStart = chunkStart.add(step);
    }
  }

  private static void readBlockBytes(
      MemoryBlock block, Address start, byte[] buffer, int length) {
    try {
      int read = block.getBytes(start, buffer, 0, length);
      if (read != length) {
        throw new IllegalArgumentException("short read in memory block: " + block.getName());
      }
    } catch (MemoryAccessException error) {
      throw new IllegalArgumentException(
          "unable to read memory block '" + block.getName() + "': " + error.getMessage(), error);
    }
  }

  private List<BlockWindow> collectInitializedWindows(
      AddressScanRanges.Resolved explicitRange, Address cursor, int patternLength) {
    List<BlockWindow> windows = new ArrayList<>();
    for (MemoryBlock block : context.currentProgram().getMemory().getBlocks()) {
      if (!block.isInitialized()) {
        continue;
      }
      Address start = block.getStart();
      Address end = block.getEnd();
      if (explicitRange != null) {
        if (!start.getAddressSpace().equals(explicitRange.start().getAddressSpace())) {
          continue;
        }
        if (explicitRange.end() != null && start.compareTo(explicitRange.end()) > 0) {
          continue;
        }
        if (end.compareTo(explicitRange.start()) < 0) {
          continue;
        }
        if (start.compareTo(explicitRange.start()) < 0) {
          start = explicitRange.start();
        }
        if (explicitRange.end() != null && end.compareTo(explicitRange.end()) > 0) {
          end = explicitRange.end();
        }
      }
      if (cursor != null) {
        if (end.compareTo(cursor) <= 0) {
          continue;
        }
        if (start.getAddressSpace().equals(cursor.getAddressSpace())
            && start.compareTo(cursor) <= 0) {
          Address afterCursor = cursor.next();
          if (afterCursor == null || afterCursor.compareTo(end) > 0) {
            continue;
          }
          start = afterCursor;
        } else if (start.compareTo(cursor) <= 0) {
          continue;
        }
      }
      if (start.compareTo(end) <= 0 && (end.subtract(start) + 1L) >= patternLength) {
        windows.add(new BlockWindow(block, start, end));
      } else if (start.compareTo(end) <= 0) {
        windows.add(new BlockWindow(block, start, end));
      }
    }
    return windows;
  }

  private String defaultRequestedBound(MemoryBlock[] blocks, boolean first) {
    Address selected = null;
    for (MemoryBlock block : blocks) {
      if (!block.isInitialized()) {
        continue;
      }
      Address candidate = first ? block.getStart() : block.getEnd();
      if (selected == null
          || (first ? candidate.compareTo(selected) < 0 : candidate.compareTo(selected) > 0)) {
        selected = candidate;
      }
    }
    if (selected != null) {
      return AddressUtil.canonicalAddress(selected);
    }
    Address fallback =
        first
            ? context.currentProgram().getMinAddress()
            : context.currentProgram().getMaxAddress();
    return fallback == null ? "0x0" : AddressUtil.canonicalAddress(fallback);
  }

  static CompiledMatcher compile(SearchTarget target) {
    return switch (target) {
      case HexPattern hex -> compileHexPattern(hex.pattern());
      case MaskedBytes masked -> compileMaskedBytes(masked.bytesHex(), masked.maskHex());
      case EncodedText text ->
          compileEncodedText(text.text(), text.encoding(), text.caseSensitive());
    };
  }

  private static CompiledMatcher compileHexPattern(String rawPattern) {
    StringBuilder nibbles = new StringBuilder(rawPattern.length());
    String trimmed = rawPattern.trim();
    int idx = 0;
    while (idx < trimmed.length()) {
      char ch = trimmed.charAt(idx);
      if (Character.isWhitespace(ch) || ch == '_' || ch == '-') {
        idx++;
        continue;
      }
      if (ch == '0'
          && idx + 1 < trimmed.length()
          && (trimmed.charAt(idx + 1) == 'x' || trimmed.charAt(idx + 1) == 'X')) {
        idx += 2;
        continue;
      }
      if (ch == '?' || ch == '.') {
        nibbles.append('?');
      } else if (Character.digit(ch, 16) >= 0) {
        nibbles.append(ch);
      } else {
        throw new IllegalArgumentException("invalid hex pattern character: '" + ch + "'");
      }
      idx++;
    }
    if (nibbles.isEmpty() || (nibbles.length() % 2) != 0) {
      throw new IllegalArgumentException("hex pattern must contain whole bytes");
    }
    int byteCount = nibbles.length() / 2;
    requireValidLength(byteCount);
    byte[] values = new byte[byteCount];
    byte[] masks = new byte[byteCount];
    for (int i = 0; i < byteCount; i++) {
      char hi = nibbles.charAt(i * 2);
      char lo = nibbles.charAt(i * 2 + 1);
      int hiMask = hi == '?' ? 0x00 : 0xF0;
      int hiVal = hi == '?' ? 0x00 : (Character.digit(hi, 16) << 4);
      int loMask = lo == '?' ? 0x00 : 0x0F;
      int loVal = lo == '?' ? 0x00 : Character.digit(lo, 16);
      masks[i] = (byte) (hiMask | loMask);
      values[i] = (byte) (hiVal | loVal);
    }
    return new CompiledMatcher(values, masks, null, null);
  }

  private static CompiledMatcher compileMaskedBytes(String bytesHex, String maskHex) {
    byte[] values = parseCleanHex(bytesHex, "bytes");
    requireValidLength(values.length);
    byte[] masks;
    if (maskHex == null || maskHex.isBlank()) {
      masks = new byte[values.length];
      Arrays.fill(masks, FULL_MASK);
    } else {
      masks = parseCleanHex(maskHex, "mask");
      if (masks.length != values.length) {
        throw new IllegalArgumentException("mask length must match bytes length");
      }
    }
    for (int i = 0; i < values.length; i++) {
      values[i] = (byte) (values[i] & masks[i]);
    }
    return new CompiledMatcher(values, masks, null, null);
  }

  private static CompiledMatcher compileEncodedText(
      String text, String rawEncoding, boolean caseSensitive) {
    Charset charset = resolveCharset(rawEncoding);
    if (StandardCharsets.US_ASCII.equals(charset)) {
      for (int i = 0; i < text.length(); i++) {
        if (text.charAt(i) > 0x7F) {
          throw new IllegalArgumentException("text contains non-ASCII characters");
        }
      }
    }
    byte[] encoded = text.getBytes(charset);
    requireValidLength(encoded.length);
    byte[] masks = new byte[encoded.length];
    Arrays.fill(masks, FULL_MASK);
    if (caseSensitive) {
      return new CompiledMatcher(encoded, masks, null, null);
    }
    boolean pureAscii = text.chars().allMatch(ch -> ch <= 0x7F);
    if (pureAscii) {
      applyAsciiCaseMasks(encoded, masks, charset);
      return new CompiledMatcher(encoded, masks, null, null);
    }
    String foldedTarget = text.toLowerCase(Locale.ROOT);
    byte[] lowerBytes = foldedTarget.getBytes(charset);
    byte[] upperBytes = text.toUpperCase(Locale.ROOT).getBytes(charset);
    if (lowerBytes.length != encoded.length || upperBytes.length != encoded.length) {
      return new CompiledMatcher(encoded, new byte[encoded.length], charset, foldedTarget);
    }
    byte[] values = new byte[encoded.length];
    for (int i = 0; i < encoded.length; i++) {
      int commonMask = ~(lowerBytes[i] ^ upperBytes[i]) & 0xFF;
      masks[i] = (byte) commonMask;
      values[i] = (byte) (lowerBytes[i] & commonMask);
    }
    return new CompiledMatcher(values, masks, charset, foldedTarget);
  }

  private static void applyAsciiCaseMasks(byte[] values, byte[] masks, Charset charset) {
    if (StandardCharsets.UTF_16LE.equals(charset)) {
      for (int i = 0; i + 1 < values.length; i += 2) {
        if (values[i + 1] == 0 && isAsciiLetter(values[i])) {
          masks[i] = ASCII_CASE_MASK;
          values[i] = (byte) (values[i] & ASCII_CASE_MASK);
        }
      }
    } else if (StandardCharsets.UTF_16BE.equals(charset)) {
      for (int i = 0; i + 1 < values.length; i += 2) {
        if (values[i] == 0 && isAsciiLetter(values[i + 1])) {
          masks[i + 1] = ASCII_CASE_MASK;
          values[i + 1] = (byte) (values[i + 1] & ASCII_CASE_MASK);
        }
      }
    } else {
      for (int i = 0; i < values.length; i++) {
        if (isAsciiLetter(values[i])) {
          masks[i] = ASCII_CASE_MASK;
          values[i] = (byte) (values[i] & ASCII_CASE_MASK);
        }
      }
    }
  }

  private static boolean isAsciiLetter(byte b) {
    int ch = b & 0xFF;
    return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z');
  }

  private static Charset resolveCharset(String rawEncoding) {
    String norm = rawEncoding == null ? "utf-8" : rawEncoding.trim().toLowerCase(Locale.ROOT);
    return switch (norm) {
      case "utf-8", "utf8" -> StandardCharsets.UTF_8;
      case "ascii", "us-ascii" -> StandardCharsets.US_ASCII;
      case "utf-16le", "utf16le" -> StandardCharsets.UTF_16LE;
      case "utf-16be", "utf16be" -> StandardCharsets.UTF_16BE;
      default -> throw new IllegalArgumentException("unsupported encoding: " + rawEncoding);
    };
  }

  private static byte[] parseCleanHex(String raw, String fieldName) {
    StringBuilder hex = new StringBuilder(raw.length());
    int idx = 0;
    while (idx < raw.length()) {
      char ch = raw.charAt(idx);
      if (Character.isWhitespace(ch) || ch == '_' || ch == '-') {
        idx++;
        continue;
      }
      if (ch == '0'
          && idx + 1 < raw.length()
          && (raw.charAt(idx + 1) == 'x' || raw.charAt(idx + 1) == 'X')) {
        idx += 2;
        continue;
      }
      hex.append(ch);
      idx++;
    }
    if (hex.isEmpty() || (hex.length() % 2) != 0) {
      throw new IllegalArgumentException(fieldName + " must be a non-empty even-length hex string");
    }
    return HexFormat.of().parseHex(hex.toString());
  }

  private static void requireValidLength(int byteLength) {
    if (byteLength < 1 || byteLength > MemoryService.MAX_SEARCH_PATTERN_BYTES) {
      throw new IllegalArgumentException(
          "search pattern byte length must be in 1.." + MemoryService.MAX_SEARCH_PATTERN_BYTES);
    }
  }

  private record BlockWindow(MemoryBlock block, Address start, Address end) {}

  record CompiledMatcher(
      byte[] values, byte[] masks, Charset unicodeFallbackCharset, String lowerTarget) {
    int length() {
      return values.length;
    }

    boolean matches(byte[] buffer, int offset) {
      for (int i = 0; i < values.length; i++) {
        if ((buffer[offset + i] & masks[i]) != values[i]) {
          return false;
        }
      }
      if (unicodeFallbackCharset != null) {
        String candidate =
            new String(buffer, offset, values.length, unicodeFallbackCharset)
                .toLowerCase(Locale.ROOT);
        return candidate.equals(lowerTarget);
      }
      return true;
    }
  }
}
