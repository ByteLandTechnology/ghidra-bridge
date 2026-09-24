package app.byteland.ghidra.agent;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

final class WebSocketFrames {
  static final int TEXT_OPCODE = 0x1;
  static final int CLOSE_OPCODE = 0x8;
  static final int PING_OPCODE = 0x9;
  static final int PONG_OPCODE = 0xA;

  private static final int FINAL_FRAGMENT_FLAG = 0x80;
  private static final int OPCODE_MASK = 0x0F;
  private static final int MASK_FLAG = 0x80;
  private static final int PAYLOAD_LENGTH_MASK = 0x7F;
  private static final int MAX_INLINE_PAYLOAD_LENGTH = 125;
  private static final int UNSIGNED_SHORT_LENGTH_MARKER = 126;
  private static final int LONG_LENGTH_MARKER = 127;
  private static final int MAX_UNSIGNED_SHORT = 0xFFFF;
  private static final int MASK_KEY_LENGTH = 4;
  private static final int NORMAL_CLOSE_STATUS = 1000;

  private WebSocketFrames() {}

  static Frame readFrame(InputStream input) throws IOException {
    int b1 = input.read();
    int b2 = input.read();
    if (b1 < 0 || b2 < 0) {
      throw new EOFException("EOF while reading frame");
    }
    boolean fin = (b1 & FINAL_FRAGMENT_FLAG) != 0;
    int opcode = b1 & OPCODE_MASK;
    boolean masked = (b2 & MASK_FLAG) != 0;
    long payloadLength = b2 & PAYLOAD_LENGTH_MASK;
    if (payloadLength == UNSIGNED_SHORT_LENGTH_MARKER) {
      payloadLength =
          Short.toUnsignedInt(ByteBuffer.wrap(readFully(input, Short.BYTES)).getShort());
    } else if (payloadLength == LONG_LENGTH_MARKER) {
      payloadLength = ByteBuffer.wrap(readFully(input, Long.BYTES)).getLong();
    }
    if (payloadLength < 0 || payloadLength > Integer.MAX_VALUE) {
      throw new IOException("Unsupported payload length: " + payloadLength);
    }
    if (!masked) {
      throw new IOException("Client frames must be masked");
    }
    byte[] mask = readFully(input, MASK_KEY_LENGTH);
    byte[] payload = readFully(input, (int) payloadLength);
    for (int i = 0; i < payload.length; i++) {
      payload[i] = (byte) (payload[i] ^ mask[i % MASK_KEY_LENGTH]);
    }
    return Frame.fromOwnedPayload(fin, opcode, payload);
  }

  static void writeFrame(OutputStream output, int opcode, byte[] payload) throws IOException {
    int length = payload.length;
    output.write(FINAL_FRAGMENT_FLAG | (opcode & OPCODE_MASK));
    if (length <= MAX_INLINE_PAYLOAD_LENGTH) {
      output.write(length);
    } else if (length <= MAX_UNSIGNED_SHORT) {
      output.write(UNSIGNED_SHORT_LENGTH_MARKER);
      output.write((length >>> 8) & 0xFF);
      output.write(length & 0xFF);
    } else {
      output.write(LONG_LENGTH_MARKER);
      for (int shift = 56; shift >= 0; shift -= 8) {
        output.write((length >>> shift) & 0xFF);
      }
    }
    output.write(payload);
    output.flush();
  }

  static byte[] readFully(InputStream input, int length) throws IOException {
    byte[] data = new byte[length];
    int offset = 0;
    while (offset < length) {
      int read = input.read(data, offset, length - offset);
      if (read < 0) {
        throw new EOFException("Unexpected EOF");
      }
      offset += read;
    }
    return data;
  }

  static int closeStatus(byte[] payload) {
    if (payload.length < Short.BYTES) {
      return NORMAL_CLOSE_STATUS;
    }
    return Short.toUnsignedInt(ByteBuffer.wrap(payload, 0, Short.BYTES).getShort());
  }

  static String closeReason(byte[] payload) {
    if (payload.length <= Short.BYTES) {
      return "closed";
    }
    return new String(payload, Short.BYTES, payload.length - Short.BYTES, StandardCharsets.UTF_8);
  }

  static final class Frame {
    private static final int TO_STRING_PREVIEW_BYTES = 16;
    private static final HexFormat HEX = HexFormat.of();

    private final boolean finalFragment;
    private final int frameOpcode;
    private final byte[] payloadBytes;

    private Frame(boolean fin, int opcode, byte[] payload) {
      this.finalFragment = fin;
      this.frameOpcode = opcode;
      this.payloadBytes = payload;
    }

    static Frame of(boolean fin, int opcode, byte[] payload) {
      return new Frame(fin, opcode, Objects.requireNonNull(payload, "payload").clone());
    }

    private static Frame fromOwnedPayload(boolean fin, int opcode, byte[] payload) {
      return new Frame(fin, opcode, Objects.requireNonNull(payload, "payload"));
    }

    boolean fin() {
      return finalFragment;
    }

    int opcode() {
      return frameOpcode;
    }

    byte[] payload() {
      return payloadBytes.clone();
    }

    @SuppressWarnings("PMD.MethodReturnsInternalArray")
    byte[] payloadView() {
      return payloadBytes;
    }

    @Override
    public boolean equals(Object other) {
      if (this == other) {
        return true;
      }
      if (!(other instanceof Frame frame)) {
        return false;
      }
      return finalFragment == frame.finalFragment
          && frameOpcode == frame.frameOpcode
          && Arrays.equals(payloadBytes, frame.payloadBytes);
    }

    @Override
    public int hashCode() {
      int result = Boolean.hashCode(finalFragment);
      result = 31 * result + frameOpcode;
      return 31 * result + Arrays.hashCode(payloadBytes);
    }

    @Override
    public String toString() {
      int previewLength = Math.min(payloadBytes.length, TO_STRING_PREVIEW_BYTES);
      String suffix = previewLength < payloadBytes.length ? "..." : "";
      return "Frame[fin="
          + finalFragment
          + ", opcode="
          + frameOpcode
          + ", payloadLength="
          + payloadBytes.length
          + ", payloadHex="
          + HEX.formatHex(payloadBytes, 0, previewLength)
          + suffix
          + "]";
    }
  }
}
