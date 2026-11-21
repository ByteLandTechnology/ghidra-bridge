package app.byteland.ghidra.agent;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Objects;

final class WebSocketFrames {
  static final int CONTINUATION_OPCODE = 0x0;
  static final int TEXT_OPCODE = 0x1;
  static final int BINARY_OPCODE = 0x2;
  static final int CLOSE_OPCODE = 0x8;
  static final int PING_OPCODE = 0x9;
  static final int PONG_OPCODE = 0xA;

  static final int NORMAL_CLOSE_STATUS = 1000;
  static final int GOING_AWAY_CLOSE_STATUS = 1001;
  static final int PROTOCOL_ERROR_CLOSE_STATUS = 1002;
  static final int UNSUPPORTED_DATA_CLOSE_STATUS = 1003;
  static final int INVALID_PAYLOAD_CLOSE_STATUS = 1007;
  static final int MESSAGE_TOO_BIG_CLOSE_STATUS = 1009;
  static final int MAX_MESSAGE_BYTES = 16 * 1024 * 1024; // 16 MiB

  private static final int FINAL_FRAGMENT_FLAG = 0x80;
  private static final int RESERVED_BITS_MASK = 0x70;
  private static final int CONTROL_FRAME_FLAG = 0x08;
  private static final int OPCODE_MASK = 0x0F;
  private static final int MASK_FLAG = 0x80;
  private static final int PAYLOAD_LENGTH_MASK = 0x7F;
  private static final int MAX_INLINE_PAYLOAD_LENGTH = 125;
  private static final int UNSIGNED_SHORT_LENGTH_MARKER = 126;
  private static final int LONG_LENGTH_MARKER = 127;
  private static final int MAX_UNSIGNED_SHORT = 0xFFFF;
  private static final int MASK_KEY_LENGTH = 4;
  private static final long MAX_FRAME_PAYLOAD_BYTES = MAX_MESSAGE_BYTES;

  private WebSocketFrames() {}

  static Frame readFrame(InputStream input) throws IOException {
    int b1 = input.read();
    if (b1 < 0) {
      throw new EOFException("EOF while reading frame");
    }
    int b2 = readByteAfterStart(input);
    if ((b1 & RESERVED_BITS_MASK) != 0) {
      throw new WebSocketProtocolException(
          PROTOCOL_ERROR_CLOSE_STATUS, "Reserved WebSocket frame bits set");
    }
    boolean fin = (b1 & FINAL_FRAGMENT_FLAG) != 0;
    int opcode = b1 & OPCODE_MASK;
    if ((opcode >= 0x3 && opcode <= 0x7) || opcode >= 0xB) {
      throw new WebSocketProtocolException(
          PROTOCOL_ERROR_CLOSE_STATUS, "Unsupported WebSocket opcode");
    }
    boolean controlFrame = (opcode & CONTROL_FRAME_FLAG) != 0;
    if (controlFrame && !fin) {
      throw new WebSocketProtocolException(
          PROTOCOL_ERROR_CLOSE_STATUS, "Control frames must not be fragmented");
    }
    boolean masked = (b2 & MASK_FLAG) != 0;
    if (!masked) {
      throw new WebSocketProtocolException(
          PROTOCOL_ERROR_CLOSE_STATUS, "Client frames must be masked");
    }
    long payloadLength = b2 & PAYLOAD_LENGTH_MASK;
    if (controlFrame && payloadLength > MAX_INLINE_PAYLOAD_LENGTH) {
      throw new WebSocketProtocolException(
          PROTOCOL_ERROR_CLOSE_STATUS, "Control frame payload exceeds 125 bytes");
    }
    if (payloadLength == UNSIGNED_SHORT_LENGTH_MARKER) {
      payloadLength =
          Short.toUnsignedInt(ByteBuffer.wrap(readFullyAfterStart(input, Short.BYTES)).getShort());
    } else if (payloadLength == LONG_LENGTH_MARKER) {
      payloadLength = ByteBuffer.wrap(readFullyAfterStart(input, Long.BYTES)).getLong();
    }
    if (payloadLength < 0) {
      throw new WebSocketProtocolException(
          PROTOCOL_ERROR_CLOSE_STATUS, "Invalid WebSocket frame length");
    }
    if (payloadLength > MAX_FRAME_PAYLOAD_BYTES) {
      throw new WebSocketProtocolException(
          MESSAGE_TOO_BIG_CLOSE_STATUS, "Frame payload exceeds 16 MiB limit");
    }
    byte[] mask = readFullyAfterStart(input, MASK_KEY_LENGTH);
    byte[] payload = readFullyAfterStart(input, (int) payloadLength);
    for (int i = 0; i < payload.length; i++) {
      payload[i] = (byte) (payload[i] ^ mask[i % MASK_KEY_LENGTH]);
    }
    if (opcode == CLOSE_OPCODE && payload.length == 1) {
      throw new WebSocketProtocolException(
          PROTOCOL_ERROR_CLOSE_STATUS, "Invalid close frame payload");
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

  private static int readByteAfterStart(InputStream input) throws IOException {
    try {
      int value = input.read();
      if (value < 0) {
        throw new EOFException("EOF while reading frame");
      }
      return value;
    } catch (SocketTimeoutException timeout) {
      throw new IOException("Timed out reading partial WebSocket frame", timeout);
    }
  }

  private static byte[] readFullyAfterStart(InputStream input, int length) throws IOException {
    try {
      return readFully(input, length);
    } catch (SocketTimeoutException timeout) {
      throw new IOException("Timed out reading partial WebSocket frame", timeout);
    }
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

  static String decodeUtf8(byte[] payload) throws WebSocketProtocolException {
    return decodeUtf8(payload, 0, payload.length);
  }

  static String decodeUtf8(byte[] payload, int offset, int length)
      throws WebSocketProtocolException {
    try {
      return StandardCharsets.UTF_8
          .newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(payload, offset, length))
          .toString();
    } catch (CharacterCodingException invalidUtf8) {
      throw new WebSocketProtocolException(
          INVALID_PAYLOAD_CLOSE_STATUS, "Invalid UTF-8 text", invalidUtf8);
    }
  }

  static CloseInfo parseClosePayload(byte[] payload) throws WebSocketProtocolException {
    if (payload.length == 0) {
      return new CloseInfo(NORMAL_CLOSE_STATUS, "closed");
    }
    if (payload.length == 1) {
      throw new WebSocketProtocolException(
          PROTOCOL_ERROR_CLOSE_STATUS, "Invalid close frame payload");
    }
    int code = Short.toUnsignedInt(ByteBuffer.wrap(payload, 0, Short.BYTES).getShort());
    if (!isValidWireCloseCode(code)) {
      throw new WebSocketProtocolException(
          PROTOCOL_ERROR_CLOSE_STATUS, "Invalid close status code");
    }
    String reason =
        payload.length == Short.BYTES
            ? "closed"
            : decodeUtf8(payload, Short.BYTES, payload.length - Short.BYTES);
    return new CloseInfo(code, reason);
  }

  private static boolean isValidWireCloseCode(int code) {
    return (code >= 1000 && code <= 1003)
        || (code >= 1007 && code <= 1014)
        || (code >= 3000 && code <= 4999);
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

  record CloseInfo(int code, String reason) {}

  static final class WebSocketProtocolException extends IOException {
    private static final long serialVersionUID = 1L;
    private final int statusCode;

    WebSocketProtocolException(int closeCode, String reason) {
      super(reason);
      this.statusCode = closeCode;
    }

    WebSocketProtocolException(int closeCode, String reason, Throwable cause) {
      super(reason, cause);
      this.statusCode = closeCode;
    }

    int closeCode() {
      return statusCode;
    }
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
