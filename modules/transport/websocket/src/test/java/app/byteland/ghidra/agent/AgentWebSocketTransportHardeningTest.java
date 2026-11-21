package app.byteland.ghidra.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Modifier;
import java.net.BindException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class AgentWebSocketTransportHardeningTest {
  private static final byte[] CLIENT_MASK = new byte[] {0x12, 0x34, 0x56, 0x78};

  @Test
  void rejectsExternalOriginAndForgedHostDuringHandshake() throws Exception {
    RecordingHandler handler = new RecordingHandler();
    try (ServerHandle handle = startServer(handler, Duration.ofSeconds(5), Duration.ofSeconds(10))) {
      int port = handle.port();

      HttpStatus forbiddenOrigin =
          rawHandshake(
              port,
              List.of(
                  "Host: 127.0.0.1:" + port,
                  "Origin: https://evil.example",
                  "Upgrade: websocket",
                  "Connection: Upgrade",
                  "Sec-WebSocket-Version: 13",
                  "Sec-WebSocket-Key: " + sampleKey()));
      assertEquals(403, forbiddenOrigin.code());

      HttpStatus forgedHost =
          rawHandshake(
              port,
              List.of(
                  "Host: evil.rebind.example",
                  "Upgrade: websocket",
                  "Connection: Upgrade",
                  "Sec-WebSocket-Version: 13",
                  "Sec-WebSocket-Key: " + sampleKey()));
      assertEquals(403, forgedHost.code());

      HttpStatus duplicateHost =
          rawHandshake(
              port,
              List.of(
                  "Host: 127.0.0.1:" + port,
                  "Host: evil.rebind.example",
                  "Upgrade: websocket",
                  "Connection: Upgrade",
                  "Sec-WebSocket-Version: 13",
                  "Sec-WebSocket-Key: " + sampleKey()));
      assertEquals(403, duplicateHost.code());

      HttpStatus wrongPortHost =
          rawHandshake(
              port,
              List.of(
                  "Host: 127.0.0.1:" + (port == 65535 ? port - 1 : port + 1),
                  "Upgrade: websocket",
                  "Connection: Upgrade",
                  "Sec-WebSocket-Version: 13",
                  "Sec-WebSocket-Key: " + sampleKey()));
      assertEquals(403, wrongPortHost.code());

      try (RawWebSocketClient valid =
          connectUpgraded(port, List.of("Origin: http://localhost:3000"))) {
        assertEquals(101, valid.handshakeStatus());
      }
    }
  }

  @Test
  void reassemblesFragmentedUtf8TextWithInterleavedPingAndPong() throws Exception {
    RecordingHandler handler = new RecordingHandler();
    try (ServerHandle handle = startServer(handler, Duration.ofSeconds(5), Duration.ofSeconds(10));
        RawWebSocketClient client = connectUpgraded(handle.port(), List.of())) {
      String message = "{\"jsonrpc\":\"2.0\",\"id\":1,\"text\":\"🚀こんにちは世界\"}";
      byte[] utf8 = message.getBytes(StandardCharsets.UTF_8);
      int rocketIndex = message.indexOf("🚀");
      int split1 = message.substring(0, rocketIndex).getBytes(StandardCharsets.UTF_8).length + 2;
      int split2 = split1 + 5;

      client.writeMaskedFrame(
          false, WebSocketFrames.TEXT_OPCODE, Arrays.copyOfRange(utf8, 0, split1));
      client.writeMaskedFrame(
          true, WebSocketFrames.PING_OPCODE, "hb".getBytes(StandardCharsets.UTF_8));

      ServerFrame pong = client.readServerFrame();
      assertEquals(WebSocketFrames.PONG_OPCODE, pong.opcode());
      assertEquals("hb", new String(pong.payload(), StandardCharsets.UTF_8));

      client.writeMaskedFrame(
          false, WebSocketFrames.CONTINUATION_OPCODE, Arrays.copyOfRange(utf8, split1, split2));
      client.writeMaskedFrame(
          true,
          WebSocketFrames.CONTINUATION_OPCODE,
          Arrays.copyOfRange(utf8, split2, utf8.length));

      String received = handler.receivedTexts.poll(5, TimeUnit.SECONDS);
      assertEquals(message, received);
    }
  }

  @Test
  void closesOversizedMessagesWith1009() throws Exception {
    int nineMiB = 9 * 1024 * 1024;
    int eightMiB = 8 * 1024 * 1024;
    byte[] firstPart = new byte[nineMiB];
    Arrays.fill(firstPart, (byte) 'a');
    byte[] secondPart = new byte[eightMiB];
    Arrays.fill(secondPart, (byte) 'b');

    RecordingHandler fragmentedHandler = new RecordingHandler();
    try (ServerHandle handle =
            startServer(fragmentedHandler, Duration.ofSeconds(5), Duration.ofSeconds(10));
        RawWebSocketClient client = connectUpgraded(handle.port(), List.of())) {
      client.writeMaskedFrame(false, WebSocketFrames.TEXT_OPCODE, firstPart);
      client.writeMaskedFrame(true, WebSocketFrames.CONTINUATION_OPCODE, secondPart);

      ServerFrame closeFrame = client.readUntilOpcode(WebSocketFrames.CLOSE_OPCODE);
      assertEquals(1009, WebSocketFrames.closeStatus(closeFrame.payload()));
      assertEquals(1009, fragmentedHandler.awaitCloseCode());
    }

    RecordingHandler singleFrameHandler = new RecordingHandler();
    try (ServerHandle handle =
            startServer(singleFrameHandler, Duration.ofSeconds(5), Duration.ofSeconds(10));
        RawWebSocketClient client = connectUpgraded(handle.port(), List.of())) {
      client.writeOversizedHeaderOnly(WebSocketFrames.MAX_MESSAGE_BYTES + 1L);
      ServerFrame closeFrame = client.readUntilOpcode(WebSocketFrames.CLOSE_OPCODE);
      assertEquals(1009, WebSocketFrames.closeStatus(closeFrame.payload()));
      assertEquals(1009, singleFrameHandler.awaitCloseCode());
    }
  }

  @Test
  void closesFramingErrorsWith1002BinaryWith1003AndInvalidUtf8With1007() throws Exception {
    assertCloseStatusForClientAction(
        1002,
        client ->
            client.writeMaskedFrame(
                true,
                WebSocketFrames.CONTINUATION_OPCODE,
                "orphan".getBytes(StandardCharsets.UTF_8)));

    assertCloseStatusForClientAction(
        1002,
        client -> {
          client.writeMaskedFrame(
              false, WebSocketFrames.TEXT_OPCODE, "part1".getBytes(StandardCharsets.UTF_8));
          client.writeMaskedFrame(
              true, WebSocketFrames.TEXT_OPCODE, "part2".getBytes(StandardCharsets.UTF_8));
        });

    assertCloseStatusForClientAction(
        1002,
        client ->
            client.writeUnmaskedFrame(
                true, WebSocketFrames.TEXT_OPCODE, "plain".getBytes(StandardCharsets.UTF_8)));

    assertCloseStatusForClientAction(
        1002,
        client ->
            client.writeMaskedFrame(
                false, WebSocketFrames.PING_OPCODE, "bad".getBytes(StandardCharsets.UTF_8)));

    assertCloseStatusForClientAction(
        1002, client -> client.writeReservedBitsFrame("rsv".getBytes(StandardCharsets.UTF_8)));

    assertCloseStatusForClientAction(
        1003,
        client -> client.writeMaskedFrame(true, WebSocketFrames.BINARY_OPCODE, new byte[] {1, 2}));

    assertCloseStatusForClientAction(
        1007,
        client ->
            client.writeMaskedFrame(
                true, WebSocketFrames.TEXT_OPCODE, new byte[] {(byte) 0xFF, (byte) 0xFE}));
  }

  @Test
  void reclaimsHalfOpenConnectionSlotAfterKeepaliveTimeoutAndPreservesResponsiveClient()
      throws Exception {
    assertTrue(
        !Modifier.isPublic(
            AgentWebSocketServer.class
                .getDeclaredConstructor(
                    AgentConfig.class,
                    AgentWebSocketServer.Handler.class,
                    Duration.class,
                    Duration.class)
                .getModifiers()));

    RecordingHandler handler = new RecordingHandler();
    try (ServerHandle handle =
        startServer(handler, Duration.ofMillis(80), Duration.ofMillis(160))) {
      int port = handle.port();

      try (RawWebSocketClient silentClient = connectUpgraded(port, List.of())) {
        HttpStatus conflictWhileActive =
            rawHandshake(
                port,
                List.of(
                    "Host: 127.0.0.1:" + port,
                    "Upgrade: websocket",
                    "Connection: Upgrade",
                    "Sec-WebSocket-Version: 13",
                    "Sec-WebSocket-Key: " + sampleKey()));
        assertEquals(409, conflictWhileActive.code());

        ServerFrame pingFrame = silentClient.readServerFrame();
        assertEquals(WebSocketFrames.PING_OPCODE, pingFrame.opcode());

        ServerFrame closeFrame = silentClient.readUntilOpcode(WebSocketFrames.CLOSE_OPCODE);
        assertEquals(1001, WebSocketFrames.closeStatus(closeFrame.payload()));
        assertEquals(1001, handler.awaitCloseCode());
      }

      try (RawWebSocketClient healthyClient = connectUpgraded(port, List.of())) {
        assertEquals(101, healthyClient.handshakeStatus());
        for (int i = 0; i < 2; i++) {
          ServerFrame ping = healthyClient.readServerFrame();
          assertEquals(WebSocketFrames.PING_OPCODE, ping.opcode());
          healthyClient.writeMaskedFrame(true, WebSocketFrames.PONG_OPCODE, ping.payload());
        }
        healthyClient.writeMaskedFrame(
            true, WebSocketFrames.TEXT_OPCODE, "still-alive".getBytes(StandardCharsets.UTF_8));
        assertEquals("still-alive", handler.receivedTexts.poll(5, TimeUnit.SECONDS));
      }
    }
  }

  private static void assertCloseStatusForClientAction(
      int expectedStatus, ClientAction clientAction) throws Exception {
    RecordingHandler handler = new RecordingHandler();
    try (ServerHandle handle = startServer(handler, Duration.ofSeconds(5), Duration.ofSeconds(10));
        RawWebSocketClient client = connectUpgraded(handle.port(), List.of())) {
      clientAction.run(client);
      ServerFrame closeFrame = client.readUntilOpcode(WebSocketFrames.CLOSE_OPCODE);
      assertEquals(expectedStatus, WebSocketFrames.closeStatus(closeFrame.payload()));
      assertEquals(expectedStatus, handler.awaitCloseCode());
    }
  }

  private static ServerHandle startServer(
      RecordingHandler handler, Duration keepaliveInterval, Duration pongTimeout)
      throws IOException {
    for (int attempt = 0; attempt < 10; attempt++) {
      int port = freePort();
      AgentConfig config =
          new AgentConfig(null, "127.0.0.1", port, "/ws/agent", null, "test-session", null);
      AgentWebSocketServer server =
          new AgentWebSocketServer(config, handler, keepaliveInterval, pongTimeout);
      try {
        server.start();
        return new ServerHandle(server, port);
      } catch (BindException retry) {
        server.close();
      }
    }
    throw new IOException("Unable to bind test WebSocket server");
  }

  private static int freePort() throws IOException {
    try (ServerSocket socket = new ServerSocket(0)) {
      return socket.getLocalPort();
    }
  }

  private static String sampleKey() {
    return Base64.getEncoder().encodeToString("0123456789abcdef".getBytes(StandardCharsets.UTF_8));
  }

  private static HttpStatus rawHandshake(int port, List<String> headers) throws IOException {
    try (Socket socket = new Socket("127.0.0.1", port)) {
      socket.setSoTimeout(5_000);
      writeUpgradeRequest(socket.getOutputStream(), headers);
      return readHttpHeaders(socket.getInputStream());
    }
  }

  private static RawWebSocketClient connectUpgraded(int port, List<String> extraHeaders)
      throws IOException {
    Socket socket = new Socket("127.0.0.1", port);
    socket.setSoTimeout(5_000);
    List<String> headers = new ArrayList<>();
    headers.add("Host: 127.0.0.1:" + port);
    headers.add("Upgrade: websocket");
    headers.add("Connection: Upgrade");
    headers.add("Sec-WebSocket-Version: 13");
    headers.add("Sec-WebSocket-Key: " + sampleKey());
    headers.addAll(extraHeaders);
    writeUpgradeRequest(socket.getOutputStream(), headers);
    InputStream input = new BufferedInputStream(socket.getInputStream());
    HttpStatus status = readHttpHeaders(input);
    assertEquals(101, status.code());
    return new RawWebSocketClient(socket, input, socket.getOutputStream(), status.code());
  }

  private static void writeUpgradeRequest(OutputStream output, List<String> headers)
      throws IOException {
    StringBuilder builder = new StringBuilder();
    builder.append("GET /ws/agent HTTP/1.1\r\n");
    for (String header : headers) {
      builder.append(header).append("\r\n");
    }
    builder.append("\r\n");
    output.write(builder.toString().getBytes(StandardCharsets.US_ASCII));
    output.flush();
  }

  private static HttpStatus readHttpHeaders(InputStream input) throws IOException {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    int state = 0;
    while (state < 4) {
      int b = input.read();
      if (b < 0) {
        break;
      }
      buffer.write(b);
      state =
          switch (state) {
            case 0 -> b == '\r' ? 1 : 0;
            case 1 -> b == '\n' ? 2 : 0;
            case 2 -> b == '\r' ? 3 : 0;
            case 3 -> b == '\n' ? 4 : 0;
            default -> state;
          };
    }
    String text = buffer.toString(StandardCharsets.US_ASCII);
    String firstLine = text.split("\r\n", 2)[0];
    String[] parts = firstLine.split(" ", 3);
    return new HttpStatus(Integer.parseInt(parts[1]), text);
  }

  @FunctionalInterface
  private interface ClientAction {
    void run(RawWebSocketClient client) throws IOException;
  }

  private record HttpStatus(int code, String rawHeaders) {}

  private record ServerFrame(boolean fin, int opcode, byte[] payload) {}

  private record ServerHandle(AgentWebSocketServer server, int port) implements AutoCloseable {
    @Override
    public void close() {
      server.close();
    }
  }

  private static final class RawWebSocketClient implements AutoCloseable {
    private final Socket socket;
    private final InputStream input;
    private final OutputStream output;
    private final int status;

    private RawWebSocketClient(
        Socket socket, InputStream input, OutputStream output, int handshakeStatus) {
      this.socket = socket;
      this.input = input;
      this.output = output;
      this.status = handshakeStatus;
    }

    int handshakeStatus() {
      return status;
    }

    void writeMaskedFrame(boolean fin, int opcode, byte[] payload) throws IOException {
      int firstByte = (fin ? 0x80 : 0x00) | (opcode & 0x0F);
      output.write(firstByte);
      writeMaskedLengthAndPayload(payload);
    }

    void writeReservedBitsFrame(byte[] payload) throws IOException {
      output.write(0x80 | 0x40 | WebSocketFrames.TEXT_OPCODE);
      writeMaskedLengthAndPayload(payload);
    }

    void writeUnmaskedFrame(boolean fin, int opcode, byte[] payload) throws IOException {
      output.write((fin ? 0x80 : 0x00) | (opcode & 0x0F));
      output.write(payload.length);
      output.write(payload);
      output.flush();
    }

    void writeOversizedHeaderOnly(long declaredLength) throws IOException {
      output.write(0x80 | WebSocketFrames.TEXT_OPCODE);
      output.write(0x80 | 127);
      ByteBuffer lengthBytes = ByteBuffer.allocate(Long.BYTES).putLong(declaredLength);
      output.write(lengthBytes.array());
      output.flush();
    }

    private void writeMaskedLengthAndPayload(byte[] payload) throws IOException {
      int length = payload.length;
      if (length <= 125) {
        output.write(0x80 | length);
      } else if (length <= 0xFFFF) {
        output.write(0x80 | 126);
        output.write((length >>> 8) & 0xFF);
        output.write(length & 0xFF);
      } else {
        output.write(0x80 | 127);
        ByteBuffer lengthBytes = ByteBuffer.allocate(Long.BYTES).putLong(length);
        output.write(lengthBytes.array());
      }
      output.write(CLIENT_MASK);
      byte[] masked = new byte[length];
      for (int i = 0; i < length; i++) {
        masked[i] = (byte) (payload[i] ^ CLIENT_MASK[i % CLIENT_MASK.length]);
      }
      output.write(masked);
      output.flush();
    }

    ServerFrame readServerFrame() throws IOException {
      int b1 = input.read();
      int b2 = input.read();
      if (b1 < 0 || b2 < 0) {
        throw new IOException("EOF reading server frame");
      }
      boolean fin = (b1 & 0x80) != 0;
      int opcode = b1 & 0x0F;
      int length = b2 & 0x7F;
      if (length == 126) {
        byte[] ext = input.readNBytes(2);
        length = Short.toUnsignedInt(ByteBuffer.wrap(ext).getShort());
      } else if (length == 127) {
        byte[] ext = input.readNBytes(8);
        length = (int) ByteBuffer.wrap(ext).getLong();
      }
      byte[] payload = input.readNBytes(length);
      return new ServerFrame(fin, opcode, payload);
    }

    ServerFrame readUntilOpcode(int expectedOpcode) throws IOException {
      while (true) {
        ServerFrame frame = readServerFrame();
        if (frame.opcode() == expectedOpcode) {
          return frame;
        }
      }
    }

    @Override
    public void close() throws IOException {
      socket.close();
    }
  }

  private static final class RecordingHandler implements AgentWebSocketServer.Handler {
    private final BlockingQueue<String> receivedTexts = new LinkedBlockingQueue<>();
    private final AtomicInteger lastCloseCode = new AtomicInteger(-1);
    private volatile CountDownLatch closeLatch = new CountDownLatch(1);

    @Override
    public void onOpen(AgentWebSocketServer.Connection connection) {
      closeLatch = new CountDownLatch(1);
    }

    @Override
    public void onText(AgentWebSocketServer.Connection connection, String message) {
      receivedTexts.add(message);
    }

    @Override
    public void onClose(
        AgentWebSocketServer.Connection connection, int statusCode, String reason) {
      lastCloseCode.set(statusCode);
      closeLatch.countDown();
    }

    @Override
    public void onConnectionError(AgentWebSocketServer.Connection connection, Throwable error) {}

    @Override
    public void onServerError(Throwable error) {}

    int awaitCloseCode() throws InterruptedException {
      assertTrue(closeLatch.await(5, TimeUnit.SECONDS), "Timed out waiting for onClose");
      return lastCloseCode.get();
    }
  }
}
