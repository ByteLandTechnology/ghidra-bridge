package app.byteland.ghidra.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class WebSocketSecurityTest {

  @Test
  @DisplayName("WebSocket server rejects unauthenticated and DNS-rebound upgrades before opening a session")
  void websocketServerRejectsUnauthenticatedAndRebindUpgrades() throws Exception {
    int port = findFreePort();
    String token = "ws-test-secret-token-value";
    AgentConfig config = new AgentConfig(null, "127.0.0.1", port, "/ws/agent", token, "demo", null);
    AtomicInteger openedSessions = new AtomicInteger();
    CountDownLatch openLatch = new CountDownLatch(1);

    AgentWebSocketServer.Handler handler =
        new AgentWebSocketServer.Handler() {
          @Override
          public void onOpen(AgentWebSocketServer.Connection connection) {
            openedSessions.incrementAndGet();
            openLatch.countDown();
          }

          @Override
          public void onText(AgentWebSocketServer.Connection connection, String message) {}

          @Override
          public void onClose(
              AgentWebSocketServer.Connection connection, int statusCode, String reason) {}

          @Override
          public void onConnectionError(
              AgentWebSocketServer.Connection connection, Throwable error) {}

          @Override
          public void onServerError(Throwable error) {}
        };

    try (AgentWebSocketServer server = new AgentWebSocketServer(config, handler)) {
      server.start();

      // 1. Exact task verification probe (unauthenticated, Host: rebind.example.invalid:<wsPort>) -> 401
      WsHandshakeReply unauthProbe =
          sendUpgradeRequest(
              port,
              "GET /ws/agent HTTP/1.1\r\n"
                  + "Host: rebind.example.invalid:"
                  + port
                  + "\r\n"
                  + "Upgrade: websocket\r\n"
                  + "Connection: Upgrade\r\n"
                  + "Sec-WebSocket-Version: 13\r\n\r\n");
      assertEquals(401, unauthProbe.statusCode());
      assertFalse(unauthProbe.rawResponse().contains(token));

      // 2. Defense-in-depth: valid Authorization header with rebound Host -> 403
      WsHandshakeReply authedRebind =
          sendUpgradeRequest(
              port,
              "GET /ws/agent HTTP/1.1\r\n"
                  + "Host: rebind.example.invalid:"
                  + port
                  + "\r\n"
                  + "Authorization: Bearer "
                  + token
                  + "\r\n"
                  + "Upgrade: websocket\r\n"
                  + "Connection: Upgrade\r\n"
                  + "Sec-WebSocket-Version: 13\r\n"
                  + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n");
      assertEquals(403, authedRebind.statusCode());

      // 3. Duplicate Host header smuggling attempt -> 400
      WsHandshakeReply duplicateHost =
          sendUpgradeRequest(
              port,
              "GET /ws/agent HTTP/1.1\r\n"
                  + "Host: rebind.example.invalid:"
                  + port
                  + "\r\n"
                  + "Host: 127.0.0.1:"
                  + port
                  + "\r\n"
                  + "Authorization: Bearer "
                  + token
                  + "\r\n"
                  + "Upgrade: websocket\r\n"
                  + "Connection: Upgrade\r\n"
                  + "Sec-WebSocket-Version: 13\r\n"
                  + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n");
      assertEquals(400, duplicateHost.statusCode());

      assertEquals(0, openedSessions.get(), "No rejected handshake may open a WebSocket session");

      // 4. Valid authenticated local upgrade succeeds -> 101 Switching Protocols
      try (Socket validSocket = new Socket("127.0.0.1", port)) {
        validSocket.setSoTimeout(5000);
        OutputStream out = validSocket.getOutputStream();
        out.write(
            ("GET /ws/agent HTTP/1.1\r\n"
                    + "Host: 127.0.0.1:"
                    + port
                    + "\r\n"
                    + "Authorization: Bearer "
                    + token
                    + "\r\n"
                    + "Upgrade: websocket\r\n"
                    + "Connection: Upgrade\r\n"
                    + "Sec-WebSocket-Version: 13\r\n"
                    + "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
                .getBytes(StandardCharsets.US_ASCII));
        out.flush();
        BufferedReader reader =
            new BufferedReader(
                new InputStreamReader(validSocket.getInputStream(), StandardCharsets.US_ASCII));
        String statusLine = reader.readLine();
        assertTrue(statusLine != null && statusLine.startsWith("HTTP/1.1 101"));
        assertTrue(openLatch.await(5, TimeUnit.SECONDS));
        assertEquals(1, openedSessions.get());
      }
    }
  }

  private static int findFreePort() throws IOException {
    try (ServerSocket socket = new ServerSocket(0)) {
      return socket.getLocalPort();
    }
  }

  private static WsHandshakeReply sendUpgradeRequest(int port, String rawRequest)
      throws IOException {
    try (Socket socket = new Socket("127.0.0.1", port)) {
      socket.setSoTimeout(5000);
      OutputStream out = socket.getOutputStream();
      out.write(rawRequest.getBytes(StandardCharsets.US_ASCII));
      out.flush();
      String response = new String(socket.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
      String statusLine = response.split("\r\n", 2)[0];
      int statusCode = Integer.parseInt(statusLine.split(" ")[1]);
      return new WsHandshakeReply(statusCode, response);
    }
  }

  private record WsHandshakeReply(int statusCode, String rawResponse) {}
}
