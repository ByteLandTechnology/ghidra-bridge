package app.byteland.ghidra.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.BindException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import org.junit.jupiter.api.Test;

class AgentWebSocketServerPortFallbackTest {

  private static AgentWebSocketServer.Handler noopHandler() {
    return new AgentWebSocketServer.Handler() {
      @Override
      public void onOpen(AgentWebSocketServer.Connection connection) {}

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
  }

  @Test
  void incrementsLoopbackPortWhenBasePortIsOccupied() throws Exception {
    try (ServerSocket occupied = new ServerSocket()) {
      occupied.bind(new InetSocketAddress("127.0.0.1", 0));
      int busyPort = occupied.getLocalPort();
      AgentConfig config =
          new AgentConfig(null, "127.0.0.1", busyPort, "/ws/agent", null, "ws-fallback", null);

      try (AgentWebSocketServer server =
          new AgentWebSocketServer(config, noopHandler(), true)) {
        server.start();
        assertTrue(server.port() > busyPort);
        assertEquals("ws://127.0.0.1:" + server.port() + "/ws/agent", server.listenUri());
      }
    }
  }

  @Test
  void failsWithBindExceptionWhenFallbackDisabled() throws Exception {
    try (ServerSocket occupied = new ServerSocket()) {
      occupied.bind(new InetSocketAddress("127.0.0.1", 0));
      int busyPort = occupied.getLocalPort();
      AgentConfig config =
          new AgentConfig(null, "127.0.0.1", busyPort, "/ws/agent", null, "ws-strict", null);

      try (AgentWebSocketServer server =
          new AgentWebSocketServer(config, noopHandler(), false)) {
        assertThrows(BindException.class, server::start);
      }
    }
  }
}
