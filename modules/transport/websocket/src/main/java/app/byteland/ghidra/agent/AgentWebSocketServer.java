package app.byteland.ghidra.agent;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.LockSupport;

/**
 * Embedded WebSocket server for inbound JSON-RPC 2.0 connections.
 */
public final class AgentWebSocketServer implements AutoCloseable {
  public static final String DEFAULT_PATH = "/ws/agent";
  private static final int SERVER_SHUTDOWN_CLOSE_CODE = 1001;
  private static final int PENDING_CLOSE_DRAIN_TIMEOUT_MILLIS = 50;
  private static final int MAX_PENDING_DRAIN_BYTES = 64 * 1024;
  private static final long RUNNER_DRAIN_WAIT_NANOS = TimeUnit.MILLISECONDS.toNanos(500);
  static final Duration DEFAULT_HANDSHAKE_TIMEOUT = Duration.ofSeconds(10);
  static final int DEFAULT_MAX_PENDING_SOCKETS = 16;

  private final AgentConfig config;
  private final Handler handler;
  private final Duration handshakeTimeout;
  private final AtomicBoolean running = new AtomicBoolean(false);
  private final AtomicReference<AgentServerConnection> activeConnection = new AtomicReference<>();
  private final PendingSockets pendingSockets;
  private ServerSocket serverSocket;

  public AgentWebSocketServer(AgentConfig config, Handler handler) {
    this(config, handler, DEFAULT_HANDSHAKE_TIMEOUT, DEFAULT_MAX_PENDING_SOCKETS);
  }

  AgentWebSocketServer(
      AgentConfig config, Handler handler, Duration handshakeTimeout, int maxPendingSockets) {
    this.config = Objects.requireNonNull(config, "config");
    this.handler = Objects.requireNonNull(handler, "handler");
    Objects.requireNonNull(handshakeTimeout, "handshakeTimeout");
    if (handshakeTimeout.isZero() || handshakeTimeout.isNegative()) {
      throw new IllegalArgumentException("handshakeTimeout must be positive");
    }
    if (maxPendingSockets < 1) {
      throw new IllegalArgumentException("maxPendingSockets must be positive");
    }
    this.handshakeTimeout = handshakeTimeout;
    this.pendingSockets = new PendingSockets(running, maxPendingSockets);
  }

  public void start() throws IOException {
    if (!running.compareAndSet(false, true)) {
      return;
    }
    ServerSocket socket = new ServerSocket();
    try {
      socket.bind(new InetSocketAddress(config.host(), config.port()));
      AgentWebSocketConnectionRunner connectionRunner =
          new AgentWebSocketConnectionRunner(
              config, handler, running, activeConnection, pendingSockets, handshakeTimeout);
      AgentWebSocketAcceptor acceptor =
          new AgentWebSocketAcceptor(socket, handler, running, pendingSockets, connectionRunner);
      Thread thread = new Thread(acceptor, "agent-ws-server");
      thread.setDaemon(true);
      serverSocket = socket;
      thread.start();
    } catch (IOException | RuntimeException startFailure) {
      running.set(false);
      closeAfterFailedStart(socket, startFailure);
      throw startFailure;
    }
  }

  private static void closeAfterFailedStart(ServerSocket socket, Throwable startFailure) {
    try {
      socket.close();
    } catch (IOException closeFailure) {
      if (closeFailure != startFailure) {
        startFailure.addSuppressed(closeFailure);
      }
    }
  }

  @Override
  public void close() {
    running.set(false);
    ServerSocket socket = serverSocket;
    if (socket != null && !socket.isClosed()) {
      try {
        socket.close();
      } catch (IOException failure) {
        handler.onServerError(failure);
      }
    }
    AgentServerConnection connection = activeConnection.getAndSet(null);
    if (connection != null) {
      try {
        connection.close(SERVER_SHUTDOWN_CLOSE_CODE, "server shutdown");
      } catch (RuntimeException failure) {
        handler.onConnectionError(connection, failure);
      }
    }
    List<Socket> runnerOwned = new ArrayList<>();
    for (DrainedSocket drained : pendingSockets.drain()) {
      if (drained.claimedByRunner()) {
        runnerOwned.add(drained.socket());
      } else {
        drainUnclaimedAndClose(drained.socket());
      }
    }
    awaitRunnerDrainAndClose(runnerOwned);
  }

  private void drainUnclaimedAndClose(Socket pending) {
    if (pending.isClosed()) {
      return;
    }
    try {
      if (!pending.isInputShutdown()) {
        pending.setSoTimeout(PENDING_CLOSE_DRAIN_TIMEOUT_MILLIS);
        InputStream input = pending.getInputStream();
        byte[] discard = new byte[1024];
        int drained = 0;
        int available = input.available();
        while (available > 0 && drained < MAX_PENDING_DRAIN_BYTES) {
          int step =
              Math.min(discard.length, Math.min(available, MAX_PENDING_DRAIN_BYTES - drained));
          int read = input.read(discard, 0, step);
          if (read <= 0) {
            break;
          }
          drained += read;
          available = input.available();
        }
      }
    } catch (IOException ignored) {
      // Ignore read errors when the server closes a socket.
    }
    closePendingSocketQuietly(pending);
  }

  private void awaitRunnerDrainAndClose(List<Socket> runnerSockets) {
    if (runnerSockets.isEmpty()) {
      return;
    }
    List<Socket> remaining = new ArrayList<>(runnerSockets);
    long deadlineNanos = System.nanoTime() + RUNNER_DRAIN_WAIT_NANOS;
    while (!remaining.isEmpty()) {
      Iterator<Socket> iterator = remaining.iterator();
      while (iterator.hasNext()) {
        Socket pending = iterator.next();
        if (isReadyToCloseWithoutReset(pending)) {
          closePendingSocketQuietly(pending);
          iterator.remove();
        }
      }
      if (remaining.isEmpty() || System.nanoTime() - deadlineNanos >= 0) {
        break;
      }
      LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(1));
      if (Thread.currentThread().isInterrupted()) {
        break;
      }
    }
    for (Socket pending : remaining) {
      closePendingSocketQuietly(pending);
    }
  }

  private static boolean isReadyToCloseWithoutReset(Socket pending) {
    if (pending.isClosed() || pending.isInputShutdown()) {
      return true;
    }
    try {
      return pending.getInputStream().available() == 0;
    } catch (IOException ignored) {
      return true;
    }
  }

  private void closePendingSocketQuietly(Socket pending) {
    if (pending.isClosed()) {
      return;
    }
    try {
      pending.close();
    } catch (IOException failure) {
      handler.onConnectionError(null, failure);
    }
  }

  record DrainedSocket(Socket socket, boolean claimedByRunner) {}

  static final class PendingSockets {
    private final Object lock = new Object();
    private final AtomicBoolean running;
    private final int maxSockets;
    private final Map<Socket, Boolean> sockets = new LinkedHashMap<>();
    private final Set<Socket> closedBeforeRead =
        Collections.newSetFromMap(new IdentityHashMap<>());

    PendingSockets(AtomicBoolean running, int maxSockets) {
      this.running = running;
      this.maxSockets = maxSockets;
    }

    boolean tryAdd(Socket socket) {
      synchronized (lock) {
        if (!running.get() || sockets.size() >= maxSockets || sockets.containsKey(socket)) {
          return false;
        }
        sockets.put(socket, Boolean.FALSE);
        return true;
      }
    }

    boolean claimForRead(Socket socket) {
      synchronized (lock) {
        Boolean reading = sockets.get(socket);
        if (reading != null) {
          if (!running.get()) {
            return false;
          }
          sockets.put(socket, Boolean.TRUE);
          return true;
        }
        return !closedBeforeRead.remove(socket);
      }
    }

    void remove(Socket socket) {
      synchronized (lock) {
        sockets.remove(socket);
      }
    }

    List<DrainedSocket> drain() {
      synchronized (lock) {
        List<DrainedSocket> snapshot = new ArrayList<>(sockets.size());
        for (Map.Entry<Socket, Boolean> entry : sockets.entrySet()) {
          if (!entry.getValue()) {
            closedBeforeRead.add(entry.getKey());
          }
          snapshot.add(new DrainedSocket(entry.getKey(), entry.getValue()));
        }
        sockets.clear();
        return List.copyOf(snapshot);
      }
    }
  }

  public interface Connection {
    void sendText(String message);

    void close(int statusCode, String reason);
  }

  public interface Handler {
    void onOpen(Connection connection);

    void onText(Connection connection, String message);

    void onClose(Connection connection, int statusCode, String reason);

    void onConnectionError(Connection connection, Throwable error);

    void onServerError(Throwable error);
  }
}
