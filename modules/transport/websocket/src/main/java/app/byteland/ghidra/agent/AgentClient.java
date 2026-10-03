package app.byteland.ghidra.agent;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.WebSocket;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * Runs the WebSocket transport as an embedded server or as an outbound client to ws_url.
 */
public final class AgentClient {
  private static final System.Logger LOGGER = System.getLogger(AgentClient.class.getName());

  private static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(30);

  private static final long CANCELLATION_POLL_INTERVAL_MILLIS = 100L;

  /** The interval of the keepalive pings to the host. */
  private static final Duration KEEPALIVE_INTERVAL = Duration.ofSeconds(5);

  /** The maximum time for the send of one keepalive ping. */
  private static final Duration KEEPALIVE_TIMEOUT = Duration.ofSeconds(10);

  public interface LifecycleListener {
    default void onListening() {}

    default void onConnected() {}
  }

  private final AgentConfig config;
  private final AgentDispatcher dispatcher;
  private final LifecycleListener lifecycleListener;
  private final Duration connectTimeout;
  private final CountDownLatch disconnectLatch = new CountDownLatch(1);
  private final AtomicReference<AgentClientChannels.MessageChannel> channelRef =
      new AtomicReference<>();
  private final AtomicReference<AgentWebSocketServer> serverRef = new AtomicReference<>();

  public AgentClient(AgentConfig config, AgentDispatcher dispatcher) {
    this(config, dispatcher, new LifecycleListener() {});
  }

  public AgentClient(
      AgentConfig config, AgentDispatcher dispatcher, LifecycleListener lifecycleListener) {
    this(config, dispatcher, lifecycleListener, DEFAULT_CONNECT_TIMEOUT);
  }

  AgentClient(
      AgentConfig config,
      AgentDispatcher dispatcher,
      LifecycleListener lifecycleListener,
      Duration connectTimeout) {
    this.config = config;
    this.dispatcher = dispatcher;
    this.lifecycleListener = lifecycleListener;
    this.connectTimeout = connectTimeout;
  }

  public void connect() throws Exception {
    connect(() -> false);
  }

  public void connect(BooleanSupplier cancellationRequested) throws Exception {
    try {
      connectUntilDisconnected(cancellationRequested);
    } finally {
      disconnect();
    }
  }

  private void connectUntilDisconnected(BooleanSupplier cancellationRequested) throws Exception {
    if (config.isServerMode()) {
      serve(cancellationRequested);
      return;
    }

    String wsUrl = config.wsUrl();
    String displayUrl = config.redactedWsUrl();
    URI uri;
    try {
      uri = URI.create(wsUrl);
    } catch (IllegalArgumentException invalidUrl) {
      throw new IllegalArgumentException("ws_url is invalid", invalidUrl);
    }
    AgentMessageHandler messageHandler =
        new AgentMessageHandler(config, dispatcher, this::disconnect);
    try (HttpClient client = HttpClient.newBuilder().connectTimeout(connectTimeout).build()) {
      WebSocket.Builder webSocketBuilder = client.newWebSocketBuilder();
      if (config.token() != null) {
        webSocketBuilder.header("Authorization", "Bearer " + config.token());
      }
      CompletableFuture<WebSocket> wsFuture =
          webSocketBuilder.buildAsync(
              uri, new AgentClientWebSocketListener(channelRef, disconnectLatch, messageHandler));

      WebSocket ws = awaitHandshake(wsFuture, displayUrl, connectTimeout, cancellationRequested);
      if (ws == null) {
        return;
      }
      AgentClientChannels.OutboundMessageChannel channel =
          activateOutbound(ws, channelRef, messageHandler::sendReady);
      lifecycleListener.onConnected();

      awaitDisconnect(cancellationRequested, channel);
    }
  }

  static AgentClientChannels.OutboundMessageChannel activateOutbound(
      WebSocket webSocket,
      AtomicReference<AgentClientChannels.MessageChannel> channelRef,
      Consumer<AgentClientChannels.MessageChannel> readySender) {
    AgentClientChannels.OutboundMessageChannel channel = AgentClientChannels.outbound(webSocket);
    channelRef.set(channel);
    readySender.accept(channel);
    webSocket.request(1);
    return channel;
  }

  static void logTransportError(String message, Throwable error) {
    LOGGER.log(System.Logger.Level.ERROR, message, error);
  }

  @SuppressWarnings({
    "PMD.AvoidCatchingGenericException",
    "PMD.CloseResource",
    "PMD.CompareObjectsWithEquals"
  })
  public void disconnect() {
    RuntimeException failure = null;
    try {
      AgentClientChannels.MessageChannel channel = channelRef.getAndSet(null);
      if (channel != null) {
        try {
          channel.close();
        } catch (RuntimeException closeFailure) {
          failure = closeFailure;
        }
      }
      AgentWebSocketServer server = serverRef.getAndSet(null);
      if (server != null) {
        try {
          server.close();
        } catch (RuntimeException closeFailure) {
          if (failure == null) {
            failure = closeFailure;
          } else if (failure != closeFailure) {
            failure.addSuppressed(closeFailure);
          }
        }
      }
    } finally {
      disconnectLatch.countDown();
    }
    if (failure != null) throw failure;
  }

  @SuppressWarnings("PMD.CloseResource")
  private void serve(BooleanSupplier cancellationRequested) throws Exception {
    AgentMessageHandler messageHandler =
        new AgentMessageHandler(config, dispatcher, this::disconnect);
    AgentWebSocketServer server =
        new AgentWebSocketServer(
            config, new AgentClientServerHandler(channelRef, disconnectLatch, messageHandler));
    serverRef.set(server);
    server.start();
    lifecycleListener.onListening();
    awaitDisconnect(cancellationRequested);
  }

  private void awaitDisconnect(BooleanSupplier cancellationRequested) throws InterruptedException {
    awaitDisconnect(cancellationRequested, null);
  }

  /**
   * Waits until the session ends. With an outbound {@code channel}, it also sends keepalive pings.
   * The JDK WebSocket does not always report a connection that the host closed, for example when
   * the host process stopped. A ping to such a connection fails, and the session then ends.
   */
  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private void awaitDisconnect(
      BooleanSupplier cancellationRequested, AgentClientChannels.OutboundMessageChannel channel)
      throws InterruptedException {
    long nextPing = System.nanoTime() + KEEPALIVE_INTERVAL.toNanos();
    while (!disconnectLatch.await(CANCELLATION_POLL_INTERVAL_MILLIS, TimeUnit.MILLISECONDS)) {
      if (cancellationRequested.getAsBoolean()) {
        disconnect();
      } else if (channel != null && System.nanoTime() - nextPing >= 0) {
        try {
          channel.ping(KEEPALIVE_TIMEOUT);
        } catch (RuntimeException lost) {
          logTransportError("WebSocket keepalive failed; the host connection is lost", lost);
          channelRef.set(null);
          channel.abort();
          disconnectLatch.countDown();
        }
        nextPing = System.nanoTime() + KEEPALIVE_INTERVAL.toNanos();
      }
    }
  }

  @SuppressWarnings("PMD.PreserveStackTrace")
  private static WebSocket awaitHandshake(
      CompletableFuture<WebSocket> wsFuture,
      String wsUrl,
      Duration timeout,
      BooleanSupplier cancellationRequested)
      throws IOException, InterruptedException {
    long deadlineNanos = System.nanoTime() + timeout.toNanos();
    TimeoutException elapsedTimeout = new TimeoutException();
    while (true) {
      if (cancellationRequested.getAsBoolean()) {
        wsFuture.cancel(true);
        return null;
      }

      long remainingNanos = deadlineNanos - System.nanoTime();
      if (remainingNanos <= 0) {
        wsFuture.cancel(true);
        throw handshakeTimeout(wsUrl, timeout, elapsedTimeout);
      }

      long waitNanos =
          Math.min(
              remainingNanos, TimeUnit.MILLISECONDS.toNanos(CANCELLATION_POLL_INTERVAL_MILLIS));
      try {
        return wsFuture.get(waitNanos, TimeUnit.NANOSECONDS);
      } catch (TimeoutException timeoutException) {
        if (deadlineNanos - System.nanoTime() <= 0) {
          wsFuture.cancel(true);
          throw handshakeTimeout(wsUrl, timeout, timeoutException);
        }
      } catch (ExecutionException executionException) {
        Throwable cause = executionException.getCause();
        throw new IOException("Failed to connect to " + wsUrl, cause);
      }
    }
  }

  private static IOException handshakeTimeout(
      String wsUrl, Duration timeout, TimeoutException cause) {
    return new IOException(
        "Timed out connecting to "
            + wsUrl
            + " after "
            + timeout.toMillis()
            + "ms; is the server reachable and accepting WebSocket connections?",
        cause);
  }
}
