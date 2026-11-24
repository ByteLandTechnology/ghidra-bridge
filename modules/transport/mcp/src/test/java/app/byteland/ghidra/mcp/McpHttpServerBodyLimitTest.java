package app.byteland.ghidra.mcp;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.JsonUtil;
import app.byteland.ghidra.agent.AgentDispatcher;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpPrincipal;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.lang.reflect.Proxy;
import java.net.BindException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class McpHttpServerBodyLimitTest {
  private static final String LOOPBACK = "127.0.0.1";
  private static final int CHUNK_SIZE = 64 * 1024;

  @Test
  void acceptsValidPostRequests() throws Exception {
    try (RunningServer running = startTestServer()) {
      HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
      String pingBody = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{}}";
      HttpResponse<String> pingResponse =
          client.send(
              HttpRequest.newBuilder(URI.create(running.server.endpoint()))
                  .timeout(Duration.ofSeconds(10))
                  .header("Content-Type", "application/json")
                  .header("MCP-Protocol-Version", "2025-11-25")
                  .POST(HttpRequest.BodyPublishers.ofString(pingBody, StandardCharsets.UTF_8))
                  .build(),
              HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
      assertEquals(200, pingResponse.statusCode());
      Map<?, ?> parsed = (Map<?, ?>) JsonUtil.parse(pingResponse.body());
      assertEquals(1, ((Number) parsed.get("id")).intValue());
      assertEquals(Map.of(), parsed.get("result"));

      // Also verify a multi-megabyte valid JSON body below the 16 MiB limit succeeds.
      String padding = " ".repeat(2 * 1024 * 1024);
      String paddedPing =
          "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\",\"params\":{}" + padding + "}";
      HttpResponse<String> paddedResponse =
          client.send(
              HttpRequest.newBuilder(URI.create(running.server.endpoint()))
                  .timeout(Duration.ofSeconds(15))
                  .header("Content-Type", "application/json")
                  .header("MCP-Protocol-Version", "2025-11-25")
                  .POST(HttpRequest.BodyPublishers.ofString(paddedPing, StandardCharsets.UTF_8))
                  .build(),
              HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
      assertEquals(200, paddedResponse.statusCode());
      Map<?, ?> parsedPadded = (Map<?, ?>) JsonUtil.parse(paddedResponse.body());
      assertEquals(2, ((Number) parsedPadded.get("id")).intValue());
    }
  }

  @Test
  void validateContentLengthEnforcesBoundariesAndRejectsMalformedHeaders() {
    assertDoesNotThrow(() -> McpHttpServer.validateContentLength(null));
    assertDoesNotThrow(() -> McpHttpServer.validateContentLength(new Headers()));

    Headers zero = new Headers();
    zero.add("Content-Length", "0");
    assertDoesNotThrow(() -> McpHttpServer.validateContentLength(zero));

    Headers exactMax = new Headers();
    exactMax.add("Content-Length", Integer.toString(McpHttpServer.MAX_REQUEST_BODY_BYTES));
    assertDoesNotThrow(() -> McpHttpServer.validateContentLength(exactMax));

    Headers whitespaceValid = new Headers();
    whitespaceValid.add("Content-Length", "  1024  ");
    assertDoesNotThrow(() -> McpHttpServer.validateContentLength(whitespaceValid));

    Headers oneOverMax = new Headers();
    oneOverMax.add("Content-Length", Long.toString(McpHttpServer.MAX_REQUEST_BODY_BYTES + 1L));
    McpHttpServer.JsonRpcError overErr =
        assertThrows(
            McpHttpServer.JsonRpcError.class,
            () -> McpHttpServer.validateContentLength(oneOverMax));
    assertEquals(413, overErr.httpStatus());
    assertEquals(-32600, overErr.code());

    Headers maxLong = new Headers();
    maxLong.add("Content-Length", Long.toString(Long.MAX_VALUE));
    McpHttpServer.JsonRpcError maxLongErr =
        assertThrows(
            McpHttpServer.JsonRpcError.class,
            () -> McpHttpServer.validateContentLength(maxLong));
    assertEquals(413, maxLongErr.httpStatus());

    Headers duplicateSame = new Headers();
    duplicateSame.add("Content-Length", "16");
    duplicateSame.add("Content-Length", "16");
    McpHttpServer.JsonRpcError dupSameErr =
        assertThrows(
            McpHttpServer.JsonRpcError.class,
            () -> McpHttpServer.validateContentLength(duplicateSame));
    assertEquals(400, dupSameErr.httpStatus());
    assertEquals(-32600, dupSameErr.code());

    Headers duplicateDiff = new Headers();
    duplicateDiff.add("Content-Length", "16");
    duplicateDiff.add("Content-Length", "32");
    McpHttpServer.JsonRpcError dupDiffErr =
        assertThrows(
            McpHttpServer.JsonRpcError.class,
            () -> McpHttpServer.validateContentLength(duplicateDiff));
    assertEquals(400, dupDiffErr.httpStatus());

    for (String invalid :
        List.of(
            "",
            "   ",
            "-1",
            "-0",
            "+10",
            "abc",
            "10, 10",
            "10, 20",
            "12 34",
            "99999999999999999999999999999")) {
      Headers malformed = new Headers();
      malformed.add("Content-Length", invalid);
      McpHttpServer.JsonRpcError err =
          assertThrows(
              McpHttpServer.JsonRpcError.class,
              () -> McpHttpServer.validateContentLength(malformed),
              "Expected HTTP 400 for Content-Length: " + invalid);
      assertEquals(400, err.httpStatus());
      assertEquals(-32600, err.code());
    }
  }

  @Test
  void readBodyBoundsReadsAtMaxPlusOneAndHandlesMismatchedContentLength() throws Exception {
    AtomicBoolean exactClosed = new AtomicBoolean(false);
    HttpExchange exactExchange =
        stubExchange(
            null,
            new RepeatingByteInputStream(
                (byte) ' ', McpHttpServer.MAX_REQUEST_BODY_BYTES, Long.MAX_VALUE, exactClosed));
    String exactBody = McpHttpServer.readBody(exactExchange);
    assertEquals(McpHttpServer.MAX_REQUEST_BODY_BYTES, exactBody.length());
    assertTrue(exactClosed.get());

    // Stream promises small Content-Length (32) in headers, but underlying stream yields 64 MiB;
    // also fail if readBody tries to read past MAX_REQUEST_BODY_BYTES + 1.
    Headers mismatchedHeaders = new Headers();
    mismatchedHeaders.add("Content-Length", "32");
    AtomicLong bytesRead = new AtomicLong();
    InputStream oversizedStream =
        new RepeatingByteInputStream(
            (byte) 'a',
            64L * 1024 * 1024,
            McpHttpServer.MAX_REQUEST_BODY_BYTES + 1L,
            new AtomicBoolean()) {
          @Override
          public int read(byte[] buf, int off, int len) throws IOException {
            int n = super.read(buf, off, len);
            if (n > 0) {
              bytesRead.addAndGet(n);
            }
            return n;
          }
        };
    HttpExchange mismatchedExchange = stubExchange(mismatchedHeaders, oversizedStream);
    McpHttpServer.JsonRpcError err =
        assertThrows(
            McpHttpServer.JsonRpcError.class, () -> McpHttpServer.readBody(mismatchedExchange));
    assertEquals(413, err.httpStatus());
    assertEquals(-32600, err.code());
    assertEquals(McpHttpServer.MAX_REQUEST_BODY_BYTES + 1L, bytesRead.get());
  }

  @Test
  void serverRejectsInvalidContentLengthOverHttpWith400() throws Exception {
    try (RunningServer running = startTestServer()) {
      // "+2" passes Long.parseLong in jdk.httpserver and reaches McpHttpServer.validateContentLength.
      RawHttpResponse plusResponse =
          sendRawRequest(
              running.port,
              "POST /mcp HTTP/1.1\r\n"
                  + "Host: 127.0.0.1:"
                  + running.port
                  + "\r\n"
                  + "Content-Type: application/json\r\n"
                  + "MCP-Protocol-Version: 2025-11-25\r\n"
                  + "Content-Length: +2\r\n"
                  + "Connection: close\r\n\r\n"
                  + "{}");
      assertEquals(400, plusResponse.statusCode);
      Map<?, ?> parsed = (Map<?, ?>) JsonUtil.parse(plusResponse.body);
      Map<?, ?> error = (Map<?, ?>) parsed.get("error");
      assertNotNull(error);
      assertEquals(-32600, ((Number) error.get("code")).intValue());

      // Negative, non-numeric, and duplicate Content-Length headers over the wire also return 400.
      for (String badHeaderBlock :
          List.of(
              "Content-Length: -5\r\n",
              "Content-Length: not-a-number\r\n",
              "Content-Length: 2\r\nContent-Length: 2\r\n")) {
        RawHttpResponse badResponse =
            sendRawRequest(
                running.port,
                "POST /mcp HTTP/1.1\r\n"
                    + "Host: 127.0.0.1:"
                    + running.port
                    + "\r\n"
                    + "Content-Type: application/json\r\n"
                    + "MCP-Protocol-Version: 2025-11-25\r\n"
                    + badHeaderBlock
                    + "Connection: close\r\n\r\n"
                    + "{}");
        assertEquals(400, badResponse.statusCode);
      }
    }
  }

  @Test
  void serverRejectsOversizedContentLengthAndPausedOversizedChunkedStreamWith413()
      throws Exception {
    try (RunningServer running = startTestServer()) {
      // 1. Oversized Content-Length (16 MiB + 1) rejected immediately before body is streamed.
      long overLimit = McpHttpServer.MAX_REQUEST_BODY_BYTES + 1L;
      try (Socket socket = new Socket(LOOPBACK, running.port)) {
        socket.setSoTimeout(10_000);
        String headers =
            "POST /mcp HTTP/1.1\r\n"
                + "Host: 127.0.0.1:"
                + running.port
                + "\r\n"
                + "Content-Type: application/json\r\n"
                + "MCP-Protocol-Version: 2025-11-25\r\n"
                + "Content-Length: "
                + overLimit
                + "\r\n\r\n";
        OutputStream out = socket.getOutputStream();
        out.write(headers.getBytes(StandardCharsets.US_ASCII));
        out.flush();

        RawHttpResponse response = readHttpResponse(socket.getInputStream());
        assertEquals(413, response.statusCode);
        assertEquals("close", response.headers.get("connection"));
        Map<?, ?> parsed = (Map<?, ?>) JsonUtil.parse(response.body);
        Map<?, ?> error = (Map<?, ?>) parsed.get("error");
        assertNotNull(error);
        assertEquals(-32600, ((Number) error.get("code")).intValue());
      }

      // 2. Oversized Transfer-Encoding: chunked (16 MiB + 1) where client pauses before 0\r\n\r\n.
      try (Socket socket = new Socket(LOOPBACK, running.port)) {
        socket.setSoTimeout(10_000);
        String headers =
            "POST /mcp HTTP/1.1\r\n"
                + "Host: 127.0.0.1:"
                + running.port
                + "\r\n"
                + "Content-Type: application/json\r\n"
                + "MCP-Protocol-Version: 2025-11-25\r\n"
                + "Transfer-Encoding: chunked\r\n\r\n";
        OutputStream out = socket.getOutputStream();
        out.write(headers.getBytes(StandardCharsets.US_ASCII));
        byte[] chunk = new byte[CHUNK_SIZE];
        Arrays.fill(chunk, (byte) 'x');
        byte[] chunkPrefix =
            (Integer.toHexString(CHUNK_SIZE) + "\r\n").getBytes(StandardCharsets.US_ASCII);
        byte[] crlf = "\r\n".getBytes(StandardCharsets.US_ASCII);

        int fullChunks = McpHttpServer.MAX_REQUEST_BODY_BYTES / CHUNK_SIZE;
        for (int i = 0; i < fullChunks; i++) {
          out.write(chunkPrefix);
          out.write(chunk);
          out.write(crlf);
        }
        // Send 1 extra byte in one more chunk (total = 16 MiB + 1) and DO NOT send 0\r\n\r\n.
        out.write("1\r\nx\r\n".getBytes(StandardCharsets.US_ASCII));
        out.flush();

        RawHttpResponse response = readHttpResponse(socket.getInputStream());
        assertEquals(413, response.statusCode);
        assertEquals("close", response.headers.get("connection"));
        Map<?, ?> parsed = (Map<?, ?>) JsonUtil.parse(response.body);
        Map<?, ?> error = (Map<?, ?>) parsed.get("error");
        assertNotNull(error);
        assertEquals(-32600, ((Number) error.get("code")).intValue());
      }

      // 3. Mismatched Content-Length over wire where client streams extra bytes past declared length.
      try (Socket socket = new Socket(LOOPBACK, running.port)) {
        socket.setSoTimeout(10_000);
        String headers =
            "POST /mcp HTTP/1.1\r\n"
                + "Host: 127.0.0.1:"
                + running.port
                + "\r\n"
                + "Content-Type: application/json\r\n"
                + "MCP-Protocol-Version: 2025-11-25\r\n"
                + "Content-Length: 16\r\n\r\n";
        OutputStream out = socket.getOutputStream();
        out.write(headers.getBytes(StandardCharsets.US_ASCII));
        out.write("{\"incomplete\":12".getBytes(StandardCharsets.US_ASCII));
        out.write(new byte[128 * 1024]);
        out.flush();
        RawHttpResponse response = readHttpResponse(socket.getInputStream());
        assertEquals(400, response.statusCode);
      }

      assertPingSucceeds(running.port);
    }
  }

  @Test
  void deliversSseErrorOnHttp413AndKeepsSessionActive() throws Exception {
    try (RunningServer running = startTestServer();
        Socket sseSocket = new Socket(LOOPBACK, running.port)) {
      sseSocket.setSoTimeout(10_000);
      OutputStream sseOut = sseSocket.getOutputStream();
      sseOut.write(
          ("GET /mcp HTTP/1.1\r\n"
                  + "Host: 127.0.0.1:"
                  + running.port
                  + "\r\n"
                  + "Accept: text/event-stream\r\n\r\n")
              .getBytes(StandardCharsets.US_ASCII));
      sseOut.flush();

      BufferedReader sseReader =
          new BufferedReader(
              new InputStreamReader(sseSocket.getInputStream(), StandardCharsets.UTF_8));
      String statusLine = sseReader.readLine();
      assertNotNull(statusLine);
      assertTrue(statusLine.startsWith("HTTP/1.1 200"), statusLine);
      String headerLine;
      while ((headerLine = sseReader.readLine()) != null && !headerLine.isEmpty()) {
        // Consume SSE response headers.
      }

      SseEvent endpointEvent = readSseEvent(sseReader);
      assertEquals("endpoint", endpointEvent.event);
      assertTrue(endpointEvent.data.startsWith("/mcp?sessionId="), endpointEvent.data);
      String sessionEndpoint = endpointEvent.data;

      // 1. Oversized Content-Length POST to active ?sessionId= endpoint.
      long overLimit = McpHttpServer.MAX_REQUEST_BODY_BYTES + 1L;
      try (Socket postSocket = new Socket(LOOPBACK, running.port)) {
        postSocket.setSoTimeout(10_000);
        String postHeaders =
            "POST "
                + sessionEndpoint
                + " HTTP/1.1\r\n"
                + "Host: 127.0.0.1:"
                + running.port
                + "\r\n"
                + "Content-Type: application/json\r\n"
                + "MCP-Protocol-Version: 2025-11-25\r\n"
                + "Content-Length: "
                + overLimit
                + "\r\n\r\n";
        postSocket.getOutputStream().write(postHeaders.getBytes(StandardCharsets.US_ASCII));
        postSocket.getOutputStream().flush();

        RawHttpResponse postResponse = readHttpResponse(postSocket.getInputStream());
        assertEquals(413, postResponse.statusCode);
        assertEquals("close", postResponse.headers.get("connection"));
      }

      SseEvent fixedErrEvent = readSseEvent(sseReader);
      assertEquals("message", fixedErrEvent.event);
      Map<?, ?> fixedErrJson = (Map<?, ?>) JsonUtil.parse(fixedErrEvent.data);
      assertEquals(
          -32600, ((Number) ((Map<?, ?>) fixedErrJson.get("error")).get("code")).intValue());

      // 2. Oversized chunked POST to active ?sessionId= endpoint.
      RawHttpResponse chunkedPostResponse =
          streamOversizedBody(
              running.port,
              "POST "
                  + sessionEndpoint
                  + " HTTP/1.1\r\n"
                  + "Host: 127.0.0.1:"
                  + running.port
                  + "\r\n"
                  + "Content-Type: application/json\r\n"
                  + "MCP-Protocol-Version: 2025-11-25\r\n"
                  + "Transfer-Encoding: chunked\r\n"
                  + "Connection: close\r\n\r\n",
              McpHttpServer.MAX_REQUEST_BODY_BYTES + CHUNK_SIZE,
              true);
      assertEquals(413, chunkedPostResponse.statusCode);
      assertEquals("close", chunkedPostResponse.headers.get("connection"));

      SseEvent chunkedErrEvent = readSseEvent(sseReader);
      assertEquals("message", chunkedErrEvent.event);
      Map<?, ?> chunkedErrJson = (Map<?, ?>) JsonUtil.parse(chunkedErrEvent.data);
      assertEquals(
          -32600, ((Number) ((Map<?, ?>) chunkedErrJson.get("error")).get("code")).intValue());

      // 3. Subsequent valid POST to the same SSE session still succeeds with 202 + SSE message.
      String ping = "{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"ping\",\"params\":{}}";
      HttpClient client = HttpClient.newHttpClient();
      HttpResponse<String> validPost =
          client.send(
              HttpRequest.newBuilder(
                      URI.create("http://" + LOOPBACK + ":" + running.port + sessionEndpoint))
                  .timeout(Duration.ofSeconds(10))
                  .header("Content-Type", "application/json")
                  .header("MCP-Protocol-Version", "2025-11-25")
                  .POST(HttpRequest.BodyPublishers.ofString(ping, StandardCharsets.UTF_8))
                  .build(),
              HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
      assertEquals(202, validPost.statusCode());

      SseEvent pingEvent = readSseEvent(sseReader);
      assertEquals("message", pingEvent.event);
      Map<?, ?> pingJson = (Map<?, ?>) JsonUtil.parse(pingEvent.data);
      assertEquals(9, ((Number) pingJson.get("id")).intValue());
      assertEquals(Map.of(), pingJson.get("result"));
    }
  }

  @Test
  void boundedHeap96mServerRejects64MiBFixedAndChunkedStreamsWithoutOom() throws Exception {
    String javaBin =
        Path.of(System.getProperty("java.home"), "bin", "java").toAbsolutePath().toString();
    String classpath = System.getProperty("java.class.path");

    Process process =
        new ProcessBuilder(
                javaBin,
                "-Xmx96m",
                "-cp",
                classpath,
                BoundedHeapServerMain.class.getName())
            .start();

    CompletableFuture<String> stderrFuture =
        CompletableFuture.supplyAsync(
            () -> {
              try (InputStream err = process.getErrorStream()) {
                return new String(err.readAllBytes(), StandardCharsets.UTF_8);
              } catch (IOException e) {
                return "STDERR_READ_ERROR: " + e;
              }
            });

    try {
      int port;
      BufferedReader stdout =
          new BufferedReader(
              new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8));
      String readyLine = stdout.readLine();
      assertNotNull(
          readyLine,
          () -> "Bounded-heap server exited early; stderr=" + stderrFuture.join());
      assertTrue(readyLine.startsWith("READY "), "Unexpected stdout: " + readyLine);
      port = Integer.parseInt(readyLine.substring("READY ".length()).trim());

      int totalBytes = 64 * 1024 * 1024;
      String fixedHeaders =
          "POST /mcp HTTP/1.1\r\n"
              + "Host: 127.0.0.1:"
              + port
              + "\r\n"
              + "Content-Type: application/json\r\n"
              + "MCP-Protocol-Version: 2025-11-25\r\n"
              + "Content-Length: "
              + totalBytes
              + "\r\n"
              + "Connection: close\r\n\r\n";
      String chunkedHeaders =
          "POST /mcp HTTP/1.1\r\n"
              + "Host: 127.0.0.1:"
              + port
              + "\r\n"
              + "Content-Type: application/json\r\n"
              + "MCP-Protocol-Version: 2025-11-25\r\n"
              + "Transfer-Encoding: chunked\r\n"
              + "Connection: close\r\n\r\n";

      RawHttpResponse fixedResponse = streamOversizedBody(port, fixedHeaders, totalBytes, false);
      assertEquals(413, fixedResponse.statusCode);
      assertEquals("close", fixedResponse.headers.get("connection"));

      RawHttpResponse chunkedResponse =
          streamOversizedBody(port, chunkedHeaders, totalBytes, true);
      assertEquals(413, chunkedResponse.statusCode);
      assertEquals("close", chunkedResponse.headers.get("connection"));

      // Verify server remains healthy and responds HTTP 200 to subsequent ping.
      HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
      HttpResponse<String> pingResponse =
          client.send(
              HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/mcp"))
                  .timeout(Duration.ofSeconds(10))
                  .header("Content-Type", "application/json")
                  .header("MCP-Protocol-Version", "2025-11-25")
                  .POST(
                      HttpRequest.BodyPublishers.ofString(
                          "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"ping\",\"params\":{}}",
                          StandardCharsets.UTF_8))
                  .build(),
              HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
      assertEquals(200, pingResponse.statusCode());
      Map<?, ?> pingJson = (Map<?, ?>) JsonUtil.parse(pingResponse.body());
      assertEquals(4, ((Number) pingJson.get("id")).intValue());

      // Signal clean shutdown by closing child stdin.
      process.getOutputStream().close();
      assertTrue(process.waitFor(15, TimeUnit.SECONDS), "Child JVM did not exit in time");
      String stderr = stderrFuture.get(5, TimeUnit.SECONDS);
      assertFalse(
          stderr.contains("java.lang.OutOfMemoryError") || stderr.contains("OutOfMemoryError"),
          "Unexpected OutOfMemoryError on server stderr:\n" + stderr);
      assertEquals(0, process.exitValue(), "Non-zero exit code; stderr:\n" + stderr);
    } finally {
      if (process.isAlive()) {
        process.destroyForcibly();
      }
    }
  }

  private static void assertPingSucceeds(int port) throws Exception {
    HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    HttpResponse<String> response =
        client.send(
            HttpRequest.newBuilder(URI.create("http://" + LOOPBACK + ":" + port + "/mcp"))
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/json")
                .header("MCP-Protocol-Version", "2025-11-25")
                .POST(
                    HttpRequest.BodyPublishers.ofString(
                        "{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"ping\",\"params\":{}}",
                        StandardCharsets.UTF_8))
                .build(),
            HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    assertEquals(200, response.statusCode());
  }

  private static RawHttpResponse sendRawRequest(int port, String rawRequest) throws Exception {
    try (Socket socket = new Socket(LOOPBACK, port)) {
      socket.setSoTimeout(10_000);
      OutputStream out = socket.getOutputStream();
      out.write(rawRequest.getBytes(StandardCharsets.US_ASCII));
      out.flush();
      return readHttpResponse(socket.getInputStream());
    }
  }

  private static RawHttpResponse streamOversizedBody(
      int port, String rawHeaders, int totalBytes, boolean chunked) throws Exception {
    try (Socket socket = new Socket(LOOPBACK, port)) {
      socket.setSoTimeout(20_000);
      InputStream in = socket.getInputStream();
      CompletableFuture<RawHttpResponse> responseFuture =
          CompletableFuture.supplyAsync(
              () -> {
                try {
                  return readHttpResponse(in);
                } catch (IOException e) {
                  throw new RuntimeException(e);
                }
              });

      try {
        OutputStream out = socket.getOutputStream();
        out.write(rawHeaders.getBytes(StandardCharsets.US_ASCII));
        byte[] payload = new byte[CHUNK_SIZE];
        Arrays.fill(payload, (byte) 'a');
        byte[] crlf = "\r\n".getBytes(StandardCharsets.US_ASCII);
        int remaining = totalBytes;
        while (remaining > 0 && !responseFuture.isDone()) {
          int step = Math.min(remaining, payload.length);
          if (chunked) {
            out.write(
                (Integer.toHexString(step) + "\r\n").getBytes(StandardCharsets.US_ASCII));
            out.write(payload, 0, step);
            out.write(crlf);
          } else {
            out.write(payload, 0, step);
          }
          remaining -= step;
        }
        if (chunked && remaining == 0 && !responseFuture.isDone()) {
          out.write("0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
        }
        out.flush();
      } catch (IOException ignored) {
        // Expected when the server sends HTTP 413 with Connection: close and drops unread bytes.
      }

      return responseFuture.get(20, TimeUnit.SECONDS);
    }
  }

  private static RawHttpResponse readHttpResponse(InputStream input) throws IOException {
    String statusLine = readAsciiLine(input);
    if (statusLine == null || !statusLine.startsWith("HTTP/1.1 ")) {
      throw new IOException("Invalid HTTP status line: " + statusLine);
    }
    String[] parts = statusLine.split(" ", 3);
    int statusCode = Integer.parseInt(parts[1]);

    Map<String, String> headers = new LinkedHashMap<>();
    while (true) {
      String line = readAsciiLine(input);
      if (line == null || line.isEmpty()) {
        break;
      }
      int colon = line.indexOf(':');
      if (colon > 0) {
        headers.put(
            line.substring(0, colon).trim().toLowerCase(Locale.ROOT),
            line.substring(colon + 1).trim());
      }
    }

    String contentLengthHeader = headers.get("content-length");
    byte[] bodyBytes;
    if (contentLengthHeader != null) {
      int length = Integer.parseInt(contentLengthHeader);
      bodyBytes = input.readNBytes(length);
    } else {
      bodyBytes = input.readAllBytes();
    }
    return new RawHttpResponse(
        statusCode, headers, new String(bodyBytes, StandardCharsets.UTF_8));
  }

  private static String readAsciiLine(InputStream input) throws IOException {
    ByteArrayOutputStream buf = new ByteArrayOutputStream(128);
    int prev = -1;
    int curr;
    while ((curr = input.read()) != -1) {
      if (prev == '\r' && curr == '\n') {
        byte[] bytes = buf.toByteArray();
        return new String(bytes, 0, bytes.length - 1, StandardCharsets.US_ASCII);
      }
      buf.write(curr);
      prev = curr;
    }
    if (buf.size() == 0) {
      return null;
    }
    return buf.toString(StandardCharsets.US_ASCII);
  }

  private static SseEvent readSseEvent(BufferedReader reader) throws IOException {
    String event = null;
    StringBuilder data = new StringBuilder();
    String line;
    while ((line = reader.readLine()) != null) {
      if (line.isEmpty()) {
        if (event != null || data.length() > 0) {
          return new SseEvent(event, data.toString());
        }
        continue;
      }
      if (line.startsWith(":")) {
        continue;
      }
      if (line.startsWith("event:")) {
        event = line.substring("event:".length()).trim();
      } else if (line.startsWith("data:")) {
        if (data.length() > 0) {
          data.append('\n');
        }
        data.append(line.substring("data:".length()).trim());
      }
    }
    throw new IOException("Unexpected EOF on SSE stream");
  }

  static RunningServer startTestServer() throws IOException {
    AgentDispatcher dispatcher = createTestDispatcher();
    for (int attempt = 0; attempt < 10; attempt++) {
      int port = findFreePort();
      McpConfig config = new McpConfig(LOOPBACK, port, "/mcp", null, "test-session", "ghidra");
      try {
        McpHttpServer server = new McpHttpServer(config, dispatcher);
        server.start();
        return new RunningServer(server, dispatcher, port);
      } catch (BindException retry) {
        // Port was claimed concurrently; try another ephemeral port.
      }
    }
    dispatcher.close();
    throw new IOException("Unable to bind test McpHttpServer after 10 attempts");
  }

  private static int findFreePort() throws IOException {
    try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getByName(LOOPBACK))) {
      return socket.getLocalPort();
    }
  }

  private static AgentDispatcher createTestDispatcher() {
    TransactionRunner transactionRunner =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            try {
              return operation.execute();
            } catch (Exception ex) {
              throw new RuntimeException(ex);
            }
          }
        };
    BridgeServices services =
        new BridgeServices(
            unusedService(ProgramService.class),
            unusedService(AddressService.class),
            unusedService(CommentService.class),
            unusedService(ReferenceService.class),
            unusedService(MemoryService.class),
            unusedService(ListingService.class),
            unusedService(FunctionService.class),
            unusedService(GlobalVariableService.class),
            noopCloseableService(AnalysisService.class),
            noopCloseableService(DecompilationService.class),
            unusedService(SymbolService.class),
            unusedService(DataTypeService.class),
            transactionRunner,
            "test-program");
    return new AgentDispatcher(services, "test-session");
  }

  private static <T> T unusedService(Class<T> type) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> {
              throw new UnsupportedOperationException(method.getName());
            }));
  }

  private static <T> T noopCloseableService(Class<T> type) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> {
              if ("close".equals(method.getName())) {
                return null;
              }
              throw new UnsupportedOperationException(method.getName());
            }));
  }

  private static HttpExchange stubExchange(Headers requestHeaders, InputStream bodyStream) {
    Headers req = requestHeaders == null ? new Headers() : requestHeaders;
    Headers rsp = new Headers();
    return new HttpExchange() {
      @Override
      public Headers getRequestHeaders() {
        return req;
      }

      @Override
      public Headers getResponseHeaders() {
        return rsp;
      }

      @Override
      public URI getRequestURI() {
        return URI.create("/mcp");
      }

      @Override
      public String getRequestMethod() {
        return "POST";
      }

      @Override
      public HttpContext getHttpContext() {
        return null;
      }

      @Override
      public void close() {}

      @Override
      public InputStream getRequestBody() {
        return bodyStream;
      }

      @Override
      public OutputStream getResponseBody() {
        return OutputStream.nullOutputStream();
      }

      @Override
      public void sendResponseHeaders(int rCode, long responseLength) {}

      @Override
      public InetSocketAddress getRemoteAddress() {
        return null;
      }

      @Override
      public int getResponseCode() {
        return -1;
      }

      @Override
      public InetSocketAddress getLocalAddress() {
        return null;
      }

      @Override
      public String getProtocol() {
        return "HTTP/1.1";
      }

      @Override
      public Object getAttribute(String name) {
        return null;
      }

      @Override
      public void setAttribute(String name, Object value) {}

      @Override
      public void setStreams(InputStream i, OutputStream o) {}

      @Override
      public HttpPrincipal getPrincipal() {
        return null;
      }
    };
  }

  private static class RepeatingByteInputStream extends InputStream {
    private final byte value;
    private final long maxAllowedReads;
    private final AtomicBoolean closedFlag;
    private long remaining;
    private long delivered;

    RepeatingByteInputStream(
        byte value, long totalBytes, long maxAllowedReads, AtomicBoolean closedFlag) {
      this.value = value;
      this.remaining = totalBytes;
      this.maxAllowedReads = maxAllowedReads;
      this.closedFlag = closedFlag;
    }

    @Override
    public int read() throws IOException {
      byte[] one = new byte[1];
      int n = read(one, 0, 1);
      return n == -1 ? -1 : (one[0] & 0xFF);
    }

    @Override
    public int read(byte[] buf, int off, int len) throws IOException {
      if (len == 0) {
        return 0;
      }
      if (remaining <= 0) {
        return -1;
      }
      int step = (int) Math.min(len, remaining);
      if (delivered + step > maxAllowedReads) {
        throw new AssertionError(
            "Stream read exceeded bound " + maxAllowedReads + " (attempted " + (delivered + step) + ")");
      }
      Arrays.fill(buf, off, off + step, value);
      remaining -= step;
      delivered += step;
      return step;
    }

    @Override
    public void close() {
      closedFlag.set(true);
    }
  }

  record RawHttpResponse(int statusCode, Map<String, String> headers, String body) {}

  record SseEvent(String event, String data) {}

  static final class RunningServer implements AutoCloseable {
    final McpHttpServer server;
    final AgentDispatcher dispatcher;
    final int port;

    RunningServer(McpHttpServer server, AgentDispatcher dispatcher, int port) {
      this.server = server;
      this.dispatcher = dispatcher;
      this.port = port;
    }

    @Override
    public void close() {
      server.close();
      dispatcher.close();
    }
  }

  public static final class BoundedHeapServerMain {
    private BoundedHeapServerMain() {}

    public static void main(String[] args) throws Exception {
      try (RunningServer running = startTestServer()) {
        System.out.println("READY " + running.port);
        System.out.flush();
        // Wait until parent closes stdin.
        while (System.in.read() != -1) {
          // Keep server running.
        }
      }
    }
  }
}
