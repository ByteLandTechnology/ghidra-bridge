package app.byteland.ghidra.agent;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;

final class WebSocketHandshake {
  private static final String WEBSOCKET_ACCEPT_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  private static final String ACCEPT_DIGEST_ALGORITHM = "SHA-1";
  private static final int MIN_REQUEST_LINE_FIELDS = 2;
  private static final int INITIAL_HTTP_RESPONSE_CAPACITY = 128;
  private static final int MAX_HANDSHAKE_BYTES = 64 * 1024;
  private static final long NANOS_PER_MILLI = 1_000_000L;

  private WebSocketHandshake() {}

  static HandshakeRequest readHandshake(Socket socket, long deadlineNanos) throws IOException {
    InputStream input = socket.getInputStream();
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    int matched = 0;
    int totalBytes = 0;
    while (matched < 4) {
      updateReadTimeout(socket, deadlineNanos);
      int b;
      try {
        b = input.read();
      } catch (SocketTimeoutException timeout) {
        if (deadlineNanos - System.nanoTime() <= 0) {
          throw handshakeTimeout(timeout);
        }
        continue;
      }
      if (deadlineNanos - System.nanoTime() <= 0) {
        throw handshakeTimeout(null);
      }
      if (b < 0) {
        throw new EOFException("EOF during handshake");
      }
      totalBytes++;
      if (totalBytes > MAX_HANDSHAKE_BYTES) {
        throw new HttpHandshakeException(
            431, "Request Header Fields Too Large", "Handshake header exceeds maximum size");
      }
      buffer.write(b);
      matched =
          switch (matched) {
            case 0 -> b == '\r' ? 1 : 0;
            case 1 -> b == '\n' ? 2 : 0;
            case 2 -> b == '\r' ? 3 : 0;
            case 3 -> b == '\n' ? 4 : 0;
            default -> matched;
          };
    }

    String requestText = buffer.toString(StandardCharsets.US_ASCII);
    List<String> lines = splitLiteral(requestText, "\r\n", 0);
    if (lines.isEmpty()) {
      throw new HttpHandshakeException(400, "Bad Request", "Missing request line");
    }
    List<String> requestLine = splitLiteral(lines.getFirst(), " ", 3);
    if (requestLine.size() < MIN_REQUEST_LINE_FIELDS) {
      throw new HttpHandshakeException(400, "Bad Request", "Malformed request line");
    }

    Map<String, String> headers = new LinkedHashMap<>();
    List<String> originHeaders = new ArrayList<>();
    for (int i = 1; i < lines.size(); i++) {
      String line = lines.get(i);
      if (line.isEmpty()) {
        continue;
      }
      int idx = line.indexOf(':');
      if (idx <= 0) {
        continue;
      }
      String headerName = line.substring(0, idx).trim().toLowerCase(Locale.ROOT);
      String headerValue = line.substring(idx + 1).trim();
      if ("origin".equals(headerName)) {
        if (!originHeaders.isEmpty()) {
          throw new HttpHandshakeException(
              403, "Forbidden", "Multiple Origin headers are not allowed");
        }
        originHeaders.add(headerValue);
      }
      headers.put(headerName, headerValue);
    }

    String target = requestLine.get(1);
    int queryIndex = target.indexOf('?');
    String path = queryIndex >= 0 ? target.substring(0, queryIndex) : target;
    String query = queryIndex >= 0 ? target.substring(queryIndex + 1) : "";
    return new HandshakeRequest(
        requestLine.getFirst(), path, parseQuery(query), headers, originHeaders);
  }

  private static void updateReadTimeout(Socket socket, long deadlineNanos) throws SocketException {
    long remainingNanos = deadlineNanos - System.nanoTime();
    if (remainingNanos <= 0) {
      throw handshakeTimeout(null);
    }
    long remainingMillis = (remainingNanos - 1L) / NANOS_PER_MILLI + 1L;
    socket.setSoTimeout((int) Math.min(Integer.MAX_VALUE, remainingMillis));
  }

  private static HttpHandshakeException handshakeTimeout(Throwable cause) {
    return new HttpHandshakeException(408, "Request Timeout", "Handshake timed out", cause);
  }

  static void writeHandshakeResponse(OutputStream output, String acceptKey) throws IOException {
    List<String> headers = new ArrayList<>();
    headers.add("Upgrade: websocket");
    headers.add("Connection: Upgrade");
    headers.add("Sec-WebSocket-Accept: " + acceptKey);
    writeHttpResponse(output, 101, "Switching Protocols", headers, null);
  }

  static void writeHttpResponse(
      OutputStream output, int status, String reason, List<String> headers, String body)
      throws IOException {
    String payload = body == null ? "" : body;
    StringBuilder response = new StringBuilder(INITIAL_HTTP_RESPONSE_CAPACITY);
    response.append("HTTP/1.1 ").append(status).append(' ').append(reason).append("\r\n");
    for (String header : headers) {
      response.append(header).append("\r\n");
    }
    if (!payload.isEmpty()) {
      byte[] bodyBytes = payload.getBytes(StandardCharsets.UTF_8);
      response
          .append("Content-Type: text/plain; charset=utf-8\r\nContent-Length: ")
          .append(bodyBytes.length)
          .append("\r\n\r\n");
      output.write(response.toString().getBytes(StandardCharsets.US_ASCII));
      output.write(bodyBytes);
    } else {
      response.append("Content-Length: 0\r\n\r\n");
      output.write(response.toString().getBytes(StandardCharsets.US_ASCII));
    }
    output.flush();
  }

  static Map<String, String> parseQuery(String rawQuery) {
    Map<String, String> query = new LinkedHashMap<>();
    if (rawQuery == null || rawQuery.isEmpty()) {
      return query;
    }
    for (String part : splitLiteral(rawQuery, "&", 0)) {
      if (part.isEmpty()) {
        continue;
      }
      int idx = part.indexOf('=');
      String key = idx >= 0 ? part.substring(0, idx) : part;
      String value = idx >= 0 ? part.substring(idx + 1) : "";
      query.put(urlDecode(key), urlDecode(value));
    }
    return query;
  }

  private static List<String> splitLiteral(String value, String delimiter, int limit) {
    List<String> parts = new ArrayList<>();
    int start = 0;
    while (limit <= 0 || parts.size() < limit - 1) {
      int end = value.indexOf(delimiter, start);
      if (end < 0) {
        break;
      }
      parts.add(value.substring(start, end));
      start = end + delimiter.length();
    }
    parts.add(value.substring(start));
    if (limit == 0 && !value.isEmpty()) {
      while (!parts.isEmpty() && parts.getLast().isEmpty()) {
        parts.removeLast();
      }
    }
    return parts;
  }

  static String urlDecode(String value) {
    return URLDecoder.decode(value, StandardCharsets.UTF_8);
  }

  record HandshakeRequest(
      String method,
      String path,
      Map<String, String> query,
      Map<String, String> headers,
      List<String> originHeaders) {
    HandshakeRequest {
      query = immutableOrderedCopy(query, "query");
      headers = immutableOrderedCopy(headers, "headers");
      originHeaders = sanitizeOriginHeaders(originHeaders);
    }

    HandshakeRequest(
        String method, String path, Map<String, String> query, Map<String, String> headers) {
      this(method, path, query, headers, extractOriginHeaders(headers));
    }

    private static List<String> sanitizeOriginHeaders(List<String> origins) {
      Objects.requireNonNull(origins, "originHeaders");
      List<String> copy = new ArrayList<>(origins.size());
      for (String origin : origins) {
        copy.add(origin == null ? "" : origin);
      }
      return Collections.unmodifiableList(copy);
    }

    private static List<String> extractOriginHeaders(Map<String, String> headers) {
      Objects.requireNonNull(headers, "headers");
      List<String> origins = new ArrayList<>();
      for (Map.Entry<String, String> entry : headers.entrySet()) {
        if ("origin".equalsIgnoreCase(entry.getKey())) {
          String value = entry.getValue();
          origins.add(value == null ? "" : value);
        }
      }
      return origins;
    }

    private static Map<String, String> immutableOrderedCopy(
        Map<String, String> source, String name) {
      return Collections.unmodifiableMap(new LinkedHashMap<>(Objects.requireNonNull(source, name)));
    }

    String acceptKey() {
      String key = headers.get("sec-websocket-key");
      try {
        MessageDigest digest = MessageDigest.getInstance(ACCEPT_DIGEST_ALGORITHM);
        return Base64.getEncoder()
            .encodeToString(
                digest.digest((key + WEBSOCKET_ACCEPT_GUID).getBytes(StandardCharsets.US_ASCII)));
      } catch (NoSuchAlgorithmException error) {
        throw new IllegalStateException("failed to compute Sec-WebSocket-Accept", error);
      }
    }
  }

  static final class HttpHandshakeException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final int statusCode;
    private final String reasonPhrase;

    HttpHandshakeException(int status, String reason, String message) {
      super(message);
      this.statusCode = status;
      this.reasonPhrase = reason;
    }

    HttpHandshakeException(int status, String reason, String message, Throwable cause) {
      super(message, cause);
      this.statusCode = status;
      this.reasonPhrase = reason;
    }

    int status() {
      return statusCode;
    }

    String reason() {
      return reasonPhrase;
    }
  }
}
