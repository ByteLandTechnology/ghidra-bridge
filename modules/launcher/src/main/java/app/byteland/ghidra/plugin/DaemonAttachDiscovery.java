package app.byteland.ghidra.plugin;

import app.byteland.ghidra.JsonUtil;
import app.byteland.ghidra.network.NetworkBinding;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Discovers a local {@code ghidra-mcp} daemon attach file and computes MD5 session identifiers.
 */
public final class DaemonAttachDiscovery {
  public static final String RUNTIME_DIR_ENV = "GHIDRA_MCP_RUNTIME_DIR";
  public static final String GUI_ATTACH_FILE = "gui-attach.json";
  public static final String SERVER_STATE_FILE = "server.json";

  private static final Pattern MD5_HEX = Pattern.compile("[0-9a-fA-F]{32}");
  private static final Set<PosixFilePermission> NON_OWNER_PERMISSIONS =
      Set.of(
          PosixFilePermission.GROUP_READ,
          PosixFilePermission.GROUP_WRITE,
          PosixFilePermission.GROUP_EXECUTE,
          PosixFilePermission.OTHERS_READ,
          PosixFilePermission.OTHERS_WRITE,
          PosixFilePermission.OTHERS_EXECUTE);

  private DaemonAttachDiscovery() {}

  /**
   * Loopback WebSocket URL and per-daemon token read from {@code gui-attach.json}.
   */
  public record AttachTarget(String wsUrl, String token) {
    public AttachTarget {
      if (wsUrl == null || wsUrl.isBlank()) {
        throw new IllegalArgumentException("wsUrl is required");
      }
      if (token == null || token.isBlank()) {
        throw new IllegalArgumentException("token is required");
      }
      wsUrl = wsUrl.trim();
      token = token.trim();
      URI uri = URI.create(wsUrl);
      String scheme = uri.getScheme();
      String host = uri.getHost();
      if (!"ws".equalsIgnoreCase(scheme) || host == null || !NetworkBinding.isLoopback(host)) {
        throw new IllegalArgumentException("Attach wsUrl must target a loopback ws:// endpoint");
      }
      if (uri.getPort() < 1 || uri.getPort() > 65535) {
        throw new IllegalArgumentException("Attach wsUrl must specify a valid TCP port");
      }
    }

    @Override
    public String toString() {
      return "AttachTarget[wsUrl=" + wsUrl + ", token=<redacted>]";
    }
  }

  public static Optional<AttachTarget> discover() {
    return discover(
        System.getenv(),
        System.getProperty("os.name", ""),
        System.getProperty("user.name", ""),
        System.getProperty("java.io.tmpdir", "/tmp"));
  }

  static Optional<AttachTarget> discover(
      Map<String, String> env, String osName, String userName, String tmpDir) {
    Objects.requireNonNull(env, "env");
    String explicitDir = env.get(RUNTIME_DIR_ENV);
    if (explicitDir != null && !explicitDir.isBlank()) {
      return readAttachDirectory(Path.of(explicitDir.trim()), userName, false);
    }

    if (osName != null && osName.toLowerCase(Locale.ROOT).startsWith("windows")) {
      String localAppData = env.get("LOCALAPPDATA");
      if (localAppData != null && !localAppData.isBlank()) {
        Path runDir = Path.of(localAppData.trim(), "ghidra-mcp", "run");
        return readAttachDirectory(runDir, userName, false);
      }
      return Optional.empty();
    }

    Set<Path> roots = unixRuntimeRoots(env.get("XDG_RUNTIME_DIR"), tmpDir);
    List<Path> candidateDirs = new ArrayList<>();
    for (Path root : roots) {
      if (!Files.isDirectory(root)) {
        continue;
      }
      try (DirectoryStream<Path> stream = Files.newDirectoryStream(root, "ghidra-mcp-*")) {
        for (Path entry : stream) {
          candidateDirs.add(entry);
        }
      } catch (IOException ignored) {
        // Ignore unreadable temporary directories.
      }
    }

    AttachTarget newestTarget = null;
    FileTime newestModified = null;
    for (Path dir : candidateDirs) {
      Optional<AttachTarget> target = readAttachDirectory(dir, userName, true);
      if (target.isEmpty()) {
        continue;
      }
      FileTime modified = lastModifiedOrEpoch(dir.resolve(GUI_ATTACH_FILE));
      if (newestModified == null || modified.compareTo(newestModified) >= 0) {
        newestModified = modified;
        newestTarget = target.get();
      }
    }
    return Optional.ofNullable(newestTarget);
  }

  public static String computeProgramSessionId(Program program) {
    Objects.requireNonNull(program, "program");
    String recordedMd5 = program.getExecutableMD5();
    if (recordedMd5 != null && MD5_HEX.matcher(recordedMd5.trim()).matches()) {
      return recordedMd5.trim().toLowerCase(Locale.ROOT);
    }

    String executablePath = program.getExecutablePath();
    if (executablePath != null && !executablePath.isBlank()) {
      Optional<String> fileMd5 = md5OfRegularFile(Path.of(executablePath.trim()));
      if (fileMd5.isPresent()) {
        return fileMd5.get();
      }
    }

    DomainFile domainFile = program.getDomainFile();
    String domainPath = domainFile == null ? "" : String.valueOf(domainFile.getPathname());
    String identity = domainPath + ":" + program.getName();
    return md5OfBytes(identity.getBytes(StandardCharsets.UTF_8));
  }

  private static Set<Path> unixRuntimeRoots(String xdgRuntimeDir, String tmpDir) {
    Set<Path> roots = new LinkedHashSet<>();
    addRuntimeRoot(roots, xdgRuntimeDir);
    addRuntimeRoot(roots, tmpDir);
    roots.add(Path.of("/tmp"));
    return roots;
  }

  private static void addRuntimeRoot(Set<Path> roots, String rawDir) {
    if (rawDir == null || rawDir.isBlank()) {
      return;
    }
    try {
      Path canonical = Path.of(rawDir.trim()).toRealPath();
      if (!hasHiddenSegment(canonical)) {
        roots.add(canonical);
      }
    } catch (IOException ignored) {
      // Skip paths that do not exist on disk.
    }
  }

  private static boolean hasHiddenSegment(Path path) {
    for (Path component : path) {
      String segment = component.getFileName().toString();
      if (segment.startsWith(".") && !".".equals(segment) && !"..".equals(segment)) {
        return true;
      }
    }
    return false;
  }

  private static Optional<AttachTarget> readAttachDirectory(
      Path dir, String userName, boolean requirePosixOwnerOnly) {
    try {
      if (Files.isSymbolicLink(dir) || !Files.isDirectory(dir, LinkOption.NOFOLLOW_LINKS)) {
        return Optional.empty();
      }
      if (requirePosixOwnerOnly && !isOwnedPrivateDirectory(dir, userName)) {
        return Optional.empty();
      }
      Path serverFile = dir.resolve(SERVER_STATE_FILE);
      Path attachFile = dir.resolve(GUI_ATTACH_FILE);
      if (Files.isSymbolicLink(serverFile)
          || Files.isSymbolicLink(attachFile)
          || !Files.isRegularFile(serverFile, LinkOption.NOFOLLOW_LINKS)
          || !Files.isRegularFile(attachFile, LinkOption.NOFOLLOW_LINKS)) {
        return Optional.empty();
      }
      String rawJson = Files.readString(attachFile, StandardCharsets.UTF_8);
      Object parsed = JsonUtil.parse(rawJson);
      if (!(parsed instanceof Map<?, ?> map)) {
        return Optional.empty();
      }
      Object wsUrl = map.get("wsUrl");
      Object token = map.get("token");
      if (!(wsUrl instanceof String urlText) || !(token instanceof String tokenText)) {
        return Optional.empty();
      }
      return Optional.of(new AttachTarget(urlText, tokenText));
    } catch (IOException | IllegalArgumentException ignored) {
      return Optional.empty();
    }
  }

  private static boolean isOwnedPrivateDirectory(Path dir, String userName) {
    try {
      PosixFileAttributes attrs =
          Files.readAttributes(dir, PosixFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
      if (userName != null
          && !userName.isBlank()
          && !userName.equals(attrs.owner().getName())) {
        return false;
      }
      for (PosixFilePermission perm : attrs.permissions()) {
        if (NON_OWNER_PERMISSIONS.contains(perm)) {
          return false;
        }
      }
      return true;
    } catch (UnsupportedOperationException unsupported) {
      return true;
    } catch (IOException error) {
      return false;
    }
  }

  private static FileTime lastModifiedOrEpoch(Path file) {
    try {
      return Files.getLastModifiedTime(file, LinkOption.NOFOLLOW_LINKS);
    } catch (IOException ignored) {
      return FileTime.fromMillis(0L);
    }
  }

  private static Optional<String> md5OfRegularFile(Path path) {
    if (!Files.isRegularFile(path)) {
      return Optional.empty();
    }
    try (InputStream in = Files.newInputStream(path)) {
      MessageDigest digest = md5Digest();
      byte[] buffer = new byte[8192];
      int read;
      while ((read = in.read(buffer)) != -1) {
        digest.update(buffer, 0, read);
      }
      return Optional.of(HexFormat.of().formatHex(digest.digest()));
    } catch (IOException ignored) {
      return Optional.empty();
    }
  }

  static String md5OfBytes(byte[] bytes) {
    MessageDigest digest = md5Digest();
    return HexFormat.of().formatHex(digest.digest(bytes));
  }

  private static MessageDigest md5Digest() {
    try {
      return MessageDigest.getInstance("MD5");
    } catch (NoSuchAlgorithmException impossible) {
      throw new IllegalStateException("MD5 algorithm is unavailable", impossible);
    }
  }
}
