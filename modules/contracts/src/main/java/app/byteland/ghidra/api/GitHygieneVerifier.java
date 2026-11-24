package app.byteland.ghidra.api;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Checks tracked Git paths, file sizes, duplicate digests, and catalog counts.
 */
final class GitHygieneVerifier {
  private static final Pattern UNEXPECTED_FILES =
      Pattern.compile(
          "(^|/)(build|out|bin)/|(^|/)\\.gradle/|(^|/)\\.idea/|(^|/)\\.vscode/"
              + "|(^|/)\\.DS_Store$|\\.iml$");
  private static final Pattern LEGACY_GRADLE =
      Pattern.compile("(^|/)(build|settings)\\.gradle\\.kts$");
  private static final Pattern LAUNCHER_TEMPLATE =
      Pattern.compile("^modules/launcher/src/main/templates/[^/]+\\.template$");
  private static final Pattern GENERATED_LAUNCHER =
      Pattern.compile("(^|/)(Bridge|GhidraMcp)\\.java$");
  private static final Pattern STALE_PROTOCOL_PATHS =
      Pattern.compile(":tooling:contract-docs|distribution/src/main/templates");
  private static final Pattern API_METHOD_ROW = Pattern.compile("^\\| `[^`]+` \\|.*");

  private GitHygieneVerifier() {}

  static void verify(Path root, List<String> violations) throws IOException {
    List<String> tracked = gitNullSeparatedPaths(root, "ls-files", "--cached", "-z");
    List<String> ignoredTracked =
        gitNullSeparatedPaths(root, "ls-files", "-ci", "--exclude-standard", "-z");

    for (String path : ignoredTracked) {
      violations.add(path + ": ignored files are tracked");
    }

    int templateCount = 0;
    Map<String, List<String>> filesByDigest = new LinkedHashMap<>();

    for (String candidate : tracked) {
      if (UNEXPECTED_FILES.matcher(candidate).find()) {
        violations.add(candidate + ": generated or local files are candidates for commit");
      }
      if (LEGACY_GRADLE.matcher(candidate).find()) {
        violations.add(candidate + ": obsolete Kotlin Gradle files remain");
      }
      if (candidate.startsWith("src/")) {
        violations.add(candidate + ": the root project must not own source files");
      }
      if (LAUNCHER_TEMPLATE.matcher(candidate).matches()) {
        templateCount++;
      }
      if (GENERATED_LAUNCHER.matcher(candidate).find()) {
        violations.add(candidate + ": generated launcher scripts must not be committed");
      }

      Path file = root.resolve(candidate);
      if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
        continue;
      }
      byte[] bytes = Files.readAllBytes(file);
      if (bytes.length == 0) {
        violations.add(candidate + ": zero-byte files are candidates for commit");
        continue;
      }
      String digest = sha256Hex(bytes);
      filesByDigest.computeIfAbsent(digest, ignored -> new ArrayList<>()).add(candidate);
    }

    if (templateCount != 1) {
      violations.add(
          "modules/launcher/src/main/templates: expected one launcher template, found "
              + templateCount);
    }

    for (List<String> group : filesByDigest.values()) {
      if (group.size() > 1) {
        violations.add(
            "exact duplicate files are candidates for commit: " + String.join(", ", group));
      }
    }

    checkStaleProtocolPaths(root, tracked, violations);
    checkApiMethodCount(root, violations);
  }

  private static void checkStaleProtocolPaths(
      Path root, List<String> tracked, List<String> violations) throws IOException {
    Set<Path> markdownFiles = new TreeSet<>(Comparator.comparing(Path::toString));
    for (String candidate : tracked) {
      if ((candidate.startsWith("README") && candidate.endsWith(".md") && !candidate.contains("/"))
          || (candidate.startsWith("docs/") && candidate.endsWith(".md"))) {
        Path resolved = root.resolve(candidate);
        if (Files.isRegularFile(resolved, LinkOption.NOFOLLOW_LINKS)) {
          markdownFiles.add(resolved);
        }
      }
    }
    try (Stream<Path> rootEntries = Files.list(root)) {
      rootEntries
          .filter(path -> Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
          .filter(
              path -> {
                String name = path.getFileName().toString();
                return name.startsWith("README") && name.endsWith(".md");
              })
          .forEach(markdownFiles::add);
    }
    Path docsDir = root.resolve("docs");
    if (Files.isDirectory(docsDir, LinkOption.NOFOLLOW_LINKS)) {
      collectMarkdownFiles(docsDir, markdownFiles);
    }

    for (Path file : markdownFiles) {
      List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
      String relative = relativePath(root, file);
      for (int index = 0; index < lines.size(); index++) {
        if (STALE_PROTOCOL_PATHS.matcher(lines.get(index)).find()) {
          violations.add(relative + ":" + (index + 1) + ": stale protocol or build paths remain");
        }
      }
    }
  }

  private static void collectMarkdownFiles(Path directory, Set<Path> files) throws IOException {
    try (Stream<Path> entries = Files.list(directory)) {
      for (Path entry : entries.sorted().toList()) {
        if (Files.isDirectory(entry, LinkOption.NOFOLLOW_LINKS)) {
          collectMarkdownFiles(entry, files);
        } else if (Files.isRegularFile(entry, LinkOption.NOFOLLOW_LINKS)
            && entry.getFileName().toString().endsWith(".md")) {
          files.add(entry);
        }
      }
    }
  }

  private static void checkApiMethodCount(Path root, List<String> violations) throws IOException {
    Path apiMarkdown = root.resolve("docs/api.md");
    if (!Files.isRegularFile(apiMarkdown, LinkOption.NOFOLLOW_LINKS)) {
      violations.add("docs/api.md: absent method reference file");
      return;
    }
    long count =
        Files.readString(apiMarkdown, StandardCharsets.UTF_8)
            .lines()
            .filter(line -> API_METHOD_ROW.matcher(line).matches())
            .count();
    int expected = ApiRegistry.catalog().methods().size();
    if (count != expected) {
      violations.add("docs/api.md: documents " + count + " methods; expected " + expected);
    }
  }

  static List<String> gitNullSeparatedPaths(Path root, String... gitArgs) throws IOException {
    List<String> command = new ArrayList<>(gitArgs.length + 1);
    command.add("git");
    command.addAll(List.of(gitArgs));

    Process process = new ProcessBuilder(command).directory(root.toFile()).start();
    CompletableFuture<byte[]> stderrFuture =
        CompletableFuture.supplyAsync(() -> readAllBytesUnchecked(process.getErrorStream()));
    byte[] stdoutBytes = readAllBytesUnchecked(process.getInputStream());
    int exitCode;
    try {
      exitCode = process.waitFor();
    } catch (InterruptedException error) {
      Thread.currentThread().interrupt();
      process.destroyForcibly();
      throw new IOException("Interrupted command: " + String.join(" ", command), error);
    }
    String stderr = new String(stderrFuture.join(), StandardCharsets.UTF_8).strip();
    if (exitCode != 0) {
      String detail = stderr.isEmpty() ? "" : " (" + stderr + ")";
      throw new IllegalStateException(
          "Git command exited with status "
              + exitCode
              + ": "
              + String.join(" ", command)
              + detail);
    }

    String output = new String(stdoutBytes, StandardCharsets.UTF_8);
    if (output.isEmpty()) {
      return List.of();
    }
    Set<String> sorted = new TreeSet<>();
    int start = 0;
    for (int index = 0; index < output.length(); index++) {
      if (output.charAt(index) == '\0') {
        if (index > start) {
          sorted.add(output.substring(start, index));
        }
        start = index + 1;
      }
    }
    if (start < output.length()) {
      sorted.add(output.substring(start));
    }
    return List.copyOf(sorted);
  }

  private static byte[] readAllBytesUnchecked(InputStream stream) {
    try (InputStream input = stream) {
      return input.readAllBytes();
    } catch (IOException error) {
      throw new IllegalStateException("Cannot read process stream", error);
    }
  }

  private static String sha256Hex(byte[] bytes) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      return HexFormat.of().formatHex(digest.digest(bytes));
    } catch (NoSuchAlgorithmException error) {
      throw new IllegalStateException("SHA-256 algorithm is unavailable", error);
    }
  }

  static String relativePath(Path root, Path target) {
    return root.relativize(target).toString().replace('\\', '/');
  }
}
