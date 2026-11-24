package app.byteland.ghidra.api;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Checks Java source files outside adapter and launcher for Ghidra API imports.
 */
final class ArchitectureVerifier {
  private static final Set<String> PERMITTED_GHIDRA_MODULES = Set.of("adapter", "launcher");

  private ArchitectureVerifier() {}

  static void verify(Path root, List<String> violations) throws IOException {
    Path modulesDir = root.resolve("modules");
    if (!Files.isDirectory(modulesDir, LinkOption.NOFOLLOW_LINKS)) {
      violations.add("modules: absent modules directory");
      return;
    }
    List<Path> sources = new ArrayList<>();
    collectJavaSources(modulesDir, modulesDir, sources);
    for (Path source : sources) {
      String text = Files.readString(source, StandardCharsets.UTF_8);
      String relative = GitHygieneVerifier.relativePath(root, source);
      for (int line : findForbiddenImportLines(text)) {
        violations.add(relative + ":" + line + ": Ghidra API import outside adapter/launcher");
      }
    }
  }

  private static void collectJavaSources(Path modulesRoot, Path directory, List<Path> files)
      throws IOException {
    try (Stream<Path> entries = Files.list(directory)) {
      for (Path entry : entries.sorted().toList()) {
        String name = entry.getFileName().toString();
        if (Files.isDirectory(entry, LinkOption.NOFOLLOW_LINKS)) {
          if (RepositoryRulesVerifier.isIgnoredDirectory(name)) {
            continue;
          }
          if (directory.equals(modulesRoot) && PERMITTED_GHIDRA_MODULES.contains(name)) {
            continue;
          }
          collectJavaSources(modulesRoot, entry, files);
        } else if (Files.isRegularFile(entry, LinkOption.NOFOLLOW_LINKS)
            && name.endsWith(".java")) {
          files.add(entry);
        }
      }
    }
  }

  static List<Integer> findForbiddenImportLines(String source) {
    List<Token> tokens = tokenizeJava(source);
    List<Integer> lines = new ArrayList<>();
    for (int index = 0; index < tokens.size(); index++) {
      Token current = tokens.get(index);
      if (!"import".equals(current.text())) {
        continue;
      }
      if (index > 0 && ".".equals(tokens.get(index - 1).text())) {
        continue;
      }
      int cursor = index + 1;
      if (cursor < tokens.size()
          && ("static".equals(tokens.get(cursor).text())
              || "module".equals(tokens.get(cursor).text()))) {
        cursor++;
      }
      if (cursor < tokens.size() && "ghidra".equals(tokens.get(cursor).text())) {
        boolean isPackageOrType =
            cursor + 1 >= tokens.size()
                || ".".equals(tokens.get(cursor + 1).text())
                || ";".equals(tokens.get(cursor + 1).text());
        if (isPackageOrType) {
          lines.add(current.line());
        }
      }
    }
    return lines;
  }

  static List<Token> tokenizeJava(String source) {
    List<Token> tokens = new ArrayList<>();
    int length = source.length();
    int index = 0;
    int line = 1;

    while (index < length) {
      char current = source.charAt(index);
      char next = index + 1 < length ? source.charAt(index + 1) : '\0';

      if (current == '\r') {
        line++;
        index += next == '\n' ? 2 : 1;
        continue;
      }
      if (current == '\n') {
        line++;
        index++;
        continue;
      }
      if (Character.isWhitespace(current)) {
        index++;
        continue;
      }

      if (current == '/' && next == '/') {
        index += 2;
        while (index < length && source.charAt(index) != '\n' && source.charAt(index) != '\r') {
          index++;
        }
        continue;
      }

      if (current == '/' && next == '*') {
        index += 2;
        while (index < length) {
          char blockChar = source.charAt(index);
          char blockNext = index + 1 < length ? source.charAt(index + 1) : '\0';
          if (blockChar == '*' && blockNext == '/') {
            index += 2;
            break;
          }
          if (blockChar == '\r') {
            line++;
            index += blockNext == '\n' ? 2 : 1;
          } else if (blockChar == '\n') {
            line++;
            index++;
          } else {
            index++;
          }
        }
        continue;
      }

      if (current == '"' && next == '"' && index + 2 < length && source.charAt(index + 2) == '"') {
        int startLine = line;
        index += 3;
        while (index < length) {
          char textChar = source.charAt(index);
          if (textChar == '\\' && index + 1 < length) {
            index += 2;
            continue;
          }
          if (textChar == '"'
              && index + 2 < length
              && source.charAt(index + 1) == '"'
              && source.charAt(index + 2) == '"') {
            index += 3;
            break;
          }
          if (textChar == '\r') {
            line++;
            index += index + 1 < length && source.charAt(index + 1) == '\n' ? 2 : 1;
          } else if (textChar == '\n') {
            line++;
            index++;
          } else {
            index++;
          }
        }
        tokens.add(new Token("\"\"\"", startLine));
        continue;
      }

      if (current == '"' || current == '\'') {
        char delimiter = current;
        int startLine = line;
        index++;
        while (index < length) {
          char literalChar = source.charAt(index);
          if (literalChar == '\\' && index + 1 < length) {
            index += 2;
            continue;
          }
          if (literalChar == delimiter) {
            index++;
            break;
          }
          if (literalChar == '\r') {
            line++;
            index += index + 1 < length && source.charAt(index + 1) == '\n' ? 2 : 1;
            break;
          }
          if (literalChar == '\n') {
            line++;
            index++;
            break;
          }
          index++;
        }
        tokens.add(new Token(String.valueOf(delimiter), startLine));
        continue;
      }

      int codePoint = source.codePointAt(index);
      if (Character.isJavaIdentifierStart(codePoint)) {
        int start = index;
        int startLine = line;
        index += Character.charCount(codePoint);
        while (index < length) {
          int part = source.codePointAt(index);
          if (!Character.isJavaIdentifierPart(part)) {
            break;
          }
          index += Character.charCount(part);
        }
        tokens.add(new Token(source.substring(start, index), startLine));
        continue;
      }

      tokens.add(new Token(String.valueOf(current), line));
      index++;
    }

    return tokens;
  }

  record Token(String text, int line) {}
}
