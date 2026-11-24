package app.byteland.ghidra.api;

import app.byteland.ghidra.JsonUtil;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.snakeyaml.engine.v2.api.Load;
import org.snakeyaml.engine.v2.api.LoadSettings;

/**
 * Checks automated ASD-STE100 rules in English documents and source comments.
 */
final class SimplifiedEnglishVerifier {
  private static final int INSTRUCTION_WORD_LIMIT = 20;
  private static final int DESCRIPTION_WORD_LIMIT = 25;
  private static final int PARAGRAPH_SENTENCE_LIMIT = 6;

  private static final List<String> FORBIDDEN_WORDS =
      List.of(
          "allow",
          "allows",
          "allowed",
          "allowing",
          "could",
          "ensure",
          "ensures",
          "ensured",
          "ensuring",
          "may",
          "might",
          "obtain",
          "obtains",
          "obtained",
          "obtaining",
          "should",
          "utilize",
          "utilizes",
          "utilized",
          "utilizing",
          "via",
          "would");

  private static final List<String> CONTRACTIONS =
      List.of(
          "aren't",
          "can't",
          "couldn't",
          "didn't",
          "doesn't",
          "don't",
          "hadn't",
          "hasn't",
          "haven't",
          "isn't",
          "mustn't",
          "shouldn't",
          "wasn't",
          "weren't",
          "won't",
          "wouldn't");

  private static final List<String> PHRASAL_VERBS =
      List.of(
          "carry out",
          "check out",
          "clean up",
          "come back",
          "find out",
          "get rid of",
          "go away",
          "look at",
          "look for",
          "put together",
          "set up",
          "shut down",
          "start up",
          "try again",
          "turn off",
          "turn on");

  private static final List<String> LATIN_ABBREVIATIONS = List.of("e.g.", "i.e.", "etc.");

  private static final Set<String> ING_EXCEPTIONS =
      Set.of(
          "coding",
          "contributing",
          "during",
          "encoding",
          "engineering",
          "formatting",
          "ing",
          "launching",
          "nothing",
          "operating",
          "ping",
          "rebinding",
          "starting",
          "string",
          "troubleshooting",
          "warning");

  private static final Set<String> INSTRUCTION_VERBS =
      Set.of(
          "add",
          "build",
          "call",
          "check",
          "choose",
          "clone",
          "close",
          "configure",
          "connect",
          "copy",
          "create",
          "define",
          "delete",
          "describe",
          "download",
          "edit",
          "enter",
          "examine",
          "give",
          "include",
          "install",
          "keep",
          "limit",
          "list",
          "make",
          "merge",
          "open",
          "pass",
          "put",
          "read",
          "register",
          "remove",
          "replace",
          "report",
          "review",
          "run",
          "save",
          "select",
          "send",
          "set",
          "start",
          "stop",
          "submit",
          "use",
          "verify",
          "wait",
          "write");

  private static final Set<String> LOCALIZED_DIRECTORIES = Set.of("ja", "zh");

  private static final Set<String> CHECKED_EXTENSIONS =
      Set.of(
          "gradle",
          "java",
          "json",
          "md",
          "rs",
          "sh",
          "svg",
          "template",
          "toml",
          "yaml",
          "yml");

  private SimplifiedEnglishVerifier() {}

  static void verify(Path root, List<String> violations) throws IOException {
    List<Path> files = collectFiles(root);
    Path asyncApiContract = root.resolve("docs/asyncapi.yaml");

    for (Path path : files) {
      String source = Files.readString(path, StandardCharsets.UTF_8);
      String relative = GitHygieneVerifier.relativePath(root, path);
      String extension = extensionOf(path);
      switch (extension) {
        case "md" -> checkMarkdown(relative, source, violations);
        case "rs", "java", "template", "gradle" ->
            checkSlashComments(relative, source, violations);
        case "sh" -> checkHashComments(relative, source, violations);
        case "toml" -> checkToml(relative, source, violations);
        case "json" -> checkJson(relative, source, violations);
        case "yaml", "yml" -> {
          if (path.equals(asyncApiContract)) {
            checkYamlContract(relative, source, violations);
          } else if (source.stripLeading().startsWith("{")) {
            checkJson(relative, source, violations);
          } else {
            checkYaml(relative, source, violations);
          }
        }
        case "svg" -> checkSvg(relative, source, violations);
        default -> {}
      }
    }
  }

  static List<Path> collectFiles(Path root) throws IOException {
    List<Path> files = new ArrayList<>();
    walkDirectory(root, files);
    files.sort(Comparator.naturalOrder());
    return List.copyOf(files);
  }

  private static void walkDirectory(Path directory, List<Path> files) throws IOException {
    try (Stream<Path> entries = Files.list(directory)) {
      for (Path entry : entries.toList()) {
        String name = entry.getFileName().toString();
        if (Files.isDirectory(entry, LinkOption.NOFOLLOW_LINKS)) {
          if (!RepositoryRulesVerifier.isIgnoredDirectory(name)
              && !LOCALIZED_DIRECTORIES.contains(name)) {
            walkDirectory(entry, files);
          }
        } else if (Files.isRegularFile(entry, LinkOption.NOFOLLOW_LINKS)
            && isCheckedFile(entry)) {
          files.add(entry);
        }
      }
    }
  }

  static boolean isCheckedFile(Path path) {
    String name = path.getFileName().toString();
    if ("CHANGELOG.md".equals(name) || name.contains(".ja-") || name.contains(".zh-")) {
      return false;
    }
    return CHECKED_EXTENSIONS.contains(extensionOf(path));
  }

  static void checkMarkdown(String path, String source, List<String> violations) {
    StringBuilder paragraph = new StringBuilder();
    int[] paragraphLine = {0};
    boolean inFence = false;
    List<String> lines = source.lines().toList();
    for (int index = 0; index < lines.size(); index++) {
      int number = index + 1;
      String trimmed = lines.get(index).strip();
      if (trimmed.startsWith("```") || trimmed.startsWith("~~~")) {
        flush(path, paragraphLine[0], paragraph, violations);
        inFence = !inFence;
        continue;
      }
      if (inFence) {
        continue;
      }
      if (trimmed.isEmpty() || trimmed.startsWith("#") || isTableSeparator(trimmed)) {
        flush(path, paragraphLine[0], paragraph, violations);
        continue;
      }
      if (trimmed.startsWith("|")) {
        flush(path, paragraphLine[0], paragraph, violations);
        for (String cell : splitPreservingEmpty(trimChar(trimmed, '|'), '|')) {
          checkText(path, number, cell, violations);
        }
        continue;
      }
      if (isSeparateMarkdownLine(trimmed)) {
        flush(path, paragraphLine[0], paragraph, violations);
        checkText(path, number, trimMarkdownPrefix(trimmed), violations);
        continue;
      }
      if (paragraph.isEmpty()) {
        paragraphLine[0] = number;
      } else {
        paragraph.append(' ');
      }
      paragraph.append(trimmed);
    }
    flush(path, paragraphLine[0], paragraph, violations);
  }

  static void checkSlashComments(String path, String source, List<String> violations) {
    StringBuilder paragraph = new StringBuilder();
    int[] paragraphLine = {0};
    boolean inBlock = false;
    boolean inFence = false;
    List<String> lines = source.lines().toList();
    for (int index = 0; index < lines.size(); index++) {
      int number = index + 1;
      String trimmed = lines.get(index).strip();
      String comment = null;
      if (inBlock) {
        String value = trimmed.endsWith("*/") ? trimmed.substring(0, trimmed.length() - 2) : trimmed;
        value = trimLeadingChar(value.strip(), '*').strip();
        comment = value;
        if (trimmed.contains("*/")) {
          inBlock = false;
        }
      } else if (trimmed.startsWith("//")) {
        String value = trimmed.substring(2);
        comment = trimLeadingSlashOrBang(value).strip();
      } else if (trimmed.startsWith("/*")) {
        inBlock = !trimmed.contains("*/");
        String value = trimLeadingChar(trimmed.substring(2), '*');
        value = stripRepeatedSuffix(value, "*/").strip();
        comment = value;
      }
      if (comment == null) {
        flush(path, paragraphLine[0], paragraph, violations);
        continue;
      }
      if (comment.startsWith("```")) {
        flush(path, paragraphLine[0], paragraph, violations);
        inFence = !inFence;
        continue;
      }
      if (inFence) {
        continue;
      }
      pushCommentText(path, number, comment, paragraphLine, paragraph, violations);
    }
    flush(path, paragraphLine[0], paragraph, violations);
  }

  static void checkHashComments(String path, String source, List<String> violations) {
    StringBuilder paragraph = new StringBuilder();
    int[] paragraphLine = {0};
    List<String> lines = source.lines().toList();
    for (int index = 0; index < lines.size(); index++) {
      int number = index + 1;
      String trimmed = lines.get(index).strip();
      if (trimmed.startsWith("#!")) {
        continue;
      }
      if (trimmed.startsWith("#")) {
        pushCommentText(
            path, number, trimmed.substring(1).strip(), paragraphLine, paragraph, violations);
      } else {
        flush(path, paragraphLine[0], paragraph, violations);
      }
    }
    flush(path, paragraphLine[0], paragraph, violations);
  }

  static void checkToml(String path, String source, List<String> violations) {
    checkHashComments(path, source, violations);
    List<String> lines = source.lines().toList();
    for (int index = 0; index < lines.size(); index++) {
      String line = lines.get(index);
      int equals = line.indexOf('=');
      if (equals < 0) {
        continue;
      }
      String key = line.substring(0, equals).strip();
      if ("description".equals(key)) {
        String value = trimChar(line.substring(equals + 1).strip(), '"');
        checkText(path, index + 1, value, violations);
      }
    }
  }

  private static void pushCommentText(
      String path,
      int line,
      String text,
      int[] paragraphLine,
      StringBuilder paragraph,
      List<String> violations) {
    if (text.isEmpty()) {
      flush(path, paragraphLine[0], paragraph, violations);
      return;
    }
    if (text.startsWith("|")) {
      flush(path, paragraphLine[0], paragraph, violations);
      if (!isTableSeparator(text)) {
        for (String cell : splitPreservingEmpty(trimChar(text, '|'), '|')) {
          checkText(path, line, cell, violations);
        }
      }
      return;
    }
    if (text.startsWith("@") || isSeparateMarkdownLine(text) || text.startsWith("#")) {
      flush(path, paragraphLine[0], paragraph, violations);
      checkText(path, line, trimMarkdownPrefix(text), violations);
      return;
    }
    if (paragraph.isEmpty()) {
      paragraphLine[0] = line;
    } else {
      paragraph.append(' ');
    }
    paragraph.append(text);
  }

  static void checkYaml(String path, String source, List<String> violations) {
    checkHashComments(path, source, violations);
    Integer blockIndent = null;
    List<String> lines = source.lines().toList();
    for (int index = 0; index < lines.size(); index++) {
      String line = lines.get(index);
      String trimmed = line.strip();
      int indent = line.length() - line.stripLeading().length();
      if (blockIndent != null) {
        if (trimmed.isEmpty()) {
          continue;
        }
        if (indent > blockIndent) {
          checkText(path, index + 1, trimmed, violations);
          continue;
        }
        blockIndent = null;
      }
      int colon = trimmed.indexOf(':');
      if (colon < 0) {
        continue;
      }
      String key = stripRepeatedPrefix(trimmed.substring(0, colon), "- ").strip();
      String value = trimmed.substring(colon + 1).strip();
      if (("description".equals(key) || "placeholder".equals(key) || "value".equals(key))
          && ("|".equals(value) || ">".equals(value) || "|-".equals(value) || ">-".equals(value))) {
        blockIndent = indent;
      } else if (("about".equals(key)
              || "description".equals(key)
              || "label".equals(key)
              || "name".equals(key))
          && !value.isEmpty()) {
        checkText(path, index + 1, value, violations);
      }
    }
  }

  static void checkYamlContract(String path, String source, List<String> violations) {
    Object parsed;
    try {
      parsed = new Load(LoadSettings.builder().build()).loadFromString(source);
    } catch (RuntimeException error) {
      violations.add(path + ":1: invalid YAML: " + error.getMessage());
      return;
    }
    checkStructuredValue(path, parsed, violations);
  }

  static void checkJson(String path, String source, List<String> violations) {
    Object parsed;
    try {
      parsed = JsonUtil.parse(source);
    } catch (RuntimeException ignored) {
      return;
    }
    checkStructuredValue(path, parsed, violations);
  }

  private static void checkStructuredValue(String path, Object value, List<String> violations) {
    if (value instanceof Map<?, ?> map) {
      for (Map.Entry<?, ?> entry : map.entrySet()) {
        String key = String.valueOf(entry.getKey());
        Object child = entry.getValue();
        if (("description".equals(key) || "title".equals(key)) && child instanceof String text) {
          checkVocabulary(path, 1, text, violations);
        }
        checkStructuredValue(path, child, violations);
      }
    } else if (value instanceof Iterable<?> array) {
      for (Object child : array) {
        checkStructuredValue(path, child, violations);
      }
    }
  }

  static void checkSvg(String path, String source, List<String> violations) {
    List<String> lines = source.lines().toList();
    for (int index = 0; index < lines.size(); index++) {
      int number = index + 1;
      String line = lines.get(index);
      int commentStart = line.indexOf("<!--");
      if (commentStart >= 0) {
        String text = stripRepeatedSuffix(line.substring(commentStart + 4), "-->").strip();
        checkText(path, number, text, violations);
      }
      if (line.contains("<text")) {
        checkText(path, number, line, violations);
      }
    }
  }

  private static void flush(
      String path, int line, StringBuilder paragraph, List<String> violations) {
    if (paragraph.isEmpty()) {
      return;
    }
    checkText(path, line, paragraph.toString(), violations);
    paragraph.setLength(0);
  }

  static void checkText(String path, int line, String text, List<String> violations) {
    String visible = visibleText(text);
    checkVocabulary(path, line, text, violations);
    checkLengths(path, line, visible, violations);
  }

  static void checkVocabulary(String path, int line, String text, List<String> violations) {
    String visible = visibleText(text);
    String lower = visible.toLowerCase(Locale.ROOT);
    List<String> tokenWords = words(lower);

    for (String forbidden : FORBIDDEN_WORDS) {
      if (tokenWords.contains(forbidden)) {
        violations.add(path + ":" + line + ": prohibited word: " + forbidden);
      }
    }
    for (String contraction : CONTRACTIONS) {
      if (tokenWords.contains(contraction)) {
        violations.add(path + ":" + line + ": contraction: " + contraction);
      }
    }
    for (String phrase : PHRASAL_VERBS) {
      if (containsPhrase(tokenWords, phrase)) {
        violations.add(path + ":" + line + ": phrasal verb: " + phrase);
      }
    }
    for (String abbreviation : LATIN_ABBREVIATIONS) {
      if (lower.contains(abbreviation)) {
        violations.add(path + ":" + line + ": Latin abbreviation: " + abbreviation);
      }
    }
    for (String word : tokenWords) {
      if (word.endsWith("ing") && !ING_EXCEPTIONS.contains(word)) {
        violations.add(path + ":" + line + ": nontechnical -ing form: " + word);
      }
    }
  }

  static void checkLengths(String path, int line, String text, List<String> violations) {
    List<String> sentences = splitSentences(text);
    if (sentences.size() > PARAGRAPH_SENTENCE_LIMIT) {
      violations.add(
          path
              + ":"
              + line
              + ": paragraph has "
              + sentences.size()
              + " sentences; maximum is "
              + PARAGRAPH_SENTENCE_LIMIT);
    }
    for (String rawSentence : sentences) {
      int boldColon = rawSentence.indexOf("**:");
      String sentence = boldColon >= 0 ? rawSentence.substring(boldColon + 3) : rawSentence;
      List<String> sentenceWords = words(sentence);
      if (sentenceWords.isEmpty()) {
        continue;
      }
      boolean isInstruction = INSTRUCTION_VERBS.contains(sentenceWords.getFirst());
      int limit = isInstruction ? INSTRUCTION_WORD_LIMIT : DESCRIPTION_WORD_LIMIT;
      if (sentenceWords.size() > limit) {
        violations.add(
            path
                + ":"
                + line
                + ": sentence has "
                + sentenceWords.size()
                + " words; maximum is "
                + limit);
      }
    }
  }

  static String visibleText(String text) {
    StringBuilder result = new StringBuilder(text.length());
    boolean code = false;
    boolean quote = false;
    boolean tag = false;
    int index = 0;
    while (index < text.length()) {
      char character = text.charAt(index);
      if (tag) {
        if (character == '>') {
          tag = false;
          result.append(' ');
        }
        index++;
        continue;
      }
      if (!code && !quote && character == '<') {
        tag = true;
        index++;
        continue;
      }
      if (!quote && character == '`') {
        code = !code;
        if (!code) {
          result.append(" CODE ");
        }
        index++;
        continue;
      }
      if (!code && character == '"') {
        quote = !quote;
        if (!quote) {
          result.append(" QUOTE ");
        }
        index++;
        continue;
      }
      if (code || quote) {
        index++;
        continue;
      }
      if (character == ']' && index + 1 < text.length() && text.charAt(index + 1) == '(') {
        index += 2;
        while (index < text.length()) {
          char next = text.charAt(index);
          index++;
          if (next == ')') {
            break;
          }
        }
        result.append(' ');
        continue;
      }
      result.append(character);
      index++;
    }
    return result.toString();
  }

  static List<String> splitSentences(String text) {
    List<String> sentences = new ArrayList<>();
    int start = 0;
    for (int index = 0; index < text.length(); index++) {
      char character = text.charAt(index);
      if (character != '.' && character != '!' && character != '?') {
        continue;
      }
      int end = index + 1;
      if (end < text.length() && !Character.isWhitespace(text.codePointAt(end))) {
        continue;
      }
      String sentence = text.substring(start, end).strip();
      if (!sentence.isEmpty()) {
        sentences.add(sentence);
      }
      start = end;
    }
    String tail = text.substring(start).strip();
    if (!tail.isEmpty()) {
      sentences.add(tail);
    }
    return sentences;
  }

  static List<String> words(String text) {
    List<String> collected = new ArrayList<>();
    int start = -1;
    for (int index = 0; index <= text.length(); index++) {
      char ch = index < text.length() ? text.charAt(index) : ' ';
      if (isWordChar(ch)) {
        if (start < 0) {
          start = index;
        }
      } else if (start >= 0) {
        addWordToken(text.substring(start, index), collected);
        start = -1;
      }
    }
    return collected;
  }

  private static void addWordToken(String raw, List<String> collected) {
    boolean hasAlpha = false;
    for (int index = 0; index < raw.length(); index++) {
      if (isAsciiAlphabetic(raw.charAt(index))) {
        hasAlpha = true;
        break;
      }
    }
    if (!hasAlpha) {
      return;
    }
    int begin = 0;
    int end = raw.length();
    while (begin < end && (raw.charAt(begin) == '-' || raw.charAt(begin) == '\'')) {
      begin++;
    }
    while (end > begin && (raw.charAt(end - 1) == '-' || raw.charAt(end - 1) == '\'')) {
      end--;
    }
    if (begin < end) {
      collected.add(raw.substring(begin, end).toLowerCase(Locale.ROOT));
    }
  }

  private static boolean containsPhrase(List<String> words, String phrase) {
    String[] phraseWords = phrase.split("\\s+");
    if (words.size() < phraseWords.length) {
      return false;
    }
    for (int start = 0; start <= words.size() - phraseWords.length; start++) {
      boolean allEqual = true;
      for (int offset = 0; offset < phraseWords.length; offset++) {
        if (!words.get(start + offset).equals(phraseWords[offset])) {
          allEqual = false;
          break;
        }
      }
      if (allEqual) {
        return true;
      }
    }
    return false;
  }

  private static boolean isTableSeparator(String text) {
    String value = trimChar(text, '|').strip();
    if (value.isEmpty()) {
      return false;
    }
    for (int index = 0; index < value.length(); index++) {
      char ch = value.charAt(index);
      if (ch != '-' && ch != ':' && ch != '|' && ch != ' ') {
        return false;
      }
    }
    return true;
  }

  private static boolean isSeparateMarkdownLine(String text) {
    return text.startsWith("- ")
        || text.startsWith("* ")
        || text.startsWith("+ ")
        || text.startsWith("> ")
        || text.startsWith("<!--")
        || hasNumberedPrefix(text);
  }

  private static boolean hasNumberedPrefix(String text) {
    int digits = countLeadingDigits(text);
    if (digits == 0) {
      return false;
    }
    String rest = text.substring(digits);
    return rest.startsWith(". ") || rest.startsWith(") ");
  }

  private static String trimMarkdownPrefix(String text) {
    if (text.startsWith("<!--")) {
      return stripRepeatedSuffix(stripRepeatedPrefix(text, "<!--"), "-->").strip();
    }
    if (!text.isEmpty()) {
      char first = text.charAt(0);
      if (first == '-' || first == '*' || first == '+' || first == '>') {
        return text.substring(1).stripLeading();
      }
    }
    int digits = countLeadingDigits(text);
    String rest = text.substring(digits);
    if (rest.startsWith(". ") || rest.startsWith(") ")) {
      return rest.substring(2);
    }
    return rest;
  }

  private static int countLeadingDigits(String text) {
    int index = 0;
    while (index < text.length() && text.charAt(index) >= '0' && text.charAt(index) <= '9') {
      index++;
    }
    return index;
  }

  private static List<String> splitPreservingEmpty(String text, char separator) {
    List<String> parts = new ArrayList<>();
    int start = 0;
    for (int index = 0; index < text.length(); index++) {
      if (text.charAt(index) == separator) {
        parts.add(text.substring(start, index));
        start = index + 1;
      }
    }
    parts.add(text.substring(start));
    return parts;
  }

  private static String trimChar(String text, char target) {
    int start = 0;
    int end = text.length();
    while (start < end && text.charAt(start) == target) {
      start++;
    }
    while (end > start && text.charAt(end - 1) == target) {
      end--;
    }
    return text.substring(start, end);
  }

  private static String trimLeadingChar(String text, char target) {
    int start = 0;
    while (start < text.length() && text.charAt(start) == target) {
      start++;
    }
    return text.substring(start);
  }

  private static String trimLeadingSlashOrBang(String text) {
    int start = 0;
    while (start < text.length() && (text.charAt(start) == '/' || text.charAt(start) == '!')) {
      start++;
    }
    return text.substring(start);
  }

  private static String stripRepeatedPrefix(String text, String prefix) {
    String current = text;
    while (current.startsWith(prefix)) {
      current = current.substring(prefix.length());
    }
    return current;
  }

  private static String stripRepeatedSuffix(String text, String suffix) {
    String current = text;
    while (current.endsWith(suffix)) {
      current = current.substring(0, current.length() - suffix.length());
    }
    return current;
  }

  private static boolean isWordChar(char ch) {
    return isAsciiAlphabetic(ch) || ch == '-' || ch == '\'';
  }

  private static boolean isAsciiAlphabetic(char ch) {
    return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z');
  }

  private static String extensionOf(Path path) {
    String name = path.getFileName().toString();
    int dot = name.lastIndexOf('.');
    return dot <= 0 ? "" : name.substring(dot + 1);
  }
}
