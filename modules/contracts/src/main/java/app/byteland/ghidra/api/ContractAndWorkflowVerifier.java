package app.byteland.ghidra.api;

import app.byteland.ghidra.JsonUtil;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.snakeyaml.engine.v2.api.Load;
import org.snakeyaml.engine.v2.api.LoadSettings;

/**
 * Checks MCP tool contracts, GitHub YAML files, URLs, and shell error masks.
 */
final class ContractAndWorkflowVerifier {
  private static final Set<String> IGNORED_DIRECTORIES =
      Set.of(".git", ".gradle", ".worktrees", "build", "node_modules", "target");
  private static final Set<String> TOKEN_SCAN_EXTENSIONS = Set.of("json", "md", "yaml", "yml");
  private static final Set<String> URL_SCAN_EXTENSIONS =
      Set.of("gradle", "json", "md", "py", "sh", "template", "toml", "yaml", "yml");
  private static final Set<String> VALID_EXPRESSION_ROOTS =
      Set.of(
          "always",
          "cancelled",
          "contains",
          "endsWith",
          "env",
          "failure",
          "false",
          "format",
          "fromJSON",
          "github",
          "hashFiles",
          "inputs",
          "join",
          "matrix",
          "needs",
          "null",
          "runner",
          "secrets",
          "startsWith",
          "steps",
          "strategy",
          "success",
          "toJSON",
          "true",
          "vars");
  private static final Pattern CANONICAL_TOOL_NAME = Pattern.compile("ghidra_([a-z][a-z0-9_]*)");
  private static final Pattern EXPRESSION_BLOCK = Pattern.compile("\\$\\{\\{(.*?)\\}\\}", Pattern.DOTALL);
  private static final Pattern CONTEXT_REF =
      Pattern.compile("(?<![A-Za-z0-9_.'\"])([A-Za-z_][A-Za-z0-9_-]*)(?:\\.([A-Za-z0-9_-]+))?(?:\\.([A-Za-z0-9_-]+))?");
  private static final Pattern OR_TRUE_MASK = Pattern.compile("\\|\\|\\s*true\\b");
  private static final Pattern ECHO_SUBSHELL_MASK =
      Pattern.compile("(?:^|[;&|]\\s*)(?:echo|printf)\\b[^\\n#]*\\$\\(");

  private ContractAndWorkflowVerifier() {}

  static void verify(Path root, List<String> violations) throws IOException {
    Set<String> domains = verifyMcpToolsContract(root, violations);
    Pattern retiredToolPattern = buildRetiredToolPattern(domains);

    verifyGithubYamlFiles(root, violations);
    verifyShellScripts(root, violations);
    scanWorkspaceFiles(root, retiredToolPattern, violations);
  }

  static Set<String> verifyMcpToolsContract(Path root, List<String> violations) throws IOException {
    Set<String> expectedDomains = catalogMcpDomains();
    Path contractPath = root.resolve("docs/mcp-tools.json");
    if (!Files.isRegularFile(contractPath, LinkOption.NOFOLLOW_LINKS)) {
      violations.add("docs/mcp-tools.json: absent MCP tools contract");
      return expectedDomains;
    }

    String raw = Files.readString(contractPath, StandardCharsets.UTF_8);
    Map<String, Object> document;
    try {
      document = JsonUtil.parseObject(raw);
    } catch (RuntimeException error) {
      violations.add("docs/mcp-tools.json:1: invalid JSON: " + error.getMessage());
      return expectedDomains;
    }

    Object toolsValue = document.get("tools");
    if (!(toolsValue instanceof List<?> tools) || tools.isEmpty()) {
      violations.add("docs/mcp-tools.json:1: tools array must not be empty");
      return expectedDomains;
    }

    Set<String> contractDomains = new LinkedHashSet<>();
    for (Object item : tools) {
      if (!(item instanceof Map<?, ?> toolMap)) {
        violations.add("docs/mcp-tools.json:1: each tool entry must be a JSON object");
        continue;
      }
      Object nameValue = toolMap.get("name");
      if (!(nameValue instanceof String name) || name.isBlank()) {
        violations.add("docs/mcp-tools.json:1: tool entry has no name");
        continue;
      }
      Matcher matcher = CANONICAL_TOOL_NAME.matcher(name);
      if (!matcher.matches()) {
        violations.add("docs/mcp-tools.json:1: non-canonical MCP tool name: " + name);
        continue;
      }
      contractDomains.add(matcher.group(1));
    }

    if (!contractDomains.equals(expectedDomains)) {
      violations.add(
          "docs/mcp-tools.json:1: MCP domains "
              + contractDomains
              + " do not match catalog domains "
              + expectedDomains);
    }
    return contractDomains.isEmpty() ? expectedDomains : contractDomains;
  }

  static Set<String> catalogMcpDomains() {
    Set<String> domains = new LinkedHashSet<>();
    domains.add("help");
    for (ApiCatalog.MethodDescriptor method : ApiRegistry.catalog().methods()) {
      String name = method.name();
      if ("interface.get".equals(name)) {
        continue;
      }
      int dot = name.indexOf('.');
      String prefix = name.substring(0, dot);
      String domain =
          switch (prefix) {
            case "session" -> "bridge";
            case "program_language" -> "program";
            case "address_space" -> "address";
            case "memory_block" -> "memory";
            case "code_unit", "data_unit", "instruction", "flow_override" -> "listing";
            case "function_call", "function_parameter", "function_local_variable" -> "function";
            case "data_type_category" -> "data_type";
            default -> prefix;
          };
      domains.add(domain);
    }
    return Set.copyOf(domains);
  }

  private static Pattern buildRetiredToolPattern(Set<String> domains) {
    String alternation =
        domains.stream().sorted().map(Pattern::quote).collect(Collectors.joining("|"));
    return Pattern.compile("(?<![A-Za-z0-9_.])ghidra\\.(" + alternation + ")(?![A-Za-z0-9_.])");
  }

  static void verifyGithubYamlFiles(Path root, List<String> violations) throws IOException {
    Path githubDir = root.resolve(".github");
    if (!Files.isDirectory(githubDir, LinkOption.NOFOLLOW_LINKS)) {
      return;
    }
    List<Path> yamlFiles = new ArrayList<>();
    collectFilesByExtension(githubDir, Set.of("yml", "yaml"), yamlFiles);
    LoadSettings settings = LoadSettings.builder().setAllowDuplicateKeys(false).build();

    for (Path file : yamlFiles) {
      String relative = GitHygieneVerifier.relativePath(root, file);
      String source = Files.readString(file, StandardCharsets.UTF_8);
      Object loaded;
      try {
        loaded = new Load(settings).loadFromString(source);
      } catch (RuntimeException error) {
        violations.add(relative + ":1: invalid YAML: " + error.getMessage());
        continue;
      }
      if (!(loaded instanceof Map<?, ?> document)) {
        violations.add(relative + ":1: expected top-level YAML mapping");
        continue;
      }
      checkNoContinueOnError(relative, document, violations);
      if (relative.startsWith(".github/actions/")) {
        verifyCompositeAction(relative, source, document, violations);
      } else if (relative.startsWith(".github/workflows/")) {
        verifyWorkflow(relative, source, document, violations);
      } else if (".github/ISSUE_TEMPLATE/config.yml".equals(relative)) {
        verifyIssueTemplateConfig(relative, document, violations);
      }
    }
  }

  private static void checkNoContinueOnError(
      String relative, Object node, List<String> violations) {
    if (node instanceof Map<?, ?> map) {
      Object flag = map.get("continue-on-error");
      if (Boolean.TRUE.equals(flag)
          || (flag instanceof String text && "true".equalsIgnoreCase(text.strip()))) {
        violations.add(relative + ":1: continue-on-error must not mask failures");
      }
      for (Object child : map.values()) {
        checkNoContinueOnError(relative, child, violations);
      }
    } else if (node instanceof Iterable<?> items) {
      for (Object item : items) {
        checkNoContinueOnError(relative, item, violations);
      }
    }
  }

  private static void verifyCompositeAction(
      String relative, String source, Map<?, ?> document, List<String> violations) {
    checkBalancedExpressions(relative, source, violations);
    Set<String> declaredInputs = new LinkedHashSet<>();
    if (document.get("inputs") instanceof Map<?, ?> inputsMap) {
      for (Object key : inputsMap.keySet()) {
        declaredInputs.add(String.valueOf(key));
      }
    }
    if (!(document.get("runs") instanceof Map<?, ?> runsMap)) {
      violations.add(relative + ":1: composite action has no runs section");
      return;
    }
    if (!"composite".equals(runsMap.get("using"))) {
      return;
    }
    if (!(runsMap.get("steps") instanceof List<?> steps) || steps.isEmpty()) {
      violations.add(relative + ":1: composite action has no steps");
      return;
    }

    Set<String> seenStepIds = new LinkedHashSet<>();
    for (Object item : steps) {
      if (!(item instanceof Map<?, ?> step)) {
        violations.add(relative + ":1: composite step must be a mapping");
        continue;
      }
      validateStepExpressions(relative, step, declaredInputs, seenStepIds, true, violations);
      if (step.containsKey("run")) {
        Object shell = step.get("shell");
        if (!(shell instanceof String shellName) || shellName.isBlank()) {
          violations.add(relative + ":1: composite run step must declare shell");
        }
        if (step.get("run") instanceof String script) {
          checkShellSnippet(relative, 1, script, violations);
        }
      }
      if (step.get("id") instanceof String stepId && !stepId.isBlank()) {
        seenStepIds.add(stepId);
      }
    }
  }

  private static void verifyWorkflow(
      String relative, String source, Map<?, ?> document, List<String> violations) {
    checkBalancedExpressions(relative, source, violations);
    if (!(document.get("jobs") instanceof Map<?, ?> jobs) || jobs.isEmpty()) {
      violations.add(relative + ":1: workflow has no jobs");
      return;
    }
    for (Object jobValue : jobs.values()) {
      if (!(jobValue instanceof Map<?, ?> job)) {
        continue;
      }
      if (!(job.get("steps") instanceof List<?> steps)) {
        continue;
      }
      Set<String> seenStepIds = new LinkedHashSet<>();
      for (Object stepValue : steps) {
        if (!(stepValue instanceof Map<?, ?> step)) {
          continue;
        }
        validateStepExpressions(relative, step, Set.of(), seenStepIds, false, violations);
        if (step.get("run") instanceof String script) {
          checkShellSnippet(relative, 1, script, violations);
        }
        if (step.get("id") instanceof String stepId && !stepId.isBlank()) {
          seenStepIds.add(stepId);
        }
      }
    }
  }

  private static void verifyIssueTemplateConfig(
      String relative, Map<?, ?> document, List<String> violations) {
    if (!(document.get("contact_links") instanceof List<?> links) || links.isEmpty()) {
      violations.add(relative + ":1: issue template config must define contact_links");
      return;
    }
    for (Object item : links) {
      if (!(item instanceof Map<?, ?> link)) {
        continue;
      }
      Object urlValue = link.get("url");
      if (!(urlValue instanceof String url)
          || !url.startsWith("https://github.com/ByteLandTechnology/")) {
        violations.add(
            relative + ":1: contact link must point to ByteLandTechnology: " + urlValue);
      }
    }
  }

  private static void checkBalancedExpressions(
      String relative, String source, List<String> violations) {
    List<String> lines = source.lines().toList();
    for (int index = 0; index < lines.size(); index++) {
      String line = lines.get(index);
      int opens = countOccurrences(line, "${{");
      int closes = countOccurrences(line, "}}");
      if (opens != closes) {
        violations.add(
            relative + ":" + (index + 1) + ": unbalanced GitHub Actions expression delimiter");
      }
    }
  }

  private static int countOccurrences(String text, String token) {
    int count = 0;
    int from = 0;
    while (true) {
      int found = text.indexOf(token, from);
      if (found < 0) {
        return count;
      }
      count++;
      from = found + token.length();
    }
  }

  private static void validateStepExpressions(
      String relative,
      Object value,
      Set<String> declaredInputs,
      Set<String> seenStepIds,
      boolean compositeAction,
      List<String> violations) {
    if (value instanceof String text) {
      Matcher exprMatcher = EXPRESSION_BLOCK.matcher(text);
      while (exprMatcher.find()) {
        String body = stripSingleQuotedLiterals(exprMatcher.group(1));
        if (body.isBlank()) {
          violations.add(relative + ":1: empty GitHub Actions expression");
          continue;
        }
        Matcher refMatcher = CONTEXT_REF.matcher(body);
        while (refMatcher.find()) {
          String rootName = refMatcher.group(1);
          String member = refMatcher.group(2);
          if (!VALID_EXPRESSION_ROOTS.contains(rootName)) {
            violations.add(
                relative + ":1: unknown expression identifier in ${{ }}: " + rootName);
            continue;
          }
          if (compositeAction && "inputs".equals(rootName)) {
            if (member == null || !declaredInputs.contains(member)) {
              violations.add(
                  relative + ":1: undeclared composite action input: inputs." + member);
            }
          }
          if ("steps".equals(rootName)) {
            if (member == null || !seenStepIds.contains(member)) {
              violations.add(relative + ":1: unknown prior step id: steps." + member);
            }
          }
        }
      }
    } else if (value instanceof Map<?, ?> map) {
      for (Object child : map.values()) {
        validateStepExpressions(
            relative, child, declaredInputs, seenStepIds, compositeAction, violations);
      }
    } else if (value instanceof Iterable<?> list) {
      for (Object child : list) {
        validateStepExpressions(
            relative, child, declaredInputs, seenStepIds, compositeAction, violations);
      }
    }
  }

  private static String stripSingleQuotedLiterals(String expression) {
    StringBuilder cleaned = new StringBuilder(expression.length());
    boolean inSingleQuote = false;
    for (int index = 0; index < expression.length(); index++) {
      char current = expression.charAt(index);
      if (current == '\'') {
        if (inSingleQuote
            && index + 1 < expression.length()
            && expression.charAt(index + 1) == '\'') {
          index++;
          continue;
        }
        inSingleQuote = !inSingleQuote;
        cleaned.append(' ');
      } else if (!inSingleQuote) {
        cleaned.append(current);
      }
    }
    return cleaned.toString();
  }

  private static void verifyShellScripts(Path root, List<String> violations) throws IOException {
    Path scriptsDir = root.resolve(".github/scripts");
    if (!Files.isDirectory(scriptsDir, LinkOption.NOFOLLOW_LINKS)) {
      return;
    }
    List<Path> scripts = new ArrayList<>();
    collectFilesByExtension(scriptsDir, Set.of("sh"), scripts);
    for (Path script : scripts) {
      String relative = GitHygieneVerifier.relativePath(root, script);
      String source = Files.readString(script, StandardCharsets.UTF_8);
      checkShellSnippet(relative, 1, source, violations);
    }
  }

  private static void checkShellSnippet(
      String relative, int baseLine, String script, List<String> violations) {
    List<String> lines = script.lines().toList();
    for (int index = 0; index < lines.size(); index++) {
      String trimmed = lines.get(index).strip();
      if (trimmed.isEmpty() || trimmed.startsWith("#")) {
        continue;
      }
      int lineNumber = baseLine + index;
      if (OR_TRUE_MASK.matcher(trimmed).find()) {
        violations.add(relative + ":" + lineNumber + ": forbidden '|| true' error mask");
      }
      if (ECHO_SUBSHELL_MASK.matcher(trimmed).find()) {
        violations.add(
            relative + ":" + lineNumber + ": command substitution inside echo/printf masks exit status");
      }
    }
  }

  private static void scanWorkspaceFiles(
      Path root, Pattern retiredToolPattern, List<String> violations) throws IOException {
    List<Path> files = new ArrayList<>();
    collectWorkspaceFiles(root, files);
    for (Path file : files) {
      String ext = extensionOf(file);
      boolean checkTokens = TOKEN_SCAN_EXTENSIONS.contains(ext);
      boolean checkUrls = URL_SCAN_EXTENSIONS.contains(ext);
      if (!checkTokens && !checkUrls) {
        continue;
      }
      String relative = GitHygieneVerifier.relativePath(root, file);
      List<String> lines = Files.readAllLines(file, StandardCharsets.UTF_8);
      for (int index = 0; index < lines.size(); index++) {
        String line = lines.get(index);
        int lineNumber = index + 1;
        if (checkUrls && line.contains("byteland-app")) {
          violations.add(relative + ":" + lineNumber + ": retired byteland-app reference");
        }
        if (checkTokens) {
          Matcher matcher = retiredToolPattern.matcher(line);
          while (matcher.find()) {
            violations.add(
                relative
                    + ":"
                    + lineNumber
                    + ": retired dotted MCP tool name: "
                    + matcher.group());
          }
        }
      }
    }
  }

  private static void collectWorkspaceFiles(Path directory, List<Path> files) throws IOException {
    try (Stream<Path> entries = Files.list(directory)) {
      for (Path entry : entries.sorted().toList()) {
        String name = entry.getFileName().toString();
        if (Files.isDirectory(entry, LinkOption.NOFOLLOW_LINKS)) {
          if (!IGNORED_DIRECTORIES.contains(name)) {
            collectWorkspaceFiles(entry, files);
          }
        } else if (Files.isRegularFile(entry, LinkOption.NOFOLLOW_LINKS)) {
          files.add(entry);
        }
      }
    }
  }

  private static void collectFilesByExtension(
      Path directory, Set<String> extensions, List<Path> files) throws IOException {
    try (Stream<Path> entries = Files.list(directory)) {
      for (Path entry : entries.sorted().toList()) {
        if (Files.isDirectory(entry, LinkOption.NOFOLLOW_LINKS)) {
          collectFilesByExtension(entry, extensions, files);
        } else if (Files.isRegularFile(entry, LinkOption.NOFOLLOW_LINKS)
            && extensions.contains(extensionOf(entry))) {
          files.add(entry);
        }
      }
    }
  }

  private static String extensionOf(Path path) {
    String name = path.getFileName().toString();
    int dot = name.lastIndexOf('.');
    return dot <= 0 ? "" : name.substring(dot + 1);
  }
}
