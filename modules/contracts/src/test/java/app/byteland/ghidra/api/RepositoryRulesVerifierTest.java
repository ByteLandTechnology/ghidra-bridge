package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Tests typed repository hygiene, architecture, contract, YAML, and STE verifiers.
 */
class RepositoryRulesVerifierTest {
  @Test
  void repositoryHeadPassesAllVerifiersWithoutGhidraInstallDir() throws Exception {
    Path root = locateRepositoryRoot();
    assertDoesNotThrow(() -> RepositoryRulesVerifier.verify(root));
    assertDoesNotThrow(() -> RepositoryRulesVerifier.verifyArchitecture(root));
    List<Path> steFiles = SimplifiedEnglishVerifier.collectFiles(root);
    assertTrue(steFiles.size() >= 235, "Expected at least 235 STE-checked files");
  }

  @Test
  void gitHygieneFailsImmediatelyOnNonZeroGitStatus(@TempDir Path tempDir) {
    List<String> violations = new ArrayList<>();
    IllegalStateException error =
        assertThrows(
            IllegalStateException.class, () -> GitHygieneVerifier.verify(tempDir, violations));
    assertTrue(error.getMessage().contains("Git command exited with status"));
  }

  @Test
  void gitHygieneRejectsNonAsciiZeroByteAndDuplicateFiles(@TempDir Path tempDir) throws Exception {
    initMinimalGitRepo(tempDir);
    runGit(tempDir, "config", "core.quotePath", "true");

    Path emptyChineseDoc = tempDir.resolve("docs/zh/空文件.md");
    Path duplicateJapaneseOne = tempDir.resolve("docs/ja/重複ファイルA.md");
    Path duplicateJapaneseTwo = tempDir.resolve("docs/ja/重複ファイルB.md");
    Files.createDirectories(emptyChineseDoc.getParent());
    Files.createDirectories(duplicateJapaneseOne.getParent());
    Files.writeString(emptyChineseDoc, "", StandardCharsets.UTF_8);
    Files.writeString(duplicateJapaneseOne, "同じ内容です。\n", StandardCharsets.UTF_8);
    Files.writeString(duplicateJapaneseTwo, "同じ内容です。\n", StandardCharsets.UTF_8);
    runGit(tempDir, "add", ".");

    List<String> violations = new ArrayList<>();
    GitHygieneVerifier.verify(tempDir, violations);

    assertTrue(
        violations.stream()
            .anyMatch(
                item ->
                    item.contains("docs/zh/空文件.md")
                        && item.contains("zero-byte files are candidates for commit")));
    assertTrue(
        violations.stream()
            .anyMatch(
                item ->
                    item.contains("docs/ja/重複ファイルA.md")
                        && item.contains("docs/ja/重複ファイルB.md")
                        && item.contains("exact duplicate files are candidates for commit")));
  }

  @Test
  void gitHygieneRejectsTrackedIgnoredLegacyAndGeneratedFiles(@TempDir Path tempDir)
      throws Exception {
    initMinimalGitRepo(tempDir);
    Files.writeString(tempDir.resolve(".gitignore"), "ignored.log\n", StandardCharsets.UTF_8);
    Files.writeString(tempDir.resolve("ignored.log"), "secret log\n", StandardCharsets.UTF_8);
    writeText(tempDir.resolve("build/out.txt"), "generated\n");
    writeText(tempDir.resolve("settings.gradle.kts"), "rootProject.name = \"demo\"\n");
    writeText(tempDir.resolve("src/Main.java"), "class Main {}\n");
    writeText(tempDir.resolve("Bridge.java"), "class Bridge {}\n");
    writeText(
        tempDir.resolve("README.md"),
        "# Demo\n\nSee `:tooling:contract-docs` and `distribution/src/main/templates`.\n");
    writeText(tempDir.resolve("docs/api.md"), "| `program.get` | `read` | Read program. |\n");
    Files.delete(tempDir.resolve("modules/launcher/src/main/templates/GhidraLauncher.java.template"));
    runGit(tempDir, "add", "-f", ".");
    runGit(tempDir, "add", "-u");

    List<String> violations = new ArrayList<>();
    GitHygieneVerifier.verify(tempDir, violations);

    assertTrue(violations.stream().anyMatch(item -> item.contains("ignored.log: ignored files")));
    assertTrue(violations.stream().anyMatch(item -> item.contains("build/out.txt: generated")));
    assertTrue(
        violations.stream().anyMatch(item -> item.contains("settings.gradle.kts: obsolete")));
    assertTrue(violations.stream().anyMatch(item -> item.contains("src/Main.java: the root")));
    assertTrue(violations.stream().anyMatch(item -> item.contains("Bridge.java: generated")));
    assertTrue(
        violations.stream().anyMatch(item -> item.contains("expected one launcher template")));
    assertTrue(
        violations.stream().anyMatch(item -> item.contains("README.md:3: stale protocol")));
    assertTrue(violations.stream().anyMatch(item -> item.contains("docs/api.md: documents 1")));
  }

  @Test
  void architectureVerifierRejectsAllFourImportBypasses(@TempDir Path tempDir) throws Exception {
    writeText(
        tempDir.resolve("modules/domain/src/main/java/demo/StaticBypass.java"),
        "package demo;\nimport static ghidra.program.model.listing.Program.*;\nclass StaticBypass {}\n");
    writeText(
        tempDir.resolve("modules/wire/src/main/java/demo/IndentedBypass.java"),
        "package demo;\n    import ghidra.program.model.listing.Program;\nclass IndentedBypass {}\n");
    writeText(
        tempDir.resolve("modules/runtime/src/main/java/demo/MultiSpaceBypass.java"),
        "package demo;\nimport   ghidra.program.model.listing.Program;\nclass MultiSpaceBypass {}\n");
    writeText(
        tempDir.resolve("modules/transport/mcp/src/main/java/demo/CommentBypass.java"),
        "package demo;\nimport /* comment */ ghidra./* nested */program.model.listing.Program;\n"
            + "import // line comment\nghidra.util.Msg;\nclass CommentBypass {}\n");

    List<String> violations = new ArrayList<>();
    ArchitectureVerifier.verify(tempDir, violations);
    assertEquals(5, violations.size(), () -> "Unexpected violations: " + violations);
    assertTrue(violations.stream().anyMatch(item -> item.contains("StaticBypass.java:2:")));
    assertTrue(violations.stream().anyMatch(item -> item.contains("IndentedBypass.java:2:")));
    assertTrue(violations.stream().anyMatch(item -> item.contains("MultiSpaceBypass.java:2:")));
    assertTrue(violations.stream().anyMatch(item -> item.contains("CommentBypass.java:2:")));
    assertTrue(violations.stream().anyMatch(item -> item.contains("CommentBypass.java:3:")));
  }

  @Test
  void architectureVerifierPermitsAdapterLauncherCommentsLiteralsAndAppImports(
      @TempDir Path tempDir) throws Exception {
    writeText(
        tempDir.resolve("modules/adapter/src/main/java/demo/AdapterClass.java"),
        "package demo;\nimport ghidra.program.model.listing.Program;\nclass AdapterClass {}\n");
    writeText(
        tempDir.resolve("modules/launcher/src/main/java/demo/LauncherClass.java"),
        "package demo;\nimport ghidra.program.model.listing.Program;\nclass LauncherClass {}\n");
    writeText(
        tempDir.resolve("modules/domain/src/main/java/demo/CleanDomain.java"),
        "package demo;\n"
            + "import app.byteland.ghidra.JsonUtil;\n"
            + "// import ghidra.program.model.listing.Program;\n"
            + "/* import static ghidra.program.model.listing.Program.*; */\n"
            + "class CleanDomain {\n"
            + "  String inline = \"import ghidra.program.model.listing.Program;\";\n"
            + "  String block = \"\"\"\n"
            + "      import ghidra.program.model.listing.Program;\n"
            + "      \"\"\";\n"
            + "}\n");

    List<String> violations = new ArrayList<>();
    ArchitectureVerifier.verify(tempDir, violations);
    assertEquals(List.of(), violations);
  }

  @Test
  void contractAndWorkflowVerifierRejectsRetiredUrlsToolNamesInvalidYamlAndMasks(
      @TempDir Path tempDir) throws Exception {
    Path repoRoot = locateRepositoryRoot();
    writeText(
        tempDir.resolve("docs/mcp-tools.json"),
        Files.readString(repoRoot.resolve("docs/mcp-tools.json"), StandardCharsets.UTF_8));
    writeText(
        tempDir.resolve(".github/ISSUE_TEMPLATE/config.yml"),
        """
        blank_issues_enabled: false
        contact_links:
          - name: Report a security issue
            url: https://github.com/byteland-app/ghidra-bridge/security/advisories/new
            about: Report security problems privately.
        """);
    writeText(
        tempDir.resolve(".github/ISSUE_TEMPLATE/bug_report.yml"),
        "name: Bug\ndescription: Send request to `ghidra.function`.\n");
    writeText(
        tempDir.resolve(".github/actions/setup-ghidra/action.yml"),
        """
        name: Demo
        inputs:
          ghidra-version:
            required: true
        runs:
          using: composite
          steps:
            - name: Bad step
              shell: bash
              continue-on-error: true
              env:
                BAD: ${{ inputs.undeclared-input }}
              run: |
                echo "GHIDRA_INSTALL_DIR=$(cd "$install_dir" && pwd)" >> "$GITHUB_ENV"
        """);
    writeText(tempDir.resolve(".github/workflows/broken.yml"), "jobs: [\n");
    writeText(
        tempDir.resolve(".github/scripts/hygiene.sh"),
        "#!/usr/bin/env bash\ngrep -E 'foo' file.txt || true\n");
    writeText(
        tempDir.resolve("docs/zh/protocol.md"), "调用 `ghidra.memory` 与 `ghidra.help`。\n");

    List<String> violations = new ArrayList<>();
    ContractAndWorkflowVerifier.verify(tempDir, violations);

    assertTrue(violations.stream().anyMatch(item -> item.contains("byteland-app")));
    assertTrue(
        violations.stream()
            .anyMatch(item -> item.contains("bug_report.yml:2: retired dotted MCP tool name")));
    assertTrue(
        violations.stream()
            .anyMatch(item -> item.contains("docs/zh/protocol.md:1: retired dotted MCP tool name")));
    assertTrue(violations.stream().anyMatch(item -> item.contains("continue-on-error")));
    assertTrue(
        violations.stream()
            .anyMatch(item -> item.contains("undeclared composite action input: inputs.undeclared-input")));
    assertTrue(
        violations.stream()
            .anyMatch(item -> item.contains("command substitution inside echo/printf")));
    assertTrue(violations.stream().anyMatch(item -> item.contains("broken.yml:1: invalid YAML")));
    assertTrue(violations.stream().anyMatch(item -> item.contains("forbidden '|| true'")));
  }

  @Test
  void simplifiedEnglishPassesOnPageJavaAndFailsOnInjectedViolations() throws Exception {
    Path repoRoot = locateRepositoryRoot();
    Path pageJava =
        repoRoot.resolve("modules/domain/src/main/java/app/byteland/ghidra/service/Page.java");
    String cleanSource = Files.readString(pageJava, StandardCharsets.UTF_8);

    List<String> cleanViolations = new ArrayList<>();
    SimplifiedEnglishVerifier.checkSlashComments("Page.java", cleanSource, cleanViolations);
    assertEquals(List.of(), cleanViolations);

    String injected =
        "// This helper could allow setting up items via e.g. a page that doesn't fit.\n"
            + cleanSource;
    List<String> violations = new ArrayList<>();
    SimplifiedEnglishVerifier.checkSlashComments("Page.java", injected, violations);
    assertTrue(violations.stream().anyMatch(item -> item.contains("prohibited word: could")));
    assertTrue(violations.stream().anyMatch(item -> item.contains("prohibited word: allow")));
    assertTrue(violations.stream().anyMatch(item -> item.contains("prohibited word: via")));
    assertTrue(violations.stream().anyMatch(item -> item.contains("contraction: doesn't")));
    assertTrue(violations.stream().anyMatch(item -> item.contains("Latin abbreviation: e.g.")));
    assertTrue(
        violations.stream().anyMatch(item -> item.contains("nontechnical -ing form: setting")));
  }

  @Test
  void simplifiedEnglishEnforcesSentenceParagraphAndYamlContractRules() {
    List<String> markdownViolations = new ArrayList<>();
    String longInstruction =
        "Run one two three four five six seven eight nine ten eleven twelve thirteen fourteen "
            + "fifteen sixteen seventeen eighteen nineteen twenty.\n";
    SimplifiedEnglishVerifier.checkMarkdown("guide.md", longInstruction, markdownViolations);
    assertTrue(
        markdownViolations.stream()
            .anyMatch(item -> item.contains("sentence has 21 words; maximum is 20")));

    List<String> paragraphViolations = new ArrayList<>();
    String sevenSentences = "One. Two. Three. Four. Five. Six. Seven.\n";
    SimplifiedEnglishVerifier.checkMarkdown("guide.md", sevenSentences, paragraphViolations);
    assertTrue(
        paragraphViolations.stream()
            .anyMatch(item -> item.contains("paragraph has 7 sentences; maximum is 6")));

    List<String> contractViolations = new ArrayList<>();
    SimplifiedEnglishVerifier.checkYamlContract(
        "docs/asyncapi.yaml", "\"description\": \"This could\\n  fail.\"\n", contractViolations);
    assertTrue(
        contractViolations.stream().anyMatch(item -> item.contains("prohibited word: could")));

    List<String> invalidYamlViolations = new ArrayList<>();
    SimplifiedEnglishVerifier.checkYamlContract("docs/asyncapi.yaml", "[", invalidYamlViolations);
    assertTrue(invalidYamlViolations.stream().anyMatch(item -> item.contains("invalid YAML")));
  }

  private static Path locateRepositoryRoot() {
    Path current = Path.of("").toAbsolutePath().normalize();
    while (current != null) {
      if (Files.exists(current.resolve(".git"))
          && Files.isRegularFile(current.resolve("settings.gradle"))) {
        return current;
      }
      current = current.getParent();
    }
    throw new IllegalStateException("Cannot locate repository root from working directory");
  }

  private static void initMinimalGitRepo(Path root) throws Exception {
    runGit(root, "init", "-q");
    runGit(root, "config", "user.email", "test@example.com");
    runGit(root, "config", "user.name", "Test");
    writeText(
        root.resolve("modules/launcher/src/main/templates/GhidraLauncher.java.template"),
        "// Launcher template.\nclass Template {}\n");
    ApiContractGenerator.main(new String[] {root.toString()});
    runGit(root, "add", ".");
  }

  private static void writeText(Path path, String content) throws IOException {
    Path parent = path.getParent();
    if (parent != null) {
      Files.createDirectories(parent);
    }
    Files.writeString(path, content, StandardCharsets.UTF_8);
  }

  private static void runGit(Path root, String... args) throws Exception {
    List<String> command = new ArrayList<>(args.length + 1);
    command.add("git");
    command.addAll(List.of(args));
    Process process = new ProcessBuilder(command).directory(root.toFile()).start();
    String stderr = new String(process.getErrorStream().readAllBytes(), StandardCharsets.UTF_8);
    process.getInputStream().readAllBytes();
    int exit = process.waitFor();
    if (exit != 0) {
      throw new IllegalStateException("git failed (" + exit + "): " + stderr);
    }
  }
}
