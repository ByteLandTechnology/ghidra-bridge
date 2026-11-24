package app.byteland.ghidra.api;

import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Runs typed repository hygiene, architecture, contract, and prose checks.
 */
public final class RepositoryRulesVerifier {
  private static final Set<String> IGNORED_DIRECTORIES =
      Set.of("bin", "build", "ghidra-dist", "node_modules", "out", "target");

  private RepositoryRulesVerifier() {}

  static boolean isIgnoredDirectory(String name) {
    return (name.startsWith(".") && !".github".equals(name))
        || IGNORED_DIRECTORIES.contains(name);
  }

  public static void main(String[] args) throws IOException {
    boolean architectureOnly = false;
    String rootArg = ".";
    for (String arg : args) {
      if ("--architecture-only".equals(arg)) {
        architectureOnly = true;
      } else {
        rootArg = arg;
      }
    }
    Path root = Path.of(rootArg).toAbsolutePath().normalize();
    if (architectureOnly) {
      verifyArchitecture(root);
      System.out.println("Architecture verification: OK");
    } else {
      verify(root);
      System.out.println("Repository rules verification: OK");
    }
  }

  public static void verify(Path root) throws IOException {
    List<String> violations = collectViolations(root);
    failOnViolations("Repository rules check failed", violations);
  }

  public static void verifyArchitecture(Path root) throws IOException {
    List<String> violations = new ArrayList<>();
    ArchitectureVerifier.verify(root, violations);
    failOnViolations("Architecture check failed", violations);
  }

  static List<String> collectViolations(Path root) throws IOException {
    Path normalized = root.toAbsolutePath().normalize();
    List<String> violations = new ArrayList<>();
    GitHygieneVerifier.verify(normalized, violations);
    ArchitectureVerifier.verify(normalized, violations);
    ContractAndWorkflowVerifier.verify(normalized, violations);
    SimplifiedEnglishVerifier.verify(normalized, violations);
    return List.copyOf(violations);
  }

  private static void failOnViolations(String headline, List<String> violations) {
    if (violations.isEmpty()) {
      return;
    }
    StringBuilder report = new StringBuilder();
    report.append(headline).append(" (").append(violations.size()).append(" violation(s)):\n");
    for (String violation : violations) {
      report.append("  ").append(violation).append('\n');
    }
    throw new IllegalStateException(report.toString().stripTrailing());
  }
}
