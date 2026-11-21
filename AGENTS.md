# AGENTS.md: rules for this repository

These rules apply to all persons and agents that change this repository.
The `./gradlew --no-daemon clean verify` and `verify-repository-hygiene.sh`
commands check that most of these rules are obeyed.

## Writing

- Use ASD-STE100 Simplified Technical English for all English text.
- This rule applies to this file, Markdown documents, code comments,
  Javadoc comments, and commit messages.

## Architecture and module boundaries

- Keep domain models and service interfaces in `modules/domain`
  independent of Ghidra classes and wire codecs.
- Keep JSON-RPC, schema definitions, and method dispatch in
  `modules/wire`.
- Keep contract generators and drift checks in `modules/contracts`. Do
  not edit `docs/api.md`, `docs/asyncapi.yaml`, or `docs/mcp-tools.json`
  by hand; run `./gradlew generateApiContracts` instead.
- Keep Ghidra API imports confined to `modules/adapter` and
  `modules/launcher`. The `verifyArchitecture` task enforces this rule.
- Keep runtime session orchestration in `modules/runtime`, WebSocket
  transport code in `modules/transport/websocket`, and Model Context
  Protocol HTTP transport code in `modules/transport/mcp`.
- Keep zero third-party runtime dependencies in `ghidra-bridge.jar`.
  Only `app/byteland/ghidra/**` classes and `META-INF/MANIFEST.MF` are
  permitted in the distribution archive (`verifyDistribution`).

## Code rules

- Compile all Java main, test, and generated launcher sources with JDK
  21 (`--release 21`), UTF-8 encoding, `-Xlint:all`, `-Werror`, and
  ErrorProne (`net.ltgt.errorprone`).
- Do not disable compiler lint categories, ErrorProne checks, Javadoc
  doclint groups, SpotBugs detectors, or PMD rulesets in `build.gradle`.
- Change the code to remove compiler, ErrorProne, Javadoc, SpotBugs, and
  PMD warnings. Do not add `@SuppressWarnings` or `@SuppressFBWarnings`
  to hide a defect that a code change can fix.
- Add a narrow `@SuppressWarnings` or `@SuppressFBWarnings` annotation
  only when a Java, Ghidra, or test contract makes the warning
  impossible to remove in code. Always include a `justification` string
  on `@SuppressFBWarnings`.
- Write complete Javadoc comments on every public and protected class,
  interface, record, enum, enum constant, field, constructor, and
  method, including `@param`, `@return`, `@throws`, and `@serial` tags.
  The `javadoc` task runs with `-Xdoclint:all` and `-Werror`.
- Keep `org.gradle.dependency.verification=strict` enabled in
  `gradle.properties`. When build plugins, static analyzers, or test
  dependencies change, refresh `gradle/verification-metadata.xml` with
  SHA-256 checksums.
- Do not modify existing test assertions to hide regressions caused by a
  code change.

## Commit messages

- Obey Conventional Commits.
- Use no more than 72 characters on each line, including spaces and list
  markers.
- Use lowercase letters for the type and the scope.
- Use these scopes when a commit changes one area:
  - `domain`, `wire`, `contracts`, `runtime`, `adapter`, `launcher`,
    `websocket`, or `mcp` for module code in `modules/`.
  - `docs` for Markdown documents and guides.
  - `build` for Gradle build files and dependency verification metadata.
  - `ci` for workflows and scripts in `.github/`.
  - If a commit changes more than one scope, do not write a scope.
- Start the summary with an imperative verb in lowercase letters.
- Do not put a period at the end of the summary.
- If you write a body, obey these rules:
  - Put one blank line between the header and the body.
  - Write the body as a list with `- ` before each item.
  - Start each item with a capital letter.
  - Put each item on one line. Do not put blank lines in the body.
  - Do not use nested lists.
- Do not add attribution lines such as `Co-Authored-By` to commit
  messages or pull request text.
- Each commit must compile and pass verification checks.

## Before you commit

Run these commands from the repository root:

- `./gradlew --no-daemon clean verify`: Compiles main, test, and
  generated launcher sources with `-Xlint:all -Werror` and ErrorProne,
  validates Javadoc with `-Xdoclint:all -Werror`, runs SpotBugs
  (`spotbugsMain`, `spotbugsTest`) and PMD (`pmdMain`, `pmdTest`), and
  verifies architecture, API contracts, and the distribution JAR.
- `./gradlew --no-daemon test`: Runs the JUnit test suites across all
  modules.
- `bash .github/scripts/verify-repository-hygiene.sh`: Checks tracked
  files, generated script exclusions, duplicates, and API method counts.
- `GRADLE_USER_HOME="$(mktemp -d)" ./gradlew --no-daemon --write-verification-metadata sha256 clean verify test`:
  Refreshes `gradle/verification-metadata.xml` from a clean Gradle cache
  when Gradle plugins or tool dependencies change.
