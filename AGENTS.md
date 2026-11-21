# AGENTS.md: rules for this repository

These rules apply to all persons and agents that change this repository.
The `./gradlew --no-daemon clean verify` and `verify-repository-hygiene.sh` checks enforce them.

## Writing

- Use ASD-STE100 Simplified Technical English for all English text.
- Apply this rule to this file, documents, code comments, Javadoc comments, and commits.

## Architecture and boundaries

- Keep Ghidra API imports (`ghidra.*`) inside `modules/adapter` and `modules/launcher`.
- Keep zero third-party runtime dependencies in `ghidra-bridge.jar`.
- Keep `org.gradle.dependency.verification=strict` in `gradle.properties`.
- Remove unused dependency checksums from `gradle/verification-metadata.xml`.
- Do not add third-party static-analysis Gradle plugins.
- Run `./gradlew generateApiContracts` after you change a public operation or wire schema.
- Do not edit `docs/api.md`, `docs/asyncapi.yaml`, or `docs/mcp-tools.json` by hand.

## Layout

- `modules/domain`: domain records, exceptions, and service interfaces.
- `modules/wire`: JSON wire codecs, schemas, and `ApiRegistry` handlers.
- `modules/contracts`: AsyncAPI and Markdown API contract generators.
- `modules/runtime`: shared session, lease pool, and transport support.
- `modules/adapter`: Ghidra implementations of the domain services.
- `modules/transport/websocket`: WebSocket server and client transport.
- `modules/transport/mcp`: Model Context Protocol HTTP server and tool generator.
- `modules/launcher`: `Bootstrap` entry point and Ghidra script template.

## Modules and files

- Keep each source or documentation line at 100 characters or fewer.
- Keep each Java file at 800 lines of code or fewer.
- Do not commit generated launcher scripts (`Bridge.java`, `GhidraMcp.java`) or build output.

## Code rules

- Compile Java main, test, and script sources for release 21 with `-Xlint:all` and `-Werror`.
- Do not disable compiler lint categories or suppress Javadoc checks.
- Change the code to remove compiler and Javadoc warnings.
- Use `@SuppressWarnings` at the narrowest scope only when a JDK API forces a cast or close check.
- Do not add SpotBugs, PMD, ErrorProne, or JSR-305 dependencies, annotations, or comments.
- Run Javadoc with `-Xdoclint:all` and `-Werror` across all Java subprojects.
- Write complete Javadoc comments on all public and protected types, constructors, and methods.
- Include `@param`, `@return`, and `@throws` tags, and document serialized exception fields.

## Commit messages

- Obey Conventional Commits.
- Use no more than 72 characters on each line, with spaces and list markers counted.
- Use lowercase letters for the type and the scope.
- Use a module name, `docs`, `build`, or `ci` as the commit scope.
- Omit the scope if a commit changes more than one scope.
- Start the summary with an imperative verb in lowercase letters and omit a final period.
- Put one blank line before an optional flat `- ` bullet body, with one sentence per line.
- Do not add attribution lines such as `Co-Authored-By` to commit messages or pull request text.
- Make sure that each commit compiles and passes verification checks.

## Verification

Set `GHIDRA_INSTALL_DIR` to a Ghidra 12.1 installation and run these checks before you commit:

```bash
# Run full verification (compiler lints, Javadoc, contracts, architecture, and distribution)
./gradlew --no-daemon clean verify

# Compile main, test, and generated script classes with Java 21 lints
./gradlew --no-daemon classes testClasses compileGeneratedScripts

# Check Javadoc comments and tags across all Java subprojects
./gradlew --no-daemon javadoc

# Run unit tests across all Java subprojects
./gradlew --no-daemon test

# Check tracked file and documentation hygiene
bash .github/scripts/verify-repository-hygiene.sh
```
