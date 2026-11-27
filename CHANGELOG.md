# Changelog

## [1.7.0](https://github.com/ByteLandTechnology/ghidra-bridge/compare/v1.6.0...v1.7.0) (2026-11-27)


### Features

* **wire,mcp:** add declarative schema validation, defaults, and pointer rebasing ([#104](https://github.com/ByteLandTechnology/ghidra-bridge/issues/104)) ([d512780](https://github.com/ByteLandTechnology/ghidra-bridge/commit/d51278008b68bab6d511c27342aadc339242d158))


### Bug Fixes

* consolidate transport validation and bootstrap lifecycle ([#70](https://github.com/ByteLandTechnology/ghidra-bridge/issues/70)) ([5f835fd](https://github.com/ByteLandTechnology/ghidra-bridge/commit/5f835fd64f15e1de20e67b638936dd7c35f92c9a))


### Performance Improvements

* **adapter:** cache sorted query snapshots across cursor pages ([#80](https://github.com/ByteLandTechnology/ghidra-bridge/issues/80)) ([513313b](https://github.com/ByteLandTechnology/ghidra-bridge/commit/513313b242673f29dc2f1c20d6043e62bad8a54c))

## [1.6.0](https://github.com/ByteLandTechnology/ghidra-bridge/compare/v1.5.1...v1.6.0) (2026-11-26)


### Features

* publish compact MCP schemas and enriched domain help ([#45](https://github.com/ByteLandTechnology/ghidra-bridge/issues/45)) ([f22b50a](https://github.com/ByteLandTechnology/ghidra-bridge/commit/f22b50aec25be525c74e8a13aa52f6248ff4771a))


### Performance Improvements

* **wire:** project and validate response fields in one pass ([#102](https://github.com/ByteLandTechnology/ghidra-bridge/issues/102)) ([01ce7d5](https://github.com/ByteLandTechnology/ghidra-bridge/commit/01ce7d5f93e08c485f05b7d2dd09dfb0f9c1aeba))

## [1.5.1](https://github.com/ByteLandTechnology/ghidra-bridge/compare/v1.5.0...v1.5.1) (2026-11-26)


### Bug Fixes

* **mcp:** bound HTTP threads, concurrent requests, and SSE sessions ([#48](https://github.com/ByteLandTechnology/ghidra-bridge/issues/48)) ([96c20a1](https://github.com/ByteLandTechnology/ghidra-bridge/commit/96c20a1239d019a8bae40b0ea738776a9c2ca99e))
* **websocket:** reassemble fragmented text frames and add keepalive timeouts ([#94](https://github.com/ByteLandTechnology/ghidra-bridge/issues/94)) ([e1732ab](https://github.com/ByteLandTechnology/ghidra-bridge/commit/e1732aba0ad2d4e0972d7d92105ab27a1e2bc28a))
* **wire:** align wire schemas, list pagination, and flow filters ([#24](https://github.com/ByteLandTechnology/ghidra-bridge/issues/24)) ([ccc7cac](https://github.com/ByteLandTechnology/ghidra-bridge/commit/ccc7cacc3de9fcaa6dfe440646cca02585973e7c))


### Performance Improvements

* **runtime:** use fair read-write locks in AgentDispatcher ([#50](https://github.com/ByteLandTechnology/ghidra-bridge/issues/50)) ([5270daf](https://github.com/ByteLandTechnology/ghidra-bridge/commit/5270dafb05e6f81340b76402278f6d0fc2c75d4e))

## [1.5.0](https://github.com/ByteLandTechnology/ghidra-bridge/compare/v1.4.1...v1.5.0) (2026-11-25)


### Features

* **launcher:** select fallback GUI ports automatically and guard program saves ([#98](https://github.com/ByteLandTechnology/ghidra-bridge/issues/98)) ([e18197c](https://github.com/ByteLandTechnology/ghidra-bridge/commit/e18197c23f874b8484c6379d4134cccc9e1fb85f))
* **mcp:** add opt-in allowed_origins override on top of default loopback policy ([#16](https://github.com/ByteLandTechnology/ghidra-bridge/issues/16)) ([9bd4e19](https://github.com/ByteLandTechnology/ghidra-bridge/commit/9bd4e190d953bfdcba54772e72db467f991af531))


### Bug Fixes

* **build:** eliminate Java 21 compiler warnings and enforce Gradle Xlint ([#123](https://github.com/ByteLandTechnology/ghidra-bridge/issues/123)) ([8f5d046](https://github.com/ByteLandTechnology/ghidra-bridge/commit/8f5d0463ba4f20298198e093dbbe8ea227e7eee5))
* validate literal HTTP Host headers across loopback transports ([#38](https://github.com/ByteLandTechnology/ghidra-bridge/issues/38)) ([6d180b8](https://github.com/ByteLandTechnology/ghidra-bridge/commit/6d180b82f045163947552bd53a27c8b99f19b433))
* **websocket:** cap outbound WebSocket messages at 16 MiB ([#40](https://github.com/ByteLandTechnology/ghidra-bridge/issues/40)) ([789d2d8](https://github.com/ByteLandTechnology/ghidra-bridge/commit/789d2d82ea919836bda916e6d8d0c5c3653198c0))
* **websocket:** isolate envelope validation and send errors ([#88](https://github.com/ByteLandTechnology/ghidra-bridge/issues/88)) ([0da3687](https://github.com/ByteLandTechnology/ghidra-bridge/commit/0da36873164e924b0d83abacee78c5ebde52c140))
* **websocket:** validate Origin headers during upgrade handshakes ([#13](https://github.com/ByteLandTechnology/ghidra-bridge/issues/13)) ([c550874](https://github.com/ByteLandTechnology/ghidra-bridge/commit/c5508743a090b6e8da295da603dbbf6a91928f53))


### Performance Improvements

* **adapter:** cache per-render lookups in GuiDocument.render ([#25](https://github.com/ByteLandTechnology/ghidra-bridge/issues/25)) ([727f9a6](https://github.com/ByteLandTechnology/ghidra-bridge/commit/727f9a62089e8102ee3e901322e5a72edd2a86b8))
* **adapter:** flush decompiler cache only after program modifications ([#34](https://github.com/ByteLandTechnology/ghidra-bridge/issues/34)) ([9289a96](https://github.com/ByteLandTechnology/ghidra-bridge/commit/9289a96fee09134c2a0140a3299cd54c03cee16a))
* **adapter:** share scan-resistant demangler cache with SymbolDemangling ([#108](https://github.com/ByteLandTechnology/ghidra-bridge/issues/108)) ([15cb2e6](https://github.com/ByteLandTechnology/ghidra-bridge/commit/15cb2e628da51e1d8a6ccbe9d186f50f66644ad8))
* **wire:** stream JSON string slices without per-string buffers ([#32](https://github.com/ByteLandTechnology/ghidra-bridge/issues/32)) ([5b108b7](https://github.com/ByteLandTechnology/ghidra-bridge/commit/5b108b78e4ce0947f01bceef13582535e3953986))

## [1.4.1](https://github.com/ByteLandTechnology/ghidra-bridge/compare/v1.4.0...v1.4.1) (2026-11-24)


### Bug Fixes

* decouple AgentDispatcher from AgentConfig during MCP startup ([#62](https://github.com/ByteLandTechnology/ghidra-bridge/issues/62)) ([2da2054](https://github.com/ByteLandTechnology/ghidra-bridge/commit/2da2054f610f53419cce17cbf1b2656696ef6568))
* **launcher:** stream runtime jar snapshot into 0600 temp file ([#20](https://github.com/ByteLandTechnology/ghidra-bridge/issues/20)) ([0b2e867](https://github.com/ByteLandTechnology/ghidra-bridge/commit/0b2e8674c77cf2ae93cb14b4104ba4ad35ff20ba))
* **mcp:** allow only loopback and configured host origins ([#29](https://github.com/ByteLandTechnology/ghidra-bridge/issues/29)) ([9d99083](https://github.com/ByteLandTechnology/ghidra-bridge/commit/9d99083067767390ac217d7fe4222d474278c457))
* **mcp:** enforce maximum request body size in McpHttpServer ([#26](https://github.com/ByteLandTechnology/ghidra-bridge/issues/26)) ([6ae0b9f](https://github.com/ByteLandTechnology/ghidra-bridge/commit/6ae0b9fd81f18e17bad03da8e1d97332a2c3fd9a))
* render text with PrettyPrinter and align decompilation timeouts ([#36](https://github.com/ByteLandTechnology/ghidra-bridge/issues/36)) ([7982a18](https://github.com/ByteLandTechnology/ghidra-bridge/commit/7982a18cc5702fb2a8d9e190d99d39250996d145))
* **transport:** reserve websocket session slot after handshake authentication ([#12](https://github.com/ByteLandTechnology/ghidra-bridge/issues/12)) ([59e5d1f](https://github.com/ByteLandTechnology/ghidra-bridge/commit/59e5d1f7d128163baaf414db8bc33c66a8ecda16))
* validate and redact outbound WebSocket URLs ([#15](https://github.com/ByteLandTechnology/ghidra-bridge/issues/15)) ([df785dd](https://github.com/ByteLandTechnology/ghidra-bridge/commit/df785dd73cc7a8706a041871cd74f02c571557c5))


### Performance Improvements

* **adapter:** use kind-specialized stateful iterators for bounded scans ([#49](https://github.com/ByteLandTechnology/ghidra-bridge/issues/49)) ([396e163](https://github.com/ByteLandTechnology/ghidra-bridge/commit/396e163c4d39e1f46eefea3e23a6fd4ab504637d))
* **mcp:** reuse serialized tool JSON in McpHttpServer ([#27](https://github.com/ByteLandTechnology/ghidra-bridge/issues/27)) ([db65f06](https://github.com/ByteLandTechnology/ghidra-bridge/commit/db65f0628774b47aa49d0d4eb2999e394b2b5162))
* **mcp:** use virtual threads and signaled waits for SSE ([#10](https://github.com/ByteLandTechnology/ghidra-bridge/issues/10)) ([a0bef3e](https://github.com/ByteLandTechnology/ghidra-bridge/commit/a0bef3eed55d0c0293b7b631a0ccbe61cf12c4d8))
* select page keys before resource materialization ([#73](https://github.com/ByteLandTechnology/ghidra-bridge/issues/73)) ([939b0b0](https://github.com/ByteLandTechnology/ghidra-bridge/commit/939b0b0146c753a13ced371d1a62f1952413536a))
* **wire:** replace WireSchema exception backtracking with boolean probing ([#22](https://github.com/ByteLandTechnology/ghidra-bridge/issues/22)) ([aa77e60](https://github.com/ByteLandTechnology/ghidra-bridge/commit/aa77e60092cde4cbe616cf4b5c563dc33db296ad))

## [1.4.0](https://github.com/ByteLandTechnology/ghidra-bridge/compare/v1.3.0...v1.4.0) (2026-11-02)


### Features

* add C++ names to symbol and function data ([2d58efa](https://github.com/ByteLandTechnology/ghidra-bridge/commit/2d58efa3bd4147c7d12c09b7d266b276a5ff0a94))
* add document decompilation with comments ([7898f49](https://github.com/ByteLandTechnology/ghidra-bridge/commit/7898f4925552ca7589b78179e15b41a5cbebaa61))


### Bug Fixes

* mark the program as analyzed after analysis completes ([73b8847](https://github.com/ByteLandTechnology/ghidra-bridge/commit/73b884792d29e4bd86c9dd38f92b32174758da58))

## [1.3.0](https://github.com/ByteLandTechnology/ghidra-bridge/compare/v1.2.0...v1.3.0) (2026-10-30)


### Features

* add function creation and deletion ([1c1b9ad](https://github.com/ByteLandTechnology/ghidra-bridge/commit/1c1b9ad32f49cca29cde76d08acdaa105f804fa0))


### Bug Fixes

* generate the asyncapi contract with snakeyaml ([cc26950](https://github.com/ByteLandTechnology/ghidra-bridge/commit/cc26950032e86d526953adf921e416b958982241))
