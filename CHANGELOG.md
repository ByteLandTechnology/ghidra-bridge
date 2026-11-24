# Changelog

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
