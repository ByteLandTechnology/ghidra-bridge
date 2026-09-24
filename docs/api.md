# Ghidra Bridge method reference

`ApiRegistry` generates this catalog. Interface version: `0.2.0`.

| Method | Effect | Description |
|---|---|---|
| `interface.get` | `read-only` | Describe all API methods, their schemas, and their effects. |
| `session.get` | `read-only` | Get the bridge session id, status, and program name. |
| `session.shutdown` | `lifecycle` | Stop the current Ghidra Bridge session. |
| `program.get` | `read-only` | Get program data from the active program. |
| `program.save` | `mutation` | Save the active program to its project file. |
| `program_language.get` | `read-only` | Get program language data from the active program. |
| `address_space.list` | `read-only` | List address space data in the active program. |
| `address.resolve` | `read-only` | Resolve an address and report its memory block, containing function, and primary symbol. |
| `memory_block.get` | `read-only` | Get memory block data from the active program. |
| `memory_block.list` | `read-only` | List memory block data in the active program. |
| `memory.read` | `read-only` | Read up to 65536 bytes at an address as hex or base64. The default length is 256 and the default encoding is hex. |
| `memory.write` | `destructive mutation` | Write hex or base64 bytes at an address. |
| `code_unit.list` | `read-only` | List code unit in address order. Set a range or time limit if necessary. Use next_cursor to get the next page. |
| `data_unit.list` | `read-only` | List data unit in address order. Set a range or time limit if necessary. Use next_cursor to get the next page. |
| `global_variable.get` | `read-only` | Get the global variable at one address. |
| `global_variable.list` | `read-only` | List global variables in address order. Set a range or time limit if necessary. Use next_cursor to get the next page. |
| `global_variable.create` | `mutation` | Create typed data and a primary global variable label at an unused address. |
| `global_variable.patch` | `destructive mutation` | Change the name or data type of a global variable. |
| `global_variable.upsert` | `destructive mutation` | Create or replace a typed global variable. Keep unrelated code and data. |
| `global_variable.delete` | `destructive mutation` | Delete a global variable definition. Set delete_symbol to delete its primary label. |
| `instruction.get` | `read-only` | Get instruction data from the active program. |
| `instruction.list` | `read-only` | List instruction in address order. Set a range or time limit if necessary. Use next_cursor to get the next page. |
| `flow_override.list` | `read-only` | List stored flow overrides. Select an address, function, or range. Use next_cursor to get the next page. |
| `flow_override.patch` | `destructive mutation` | Set or clear flow overrides. Select an address, function, or range. |
| `function.get` | `read-only` | Get function data from the active program. |
| `function.list` | `read-only` | List function in address order. Set a range or time limit if necessary. Use next_cursor to get the next page. |
| `function.patch` | `destructive mutation` | Change function data in the active program. |
| `function_parameter.create` | `mutation` | Create function parameter data in the active program. |
| `function_parameter.patch` | `destructive mutation` | Change function parameter data in the active program. |
| `function_parameter.delete` | `destructive mutation` | Delete function parameter data from the active program. |
| `function_local_variable.patch` | `destructive mutation` | Change function local variable data in the active program. |
| `function_call.list` | `read-only` | List the callers or callees of a function. The default direction is callees. |
| `analysis.get` | `read-only` | Get analysis data from the active program. |
| `analysis.start` | `mutation` | Start automatic analysis of the active program. |
| `decompilation.get` | `read-only` | Decompile the function at an entry point. Set scan.timeout_ms between 100 and 300000. The default is 30000 milliseconds. Ghidra rounds the time up to whole seconds. |
| `symbol.get` | `read-only` | Get symbol data from the active program. |
| `symbol.list` | `read-only` | List symbol in address order. Set a range or time limit if necessary. Use next_cursor to get the next page. |
| `symbol.patch` | `destructive mutation` | Change symbol data in the active program. |
| `reference.list` | `read-only` | List references from or to an address. Set filter.direction. |
| `comment.get` | `read-only` | Get comment data from the active program. |
| `comment.list` | `read-only` | List comment in address order. Set a range or time limit if necessary. Use next_cursor to get the next page. |
| `comment.create` | `mutation` | Create comment data in the active program. |
| `comment.patch` | `destructive mutation` | Change comment data in the active program. |
| `comment.upsert` | `destructive mutation` | Create or replace comment data in the active program. |
| `comment.delete` | `destructive mutation` | Delete comment data from the active program. |
| `data_type_category.list` | `read-only` | List data type category data in the active program. |
| `data_type.get` | `read-only` | Get data type data from the active program. |
| `data_type.list` | `read-only` | List data type data in the active program. |
| `data_type.create` | `mutation` | Create data type data in the active program. |
| `data_type.patch` | `destructive mutation` | Change data type data in the active program. |
| `data_type.upsert` | `destructive mutation` | Create or replace data type data in the active program. |
| `data_type.delete` | `destructive mutation` | Delete data type data from the active program. |
| `batch.execute` | `destructive mutation` | Check and run a batch in order. Use per_item to keep item errors. Use all_or_none to roll back the batch after an error. |

Use the input schema for each method. The bridge rejects unknown fields and type conversions.
