# Security policy

## Supported code

Security fixes apply to the current `next` branch.

## Run the server

The bridge can read and change the active Ghidra program. Bind a local server to a loopback address when possible.

A server on another interface needs a token. Send the token in the `Authorization: Bearer <token>` header. Do not put the token in a URL.

A token does not encrypt traffic. Use an authenticated TLS proxy for remote access. Give access only to trusted clients.

## Report a problem

Send a private report to the repository maintainers. Include the affected version, steps to reproduce the problem, and its effect. Do not include a real token or sensitive program data.
