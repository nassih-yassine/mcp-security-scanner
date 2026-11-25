# Security policy

## Reporting a vulnerability

Email the maintainer at yassine-nassih@outlook.com with a description and a
reproduction. Do not open a public issue for a vulnerability.

You get an acknowledgement within 72 hours and a fix or a written plan within 90
days. Credit is given in the release notes unless you ask otherwise.

## Scope

In scope: `mcpscan` itself — memory safety, panic on crafted input, secret
leakage in its own output, network egress outside `--online`, and path traversal
while reading configs.

Out of scope: findings `mcpscan` reports about third-party MCP servers. Those are
reports about other software; send them to the server's maintainers. This file is
for vulnerabilities in the scanner.
