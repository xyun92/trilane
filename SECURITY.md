# Security Policy

TriLane is a dual-use security tool. Use it only on systems you own, operate, or are explicitly authorized to test.

## Reporting Vulnerabilities In TriLane

Please report vulnerabilities privately to the project maintainers. Include:

- affected version or commit
- operating system
- reproduction steps
- impact
- whether Lab Mode was enabled

Do not include third-party secrets, live exploit tokens, or private target data in public issues.

## Responsible Use

- Do not run TriLane against third-party systems without written permission.
- Respect bounty scope, rate limits, data-handling rules, and disclosure timelines.
- Do not use Lab Mode on shared, production, or sensitive machines unless you understand the access it grants.
- Do not publish generated exploit details for third-party systems before responsible disclosure is complete.

## Lab Mode Warning

Lab Mode grants the agent full local filesystem and command execution access for the active target. It may start services, invoke containers, read source files, write PoCs, and execute local commands.

Use Safe Mode when you are exploring, evaluating the tool, or working with untrusted projects. Use Lab Mode only for authorized local labs or controlled assessment environments.
