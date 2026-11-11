# Security Policy

## Project status

OniShield AI is under active early-stage development. It is not currently represented as a production-ready security product. Do not rely on this repository as the sole protection for any system.

## Reporting a vulnerability

Do not publish exploitable vulnerability details, credentials, customer data, or attack instructions in a public issue.

For this private project, contact the repository owner directly through a trusted private channel and include:
- affected component and version/commit;
- concise impact description;
- safe reproduction steps using an owned or authorized test environment;
- logs or proof-of-concept evidence with secrets and personal data removed;
- suggested mitigation, if known.

Do not test against third-party systems or access, modify, or exfiltrate data without explicit written authorization.

## Response expectations

The maintainers will acknowledge reports when practical, assess severity and scope, reproduce safely, and coordinate remediation before any public disclosure. No response-time SLA is promised at this stage.

## Security development requirements

- Never commit secrets. Use local environment variables and ignored local configuration.
- Apply least privilege to service accounts, agents, and integrations.
- Validate and normalize untrusted telemetry.
- Treat model output and external threat-intelligence content as untrusted input.
- Require policy checks before tool execution.
- Require human approval for destructive or high-impact actions.
- Maintain auditable records of security decisions and actions.
- Test tenant isolation, authentication, authorization, and failure handling.

## Supported disclosure

Only report issues affecting this project or its explicitly authorized test environments. This policy does not grant authorization to test any other system.
