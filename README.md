# Identity MCP Server

[![Crates.io](https://img.shields.io/crates/v/mcp-identity.svg)](https://crates.io/crates/mcp-identity)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![ADK-Rust Enterprise](https://img.shields.io/badge/ADK--Rust-Enterprise-purple.svg)](https://enterprise.adk-rust.com)
[![Registry Ready](https://img.shields.io/badge/ADK_Registry-Ready-green.svg)](https://www.zavora.ai)

Policy-enforced identity control plane for [ADK-Rust Enterprise](https://enterprise.adk-rust.com) agents. Look up users, verify identity, check MFA, review entitlements, request access changes, and manage lifecycle events — all audit-logged with actor context.

## What It Does

When your agent handles a support ticket, it needs to know: who is this user? Are they active? Is their MFA enabled? What do they have access to? Should we grant/revoke access? This MCP provides those answers with governance built in.

## Architecture

<p align="center">
  <img src="https://raw.githubusercontent.com/zavora-ai/mcp-identity/main/docs/architecture.svg" alt="Identity MCP Architecture" width="700"/>
</p>

## Key Principles

- **Actor context on every call** — who is asking, from which agent, for which ticket, for what purpose.
- **Audit-logged** — every identity lookup is recorded (PII access tracking).
- **Minimized PII** — returns only what's needed, never secrets or recovery codes.
- **Approval-gated writes** — access changes go through approval workflow.
- **Break-glass revoke** — emergency revocation with mandatory post-review.
- **Pluggable** — in-memory store now, Okta/Azure AD/Google Workspace via feature flags.

## Tools (8)

| Tool | What It Does | Risk |
|------|-------------|------|
| `lookup_user` | Find by email/username/name/employee ID | Sensitive read |
| `get_user_groups` | Groups with type (security, app, role, dynamic) | Sensitive read |
| `get_mfa_status` | MFA enrollment, methods, last verified | Security-sensitive read |
| `validate_identity` | Status, manager, MFA, risk level, active check | Sensitive read |
| `list_entitlements` | All access with source, grant type, risk, expiry | High-sensitivity read |
| `request_access_change` | Grant/revoke through approval workflow | Controlled write |
| `revoke_access` | Emergency revocation (break-glass) | Critical write |
| `create_user_lifecycle_task` | Onboarding/offboarding/transfer tasks | Lifecycle write |

## Verified Output

```
> lookup_user(query: "james", actor: {purpose: "support_ticket"})

{ "count": 1, "users": [{ "full_name": "James Karanja", "email": "james.karanja@company.com", "status": "active" }] }

> get_mfa_status(user_id: "usr_001")

{ "enabled": true, "methods": ["totp", "webauthn"], "last_verified": "2026-05-24T..." }

> list_entitlements(user_id: "usr_001")

{ "count": 3, "entitlements": [
  { "resource": "github:zavora-ai", "role": "write", "grant_type": "group", "risk": "medium" },
  { "resource": "aws:staging", "role": "developer", "grant_type": "role", "risk": "low" },
  { "resource": "vpn", "role": "user", "grant_type": "group", "risk": "low" }
]}

> request_access_change(user_id: "usr_001", action: "grant", resource: "aws:production", role: "admin", reason: "Release deployment")

{ "request_id": "AR-18B75D44", "status": "pending", "policy_decision": "awaiting_approval" }

> revoke_access(user_id: "usr_001", resource: "vpn", role: "user", reason: "Account compromised", ticket_id: "SEC-001")

{ "revoked": true, "requires_post_review": true, "effective_at": "2026-05-24T..." }

> create_user_lifecycle_task(user_id: "usr_002", task_type: "offboarding", owner_team: "IT Operations")

{ "task_id": "LT-487D94ED", "steps": ["Revoke all access", "Disable accounts", "Collect hardware", ...], "systems_impacted": ["All systems"] }
```

## Installation

### Build

```bash
git clone https://github.com/zavora-ai/mcp-identity
cd mcp-identity
cargo build --release
```

### Run with demo data

```bash
SEED_DATA=1 ./target/release/mcp-identity
```

### MCP client config

```json
{
  "mcpServers": {
    "identity": {
      "command": "/path/to/mcp-identity",
      "env": { "SEED_DATA": "1" }
    }
  }
}
```

## Governance

| Action | Requirement |
|--------|-------------|
| All reads | Actor context logged, PII access recorded |
| `request_access_change` | Reason + requester + ticket linkage, approval workflow |
| `revoke_access` | Reason + requester + ticket + break-glass policy, post-review required |
| `create_user_lifecycle_task` | Owner team assignment, downstream system tracking |

## MCP Server Manifest

```toml
server_id = "mcp_identity"
display_name = "Identity MCP"
version = "1.0.0"
domain = "it_operations"
risk_level = "high"
writes_allowed = "gated"
transports = ["stdio"]
governance_gates = ["pii_access_logged", "access_change_requires_approval", "revoke_requires_break_glass"]
```

## Contributors

<!-- ALL-CONTRIBUTORS-LIST:START -->
| [<img src="https://github.com/jkmaina.png" width="80px;" alt=""/><br /><sub><b>James Karanja Maina</b></sub>](https://github.com/jkmaina) |
|:---:|
<!-- ALL-CONTRIBUTORS-LIST:END -->

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.

---

Part of the [ADK-Rust Enterprise](https://enterprise.adk-rust.com) MCP server ecosystem.

## Registry Compliance

This server implements the [ADK MCP SDK](https://crates.io/crates/adk-mcp-sdk) contract:

- **HealthCheck** — async health probe for registry monitoring
- **mcp-server.toml** — manifest declaring tools, risk classes, and credentials
- **Structured tracing** — `RUST_LOG` env-filter for observability

## rmcp and MCP compatibility

This server is built with [`rmcp` 3.1.2](https://github.com/modelcontextprotocol/rust-sdk/releases/tag/rmcp-v3.1.2) and requires Rust 1.88 or newer. The rmcp 3 rollout retains legacy MCP initialization compatibility and targets MCP protocol revisions `2025-11-25` and `2026-07-28`.
