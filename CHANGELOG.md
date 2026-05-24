# Changelog

## [1.1.0] - 2025-05-24

### Added
- HealthCheck trait implementation for registry monitoring
- `mcp-server.toml` manifest for ADK registry onboarding
- Structured tracing with `tracing-subscriber` (env-filter)

### Changed
- Edition upgraded to Rust 2024
- Added `adk-mcp-sdk` HealthCheck integration


## [1.0.0] - 2026-05-24

### Added
- 8 MCP tools: lookup_user, get_user_groups, get_mfa_status, validate_identity, list_entitlements, request_access_change, revoke_access, create_user_lifecycle_task
- Actor context (actor_id, agent_id, session_id, ticket_id, purpose) on every tool call
- Audit logging for all identity operations (PII access tracking)
- Entitlements with source, grant_type, risk level, environment, and expiration
- Group memberships with type classification (security, app, role, distribution, dynamic)
- Access request workflow with approval gates and policy decisions
- Emergency revoke with break-glass controls and mandatory post-review
- Lifecycle tasks (onboarding/offboarding/transfer/role-change) with steps and impacted systems
- Seeded demo data via SEED_DATA env var
