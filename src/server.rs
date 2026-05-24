use crate::store::IdentityStore;
use crate::types::*;
use rmcp::{handler::server::wrapper::Parameters, schemars, tool, tool_router};
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LookupUserInput {
    /// Email, username, full name, or employee ID
    pub query: String,
    #[serde(default)]
    pub actor: ActorContext,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetUserGroupsInput {
    pub user_id: String,
    #[serde(default)]
    pub actor: ActorContext,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetMfaStatusInput {
    pub user_id: String,
    #[serde(default)]
    pub actor: ActorContext,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ValidateIdentityInput {
    pub user_id: String,
    #[serde(default)]
    pub actor: ActorContext,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListEntitlementsInput {
    pub user_id: String,
    #[serde(default)]
    pub actor: ActorContext,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RequestAccessChangeInput {
    pub user_id: String,
    pub action: AccessAction,
    pub resource: String,
    pub role: String,
    pub reason: String,
    pub requested_by: String,
    pub ticket_id: Option<String>,
    #[serde(default)]
    pub actor: ActorContext,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RevokeAccessInput {
    pub user_id: String,
    pub resource: String,
    pub role: String,
    pub reason: String,
    pub requested_by: String,
    pub ticket_id: Option<String>,
    #[serde(default)]
    pub actor: ActorContext,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CreateLifecycleTaskInput {
    pub user_id: String,
    pub task_type: TaskType,
    pub owner_team: String,
    pub ticket_id: Option<String>,
    #[serde(default)]
    pub actor: ActorContext,
}

impl Default for ActorContext {
    fn default() -> Self {
        Self { actor_id: None, agent_id: None, session_id: None, ticket_id: None, purpose: None }
    }
}

#[derive(Clone)]
pub struct IdentityServer {
    pub store: Arc<IdentityStore>,
}

#[tool_router(server_handler)]
impl IdentityServer {
    #[tool(description = "Look up a user by email, username, full name, or employee ID. Returns matching users with minimized PII. Audit-logged.")]
    fn lookup_user(&self, Parameters(i): Parameters<LookupUserInput>) -> String {
        let users = self.store.lookup_user(&i.query, &i.actor);
        let results: Vec<serde_json::Value> = users.iter().map(|u| serde_json::json!({
            "id": u.id, "username": u.username, "email": u.email, "full_name": u.full_name,
            "department": u.department, "status": u.status, "risk_level": u.risk_level,
        })).collect();
        serde_json::to_string_pretty(&serde_json::json!({"count": results.len(), "users": results})).unwrap()
    }

    #[tool(description = "List groups/roles a user belongs to, including group type (security, app, role, distribution, dynamic). Audit-logged.")]
    fn get_user_groups(&self, Parameters(i): Parameters<GetUserGroupsInput>) -> String {
        let groups = self.store.get_groups(&i.user_id, &i.actor);
        serde_json::to_string_pretty(&serde_json::json!({"user_id": i.user_id, "count": groups.len(), "groups": groups})).unwrap()
    }

    #[tool(description = "Check MFA enrollment status, methods, and last verification. Returns safe metadata only (no device IDs or recovery codes). Security-sensitive read.")]
    fn get_mfa_status(&self, Parameters(i): Parameters<GetMfaStatusInput>) -> String {
        match self.store.get_mfa_status(&i.user_id, &i.actor) {
            Some(mfa) => serde_json::to_string_pretty(&serde_json::json!({"user_id": i.user_id, "enabled": mfa.enabled, "methods": mfa.methods, "last_verified": mfa.last_verified, "enrolled_at": mfa.enrolled_at})).unwrap(),
            None => format!("User not found: {}", i.user_id),
        }
    }

    #[tool(description = "Verify user exists and is active. Returns status, manager, department, MFA state, and risk level. Used by other tools to gate actions.")]
    fn validate_identity(&self, Parameters(i): Parameters<ValidateIdentityInput>) -> String {
        match self.store.validate_identity(&i.user_id, &i.actor) {
            Some(v) => serde_json::to_string_pretty(&v).unwrap(),
            None => serde_json::to_string_pretty(&serde_json::json!({"valid": false, "user_id": i.user_id, "reason": "User not found"})).unwrap(),
        }
    }

    #[tool(description = "List all entitlements for a user with source, grant type, risk level, and expiration. High-sensitivity read.")]
    fn list_entitlements(&self, Parameters(i): Parameters<ListEntitlementsInput>) -> String {
        let ents = self.store.list_entitlements(&i.user_id, &i.actor);
        serde_json::to_string_pretty(&serde_json::json!({"user_id": i.user_id, "count": ents.len(), "entitlements": ents})).unwrap()
    }

    #[tool(description = "Request access grant or revoke. Goes through approval workflow. Requires reason, requester, and optional ticket linkage. Controlled write.")]
    fn request_access_change(&self, Parameters(i): Parameters<RequestAccessChangeInput>) -> String {
        let req = self.store.request_access_change(&i.user_id, i.action, &i.resource, &i.role, &i.reason, &i.requested_by, i.ticket_id.as_deref(), &i.actor);
        serde_json::to_string_pretty(&serde_json::json!({
            "request_id": req.id, "status": req.status, "user_id": req.user_id,
            "action": req.action, "resource": req.resource, "role": req.role,
            "policy_decision": req.policy_decision, "message": "Access request submitted. Awaiting approval.",
        })).unwrap()
    }

    #[tool(description = "Emergency access revocation. Immediate effect. Requires reason, requester, ticket, and triggers post-action review. Critical/break-glass write.")]
    fn revoke_access(&self, Parameters(i): Parameters<RevokeAccessInput>) -> String {
        match self.store.revoke_access(&i.user_id, &i.resource, &i.role, &i.reason, &i.requested_by, i.ticket_id.as_deref(), &i.actor) {
            Ok(v) => serde_json::to_string_pretty(&v).unwrap(),
            Err(e) => format!("Error: {}", e),
        }
    }

    #[tool(description = "Create onboarding/offboarding/transfer/role-change lifecycle task with steps and impacted systems. Lifecycle-impacting write.")]
    fn create_user_lifecycle_task(&self, Parameters(i): Parameters<CreateLifecycleTaskInput>) -> String {
        let task = self.store.create_lifecycle_task(&i.user_id, i.task_type, &i.owner_team, i.ticket_id.as_deref(), &i.actor);
        serde_json::to_string_pretty(&serde_json::json!({
            "task_id": task.id, "task_type": task.task_type, "status": task.status,
            "owner_team": task.owner_team, "steps": task.steps, "systems_impacted": task.systems_impacted,
        })).unwrap()
    }
}
