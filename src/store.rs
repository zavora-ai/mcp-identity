use crate::types::*;
use chrono::Utc;
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

pub struct IdentityStore {
    users: Mutex<HashMap<String, User>>,
    entitlements: Mutex<HashMap<String, Vec<Entitlement>>>,
    access_requests: Mutex<Vec<AccessRequest>>,
    lifecycle_tasks: Mutex<Vec<LifecycleTask>>,
    audit_log: Mutex<Vec<serde_json::Value>>,
}

impl IdentityStore {
    pub fn new() -> Self {
        Self {
            users: Mutex::new(HashMap::new()),
            entitlements: Mutex::new(HashMap::new()),
            access_requests: Mutex::new(Vec::new()),
            lifecycle_tasks: Mutex::new(Vec::new()),
            audit_log: Mutex::new(Vec::new()),
        }
    }

    fn audit(&self, action: &str, actor: &ActorContext, details: serde_json::Value) {
        self.audit_log.lock().unwrap().push(serde_json::json!({
            "action": action, "actor": actor, "details": details, "timestamp": Utc::now(),
        }));
    }

    pub fn add_user(&self, user: User) {
        let id = user.id.clone();
        self.users.lock().unwrap().insert(id.clone(), user);
        self.entitlements.lock().unwrap().entry(id).or_default();
    }

    pub fn add_entitlement(&self, user_id: &str, ent: Entitlement) {
        self.entitlements.lock().unwrap().entry(user_id.to_string()).or_default().push(ent);
    }

    pub fn lookup_user(&self, query: &str, actor: &ActorContext) -> Vec<User> {
        self.audit("lookup_user", actor, serde_json::json!({"query": query}));
        let q = query.to_lowercase();
        self.users.lock().unwrap().values()
            .filter(|u| u.username.to_lowercase().contains(&q) || u.email.to_lowercase().contains(&q) || u.full_name.to_lowercase().contains(&q) || u.employee_id.as_deref().map(|e| e.contains(&q)).unwrap_or(false))
            .cloned().collect()
    }

    pub fn get_user(&self, id: &str) -> Option<User> {
        self.users.lock().unwrap().get(id).cloned()
    }

    pub fn get_mfa_status(&self, user_id: &str, actor: &ActorContext) -> Option<MfaStatus> {
        self.audit("get_mfa_status", actor, serde_json::json!({"user_id": user_id}));
        self.users.lock().unwrap().get(user_id).map(|u| u.mfa.clone())
    }

    pub fn get_groups(&self, user_id: &str, actor: &ActorContext) -> Vec<GroupMembership> {
        self.audit("get_user_groups", actor, serde_json::json!({"user_id": user_id}));
        self.users.lock().unwrap().get(user_id).map(|u| u.groups.clone()).unwrap_or_default()
    }

    pub fn list_entitlements(&self, user_id: &str, actor: &ActorContext) -> Vec<Entitlement> {
        self.audit("list_entitlements", actor, serde_json::json!({"user_id": user_id}));
        self.entitlements.lock().unwrap().get(user_id).cloned().unwrap_or_default()
    }

    pub fn validate_identity(&self, user_id: &str, actor: &ActorContext) -> Option<serde_json::Value> {
        self.audit("validate_identity", actor, serde_json::json!({"user_id": user_id}));
        let users = self.users.lock().unwrap();
        users.get(user_id).map(|u| serde_json::json!({
            "valid": true, "user_id": u.id, "status": u.status, "full_name": u.full_name,
            "department": u.department, "manager": u.manager, "mfa_enabled": u.mfa.enabled,
            "risk_level": u.risk_level, "active": u.status == UserStatus::Active,
        }))
    }

    pub fn request_access_change(&self, user_id: &str, action: AccessAction, resource: &str, role: &str, reason: &str, requested_by: &str, ticket_id: Option<&str>, actor: &ActorContext) -> AccessRequest {
        self.audit("request_access_change", actor, serde_json::json!({"user_id": user_id, "action": action, "resource": resource}));
        let req = AccessRequest {
            id: format!("AR-{}", Uuid::new_v4().simple().to_string()[..8].to_uppercase()),
            user_id: user_id.to_string(), action, resource: resource.to_string(), role: role.to_string(),
            reason: reason.to_string(), requested_by: requested_by.to_string(),
            ticket_id: ticket_id.map(|s| s.to_string()), status: RequestStatus::Pending,
            approver: None, policy_decision: Some("awaiting_approval".to_string()),
            created_at: Utc::now(), updated_at: Utc::now(),
        };
        self.access_requests.lock().unwrap().push(req.clone());
        req
    }

    pub fn revoke_access(&self, user_id: &str, resource: &str, role: &str, reason: &str, requested_by: &str, ticket_id: Option<&str>, actor: &ActorContext) -> Result<serde_json::Value, String> {
        self.audit("revoke_access", actor, serde_json::json!({"user_id": user_id, "resource": resource, "reason": reason, "break_glass": true}));
        let mut ents = self.entitlements.lock().unwrap();
        let user_ents = ents.get_mut(user_id).ok_or_else(|| format!("User not found: {}", user_id))?;
        let before = user_ents.len();
        user_ents.retain(|e| !(e.resource == resource && e.role == role));
        let revoked = before - user_ents.len();
        Ok(serde_json::json!({
            "revoked": revoked > 0, "user_id": user_id, "resource": resource, "role": role,
            "reason": reason, "requested_by": requested_by, "ticket_id": ticket_id,
            "effective_at": Utc::now(), "requires_post_review": true,
        }))
    }

    pub fn create_lifecycle_task(&self, user_id: &str, task_type: TaskType, owner_team: &str, ticket_id: Option<&str>, actor: &ActorContext) -> LifecycleTask {
        self.audit("create_lifecycle_task", actor, serde_json::json!({"user_id": user_id, "task_type": task_type}));
        let steps = match &task_type {
            TaskType::Onboarding => vec!["Create accounts", "Assign groups", "Provision hardware", "Schedule orientation", "Grant base entitlements"],
            TaskType::Offboarding => vec!["Revoke all access", "Disable accounts", "Collect hardware", "Transfer data ownership", "Archive mailbox"],
            TaskType::Transfer => vec!["Review current entitlements", "Revoke old team access", "Grant new team access", "Update manager"],
            TaskType::RoleChange => vec!["Review role requirements", "Adjust entitlements", "Update groups", "Notify manager"],
        }.iter().map(|s| s.to_string()).collect();
        let systems = match &task_type {
            TaskType::Onboarding => vec!["Azure AD", "GitHub", "Slack", "VPN", "Email"],
            TaskType::Offboarding => vec!["All systems"],
            _ => vec!["Azure AD", "GitHub"],
        }.iter().map(|s| s.to_string()).collect();
        let task = LifecycleTask {
            id: format!("LT-{}", Uuid::new_v4().simple().to_string()[..8].to_uppercase()),
            user_id: user_id.to_string(), task_type, status: TaskStatus::Pending,
            owner_team: owner_team.to_string(), ticket_id: ticket_id.map(|s| s.to_string()),
            steps, systems_impacted: systems, created_at: Utc::now(),
        };
        self.lifecycle_tasks.lock().unwrap().push(task.clone());
        task
    }
}
