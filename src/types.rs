use chrono::{DateTime, Utc};
use rmcp::schemars;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum UserStatus { Active, Suspended, Deactivated, Pending }

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum GrantType { Direct, Group, Role, Inherited, Temporary }

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum EntitlementRisk { Low, Medium, High, Critical }

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AccessAction { Grant, Revoke }

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RequestStatus { Pending, Approved, Denied, Expired }

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TaskType { Onboarding, Offboarding, Transfer, RoleChange }

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus { Pending, InProgress, Completed }

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum GroupType { Security, Application, Role, Distribution, Dynamic }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub full_name: String,
    pub department: String,
    pub job_title: Option<String>,
    pub location: Option<String>,
    pub manager: Option<String>,
    pub employee_id: Option<String>,
    pub status: UserStatus,
    pub mfa: MfaStatus,
    pub groups: Vec<GroupMembership>,
    pub risk_level: EntitlementRisk,
    pub last_login_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaStatus {
    pub enabled: bool,
    pub methods: Vec<String>,
    pub last_verified: Option<DateTime<Utc>>,
    pub enrolled_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMembership {
    pub group_id: String,
    pub group_name: String,
    pub group_type: GroupType,
    pub role_in_group: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entitlement {
    pub resource: String,
    pub role: String,
    pub source: String,
    pub grant_type: GrantType,
    pub risk: EntitlementRisk,
    pub environment: Option<String>,
    pub granted_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub granted_by: String,
    pub justification: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessRequest {
    pub id: String,
    pub user_id: String,
    pub action: AccessAction,
    pub resource: String,
    pub role: String,
    pub reason: String,
    pub requested_by: String,
    pub ticket_id: Option<String>,
    pub status: RequestStatus,
    pub approver: Option<String>,
    pub policy_decision: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleTask {
    pub id: String,
    pub user_id: String,
    pub task_type: TaskType,
    pub status: TaskStatus,
    pub owner_team: String,
    pub ticket_id: Option<String>,
    pub steps: Vec<String>,
    pub systems_impacted: Vec<String>,
    pub created_at: DateTime<Utc>,
}

/// Actor context for audit — who is calling, from where, for what purpose
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ActorContext {
    pub actor_id: Option<String>,
    pub agent_id: Option<String>,
    pub session_id: Option<String>,
    pub ticket_id: Option<String>,
    pub purpose: Option<String>,
}
