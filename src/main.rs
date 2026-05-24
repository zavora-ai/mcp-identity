mod server;
mod store;
mod types;

use chrono::Utc;
use rmcp::{ServiceExt, transport::stdio};
use server::IdentityServer;
use store::IdentityStore;
use types::*;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive("info".parse().unwrap())).init();
    let store = Arc::new(IdentityStore::new());

    // Seed demo users if SEED_DATA env is set
    if std::env::var("SEED_DATA").is_ok() {
        seed_demo_data(&store);
    }

    let server = IdentityServer { store };
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

fn seed_demo_data(store: &IdentityStore) {
    let now = Utc::now();
    store.add_user(User {
        id: "usr_001".into(), username: "jkaranja".into(), email: "james.karanja@company.com".into(),
        full_name: "James Karanja".into(), department: "Engineering".into(), job_title: Some("Senior Engineer".into()),
        location: Some("Nairobi".into()), manager: Some("usr_003".into()), employee_id: Some("EMP-1001".into()),
        status: UserStatus::Active, risk_level: EntitlementRisk::Medium, last_login_at: Some(now),
        mfa: MfaStatus { enabled: true, methods: vec!["totp".into(), "webauthn".into()], last_verified: Some(now), enrolled_at: Some(now) },
        groups: vec![
            GroupMembership { group_id: "grp_eng".into(), group_name: "Engineering".into(), group_type: GroupType::Security, role_in_group: Some("member".into()) },
            GroupMembership { group_id: "grp_vpn".into(), group_name: "VPN Users".into(), group_type: GroupType::Application, role_in_group: None },
        ],
        created_at: now,
    });
    store.add_entitlement("usr_001", Entitlement { resource: "github:zavora-ai".into(), role: "write".into(), source: "azure_ad".into(), grant_type: GrantType::Group, risk: EntitlementRisk::Medium, environment: Some("production".into()), granted_at: now, expires_at: None, granted_by: "system".into(), justification: Some("Engineering team member".into()) });
    store.add_entitlement("usr_001", Entitlement { resource: "aws:staging".into(), role: "developer".into(), source: "okta".into(), grant_type: GrantType::Role, risk: EntitlementRisk::Low, environment: Some("staging".into()), granted_at: now, expires_at: None, granted_by: "manager".into(), justification: None });
    store.add_entitlement("usr_001", Entitlement { resource: "vpn".into(), role: "user".into(), source: "azure_ad".into(), grant_type: GrantType::Group, risk: EntitlementRisk::Low, environment: None, granted_at: now, expires_at: None, granted_by: "system".into(), justification: None });

    store.add_user(User {
        id: "usr_002".into(), username: "sngugi".into(), email: "sarah.ngugi@company.com".into(),
        full_name: "Sarah Ngugi".into(), department: "Marketing".into(), job_title: Some("Marketing Manager".into()),
        location: Some("Nairobi".into()), manager: Some("usr_003".into()), employee_id: Some("EMP-1002".into()),
        status: UserStatus::Active, risk_level: EntitlementRisk::Low, last_login_at: Some(now),
        mfa: MfaStatus { enabled: false, methods: vec![], last_verified: None, enrolled_at: None },
        groups: vec![
            GroupMembership { group_id: "grp_mkt".into(), group_name: "Marketing".into(), group_type: GroupType::Security, role_in_group: Some("member".into()) },
        ],
        created_at: now,
    });
    store.add_entitlement("usr_002", Entitlement { resource: "hubspot".into(), role: "admin".into(), source: "okta".into(), grant_type: GrantType::Direct, risk: EntitlementRisk::Medium, environment: None, granted_at: now, expires_at: None, granted_by: "manager".into(), justification: Some("Marketing lead".into()) });
}
