use anyhow::Result;
use clap::Subcommand;

use crate::contract;
use crate::output::{self, Format};

#[derive(Subcommand)]
pub enum RequestAction {
    /// Create a bounty + configure repo + set delivery (atomic)
    Submit {
        /// Repository in owner/repo format
        repo: String,
        /// Amount of ROSE to deposit
        #[arg(long, default_value = "1.0")]
        amount: f64,
        /// Trigger mode: on-change, on-push, periodic
        #[arg(long, default_value = "on-change")]
        trigger: String,
        /// Audit mode: static, tee-local, tee-api
        #[arg(long, default_value = "tee-api")]
        mode: String,
    },
    /// List bounties on the market
    List {
        /// Include closed/cancelled bounties
        #[arg(long)]
        all: bool,
    },
    /// Watch a bounty for audit completion (streams NDJSON events)
    Watch {
        /// Bounty ID
        bounty_id: u64,
    },
    /// Download and decrypt audit results
    Results {
        /// Audit ID
        audit_id: u64,
    },
}

pub async fn run(action: RequestAction, format: &Format) -> Result<()> {
    match action {
        RequestAction::Submit { repo, amount, trigger, mode } => {
            let info = serde_json::json!({
                "repo": repo,
                "amount": format!("{} ROSE", amount),
                "trigger": trigger,
                "mode": mode,
                "status": "not_implemented",
                "message": "Atomic submit will chain: createBounty + setRepoInfo + setAuditConfig + setDeliveryConfig"
            });
            output::print_success(format, "request.submit", &info);
        }
        RequestAction::List { all } => {
            let bounties = contract::list_bounties(!all).await?;
            output::print_success(format, "request.list", &serde_json::json!({
                "bounties": bounties,
                "count": bounties.len(),
            }));
        }
        RequestAction::Watch { bounty_id } => {
            let info = serde_json::json!({
                "bounty_id": bounty_id,
                "status": "not_implemented"
            });
            output::print_success(format, "request.watch", &info);
        }
        RequestAction::Results { audit_id } => {
            let info = serde_json::json!({
                "audit_id": audit_id,
                "status": "not_implemented"
            });
            output::print_success(format, "request.results", &info);
        }
    }
    Ok(())
}
