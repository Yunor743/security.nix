//! MiniSOC: a personal, local Security Operations Center.
//!
//! `minisoc engine` is the long-running processor (systemd user service);
//! every other subcommand is a user action, also used by the Quickshell UI.

mod ai;
mod config;
mod ctl;
mod engine;
mod filters;
mod ingest;
mod normalize;
mod store;
mod util;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "minisoc", version, about = "MiniSOC — personal local SOC")]
struct Cli {
    /// Engine configuration (default: $MINISOC_CONFIG or /etc/minisoc/engine.json)
    #[arg(long, global = true)]
    config: Option<String>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the engine (normally started by systemd --user)
    Engine,
    /// Engine, rules and AI status
    Status {
        #[arg(long)]
        json: bool,
    },
    /// List events (active, pinned, closed, tp, fp, filtered, analyzed, all)
    List {
        #[arg(long, default_value = "active")]
        state: String,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Full details of one event (fields, raw, analysis, history)
    Show {
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Keep an alert at the top; never hidden by rules or the AI
    Pin {
        id: String,
    },
    Unpin {
        id: String,
    },
    /// Close an alert as true positive: real activity, handled (logs are never modified)
    Tp {
        id: String,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Close an alert as false positive: noise. The AI filter review learns
    /// from these
    Fp {
        #[arg(required_unless_present = "all")]
        id: Option<String>,
        /// Close every active alert as false positive (pinned ones are kept)
        #[arg(long, conflicts_with = "id")]
        all: bool,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Former name of `fp`
    #[command(hide = true)]
    Discard {
        #[arg(required_unless_present = "all")]
        id: Option<String>,
        #[arg(long, conflicts_with = "id")]
        all: bool,
        #[arg(long)]
        reason: Option<String>,
    },
    /// Re-open a closed alert (its verdict is cleared)
    #[command(visible_alias = "restore")]
    Reopen {
        id: String,
    },
    /// Run the AI filter review now (FP-closed alerts -> AI rules)
    Review {
        /// Show the changes without applying nor proposing them
        #[arg(long)]
        dry_run: bool,
        /// Print the (redacted) data a review sends to the model, no request
        #[arg(long)]
        show_input: bool,
        #[arg(long)]
        json: bool,
    },
    /// Ask the AI to (re)analyze an event
    Analyze {
        id: String,
    },
    /// Show why the filter rules keep or exclude an event
    Explain {
        id: String,
        #[arg(long)]
        json: bool,
    },
    /// Manage alert_filter.yaml
    Filter {
        #[command(subcommand)]
        cmd: FilterCmd,
    },
    /// List AI proposals
    Proposals {
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// Accept or reject an AI proposal
    Proposal {
        #[arg(value_parser = ["accept", "reject"])]
        decision: String,
        id: i64,
    },
    /// Ingest log lines without the collector (stdin or a file)
    Ingest {
        #[arg(long)]
        source: String,
        #[arg(long, default_value = "json", value_parser = ["json", "raw"])]
        parser: String,
        file: Option<String>,
    },
    /// Inspect / edit the AI prompts (list, show, path, edit, reset)
    Prompts {
        action: String,
        name: Option<String>,
    },
}

#[derive(Subcommand)]
enum FilterCmd {
    /// Validate a rules file (default: the user file)
    Validate { file: Option<String> },
    /// Effective rules with hit counters
    List {
        #[arg(long)]
        json: bool,
    },
    /// Print the rule "Create filter" would add for an event
    Draft {
        id: String,
        /// Also match this field's value (repeatable)
        #[arg(long = "field")]
        fields: Vec<String>,
        /// Do not match the exact message
        #[arg(long)]
        no_message: bool,
        #[arg(long)]
        json: bool,
    },
    /// Append that rule to the user file (backup + atomic write)
    Create {
        id: String,
        #[arg(long = "field")]
        fields: Vec<String>,
        #[arg(long)]
        no_message: bool,
        #[arg(long)]
        rule_id: Option<String>,
    },
    /// List backups of the user rules file
    Backups,
    /// Restore the latest (or the given) backup
    Rollback {
        #[arg(long)]
        to: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    let cfg = match config::Config::load(cli.config.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("minisoc: config: {e}");
            std::process::exit(2);
        }
    };
    util::set_log_level(&cfg.log_level);
    let res = match cli.cmd {
        Cmd::Engine => match engine::Engine::new(cfg) {
            Ok(e) => e.run(),
            Err(e) => Err(e),
        },
        Cmd::Status { json } => ctl::status(&cfg, json),
        Cmd::List { state, limit, json } => ctl::list(&cfg, &state, limit, json),
        Cmd::Show { id, json } => ctl::show(&cfg, &id, json),
        Cmd::Pin { id } => ctl::set_pin(&cfg, &id, true),
        Cmd::Unpin { id } => ctl::set_pin(&cfg, &id, false),
        Cmd::Tp { id, reason } => ctl::close(&cfg, &id, "tp", reason.as_deref()),
        Cmd::Fp {
            id: Some(id),
            reason,
            ..
        }
        | Cmd::Discard {
            id: Some(id),
            reason,
            ..
        } => ctl::close(&cfg, &id, "fp", reason.as_deref()),
        Cmd::Fp {
            id: None, reason, ..
        }
        | Cmd::Discard {
            id: None, reason, ..
        } => ctl::close_all_fp(&cfg, reason.as_deref()),
        Cmd::Reopen { id } => ctl::restore(&cfg, &id),
        Cmd::Review {
            dry_run,
            show_input,
            json,
        } => ai::review::run_cli(&cfg, dry_run, show_input, json),
        Cmd::Analyze { id } => ctl::analyze(&cfg, &id),
        Cmd::Explain { id, json } => ctl::explain(&cfg, &id, json),
        Cmd::Filter { cmd } => match cmd {
            FilterCmd::Validate { file } => ctl::filter_validate(&cfg, file.as_deref()),
            FilterCmd::List { json } => ctl::filter_list(&cfg, json),
            FilterCmd::Draft {
                id,
                fields,
                no_message,
                json,
            } => ctl::filter_draft(&cfg, &id, &fields, !no_message, json),
            FilterCmd::Create {
                id,
                fields,
                no_message,
                rule_id,
            } => ctl::filter_create(&cfg, &id, &fields, !no_message, rule_id.as_deref()),
            FilterCmd::Backups => ctl::filter_backups(&cfg),
            FilterCmd::Rollback { to } => ctl::filter_rollback(&cfg, to.as_deref()),
        },
        Cmd::Proposals { status, json } => ctl::proposals(&cfg, status.as_deref(), json),
        Cmd::Proposal { decision, id } => ctl::proposal_decide(&cfg, id, decision == "accept"),
        Cmd::Ingest {
            source,
            parser,
            file,
        } => ctl::ingest(&cfg, &source, &parser, file.as_deref()),
        Cmd::Prompts { action, name } => ctl::prompts_cmd(&cfg, &action, name.as_deref()),
    };
    if let Err(e) = res {
        eprintln!("minisoc: {e}");
        std::process::exit(1);
    }
}
