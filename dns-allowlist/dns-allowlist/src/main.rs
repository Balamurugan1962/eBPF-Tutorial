//! DNS Domain Allowlist — Userspace Loader
//!
//! This binary:
//!   1. Loads the compiled eBPF object (embedded at build time).
//!   2. Attaches it to the chosen network interface as a TC egress classifier.
//!   3. Populates the `ALLOWLIST` BPF HashMap with the allowed domain names.
//!   4. Waits for Ctrl-C, then cleans up (detach is automatic on drop).
//!
//! Usage (must run as root on Linux):
//!   sudo RUST_LOG=info ./dns-allowlist --iface eth0 --allow example.com
//!
//! By default, `geeksforgeeks.org` is always in the allowlist.

use anyhow::{Context, Result};
use aya::{
    maps::HashMap,
    programs::{tc, SchedClassifier, TcAttachType},
    Ebpf,
};
use aya_log::EbpfLogger;
use clap::Parser;
use dns_allowlist_common::DomainKey;
use log::{info, warn};
use tokio::signal;

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Parser)]
#[command(
    name = "dns-allowlist",
    about = "eBPF DNS domain allowlist — blocks all DNS queries except specified domains",
    version
)]
struct Opt {
    /// Network interface to attach the TC egress filter to.
    #[arg(short, long, default_value = "lo")]
    iface: String,

    /// Additional domain(s) to allow (can be specified multiple times).
    /// geeksforgeeks.org is always included by default.
    #[arg(short, long, value_name = "DOMAIN")]
    allow: Vec<String>,
}

// ─── Built-in default allowlist ───────────────────────────────────────────────

/// Domains that are always permitted, regardless of CLI flags.
const DEFAULT_ALLOWED_DOMAINS: &[&str] = &[
    "geeksforgeeks.org",
    // Add more built-in domains here as needed.
];

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::parse();

    // Enable logging (RUST_LOG env var controls verbosity, default = info).
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // ── Load the eBPF object ─────────────────────────────────────────────────
    // The eBPF ELF binary is embedded at compile time by aya-build.
    let mut bpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/dns-allowlist-ebpf"
    )))
    .context("failed to load eBPF object")?;

    // ── Start eBPF log forwarder ─────────────────────────────────────────────
    match EbpfLogger::init(&mut bpf) {
        Ok(_) => info!("eBPF logger initialized"),
        Err(e) => warn!("could not init eBPF logger (no log stmts in eBPF?): {e}"),
    }

    // ── Attach TC egress classifier ──────────────────────────────────────────
    // TC requires creating a clsact qdisc on the interface first.
    tc::qdisc_add_clsact(&opt.iface)
        .context(format!(
            "failed to add clsact qdisc to '{}' \
             (is the interface name correct? does it already exist?)",
            opt.iface
        ))
        .or_else(|e| {
            // qdisc might already exist — that is fine.
            if e.to_string().contains("File exists") {
                Ok(())
            } else {
                Err(e)
            }
        })?;

    let program: &mut SchedClassifier = bpf
        .program_mut("dns_allowlist")
        .context("eBPF program 'dns_allowlist' not found in object")?
        .try_into()
        .context("program is not a SchedClassifier")?;

    program.load().context("failed to load TC program")?;
    program
        .attach(&opt.iface, TcAttachType::Egress)
        .context("failed to attach TC egress program")?;

    info!(
        "✅ dns-allowlist attached to interface '{}' (TC egress)",
        opt.iface
    );

    // ── Populate the ALLOWLIST map ───────────────────────────────────────────
    let mut allowlist: HashMap<_, DomainKey, u32> =
        HashMap::try_from(bpf.map_mut("ALLOWLIST").context("ALLOWLIST map not found")?)
            .context("failed to access ALLOWLIST map")?;

    // Combine built-in defaults + user-supplied CLI domains.
    let all_domains: Vec<String> = DEFAULT_ALLOWED_DOMAINS
        .iter()
        .map(|s| s.to_string())
        .chain(opt.allow.iter().cloned())
        .collect();

    for domain in &all_domains {
        let domain_lower = domain.to_lowercase();
        let key = DomainKey::from_bytes(domain_lower.as_bytes());
        allowlist
            .insert(key, 0, 0)
            .with_context(|| format!("failed to insert '{}' into ALLOWLIST", domain))?;
        info!("  ✔ Allowed: {}", domain_lower);
    }

    info!("");
    info!("🚫 All other DNS queries will be DROPPED.");
    info!("Press Ctrl-C to exit (TC program will be detached automatically).");

    // ── Wait for shutdown signal ─────────────────────────────────────────────
    signal::ctrl_c().await.context("failed to listen for Ctrl-C")?;

    info!("Shutting down — removing TC program from '{}'...", opt.iface);
    // The `bpf` and `program` handles are dropped here, which causes aya to
    // detach the TC classifier automatically.

    Ok(())
}
