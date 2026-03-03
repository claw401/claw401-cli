use std::io::{self, Read, Write};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde_json::Value;

use claw401_core::{
    agent::{create_agent_attestation, verify_agent_attestation, AgentCapabilities, CreateAgentAttestationOptions, VerifyAgentAttestationOptions},
    auth::{
        generate_challenge, verify_signature, GenerateChallengeOptions, SignedChallenge,
        VerifySignatureOptions,
    },
    cache::InMemoryNonceCache,
    session::{create_session, CreateSessionOptions},
};

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

#[derive(Parser)]
#[command(
    name = "claw401",
    about = "Claw401 X401 wallet authentication protocol CLI",
    version = "0.1.0",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new authentication challenge
    Challenge {
        /// Domain to bind the challenge to
        #[arg(long)]
        domain: String,

        /// Challenge TTL in seconds [default: 300]
        #[arg(long, default_value = "300")]
        ttl_seconds: u64,

        /// Output compact JSON (no pretty-print)
        #[arg(long)]
        compact: bool,
    },

    /// Verify a signed challenge
    Verify {
        /// Path to signed challenge JSON file
        #[arg(long, conflicts_with = "stdin")]
        file: Option<PathBuf>,

        /// Read signed challenge JSON from stdin
        #[arg(long, conflicts_with = "file")]
        stdin: bool,

        /// Expected domain for verification
        #[arg(long)]
        domain: String,

        /// Clock skew tolerance in seconds [default: 30]
        #[arg(long, default_value = "30")]
        clock_skew_seconds: u64,
    },

    /// Create a session from verification inputs
    Session {
        /// Authenticated wallet public key (base58)
        #[arg(long)]
        pubkey: String,

        /// Session domain
        #[arg(long)]
        domain: String,

        /// Challenge nonce (hex, 64 chars)
        #[arg(long)]
        nonce: String,

        /// Comma-separated scope list [default: read]
        #[arg(long, default_value = "read")]
        scopes: String,

        /// Session TTL in hours [default: 24]
        #[arg(long, default_value = "24")]
        ttl_hours: u64,

        /// Output compact JSON
        #[arg(long)]
        compact: bool,
    },

    /// Create an operator-signed agent attestation
    Attest {
        /// Agent's public key (base58)
        #[arg(long)]
        agent_key: String,

        /// Operator's public key (base58)
        #[arg(long)]
        operator_key: String,

        /// Path to operator's secret key file (raw 32-byte hex or base64)
        #[arg(long)]
        operator_secret_key_file: PathBuf,

        /// Human-readable agent identifier
        #[arg(long)]
        agent_id: String,

        /// Comma-separated action strings
        #[arg(long)]
        actions: String,

        /// Comma-separated resource patterns
        #[arg(long, default_value = "")]
        resources: String,

        /// Comma-separated MCP tool names
        #[arg(long, default_value = "")]
        mcp_tools: String,

        /// Attestation TTL in hours [default: 24]
        #[arg(long, default_value = "24")]
        ttl_hours: u64,

        /// Output compact JSON
        #[arg(long)]
        compact: bool,
    },

    /// Inspect and validate any Claw401 protocol artifact
    Inspect {
        /// Path to artifact JSON file
        #[arg(long, conflicts_with = "stdin")]
        file: Option<PathBuf>,

        /// Read artifact from stdin
        #[arg(long, conflicts_with = "file")]
        stdin: bool,
    },
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli) {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Challenge { domain, ttl_seconds, compact } => {
            cmd_challenge(domain, ttl_seconds, compact)
        }
        Commands::Verify { file, stdin, domain, clock_skew_seconds } => {
            cmd_verify(file, stdin, domain, clock_skew_seconds)
        }
        Commands::Session { pubkey, domain, nonce, scopes, ttl_hours, compact } => {
            cmd_session(pubkey, domain, nonce, scopes, ttl_hours, compact)
        }
        Commands::Attest {
            agent_key,
            operator_key,
            operator_secret_key_file,
            agent_id,
            actions,
            resources,
            mcp_tools,
            ttl_hours,
            compact,
        } => cmd_attest(
            agent_key,
            operator_key,
            operator_secret_key_file,
            agent_id,
            actions,
            resources,
            mcp_tools,
            ttl_hours,
            compact,
        ),
        Commands::Inspect { file, stdin } => cmd_inspect(file, stdin),
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn cmd_challenge(domain: String, ttl_seconds: u64, compact: bool) -> Result<()> {
    let challenge = generate_challenge(GenerateChallengeOptions {
        domain,
        ttl_ms: Some(ttl_seconds * 1000),
    })
    .context("Failed to generate challenge")?;

    let value = serde_json::to_value(&challenge).context("Serialization failed")?;
    print_json(&value, compact);
    Ok(())
}

fn cmd_verify(
    file: Option<PathBuf>,
    stdin: bool,
    domain: String,
    clock_skew_seconds: u64,
) -> Result<()> {
    let json = read_input(file, stdin)?;
    let signed: SignedChallenge = serde_json::from_str(&json).context("Invalid signed challenge JSON")?;

    let cache = InMemoryNonceCache::new(None);
    let result = verify_signature(VerifySignatureOptions {
        signed_challenge: &signed,
        expected_domain: &domain,
        nonce_cache: &cache,
        clock_skew_ms: Some(clock_skew_seconds * 1000),
    });

    match result {
        Ok(ok) => {
            let output = serde_json::json!({
                "valid": true,
                "publicKey": ok.public_key,
            });
            println!("{}", serde_json::to_string_pretty(&output)?);
            Ok(())
        }
        Err(e) => {
            let output = serde_json::json!({
                "valid": false,
                "error": e.to_string(),
            });
            eprintln!("{}", serde_json::to_string_pretty(&output)?);
            std::process::exit(1);
        }
    }
}

fn cmd_session(
    pubkey: String,
    domain: String,
    nonce: String,
    scopes_str: String,
    ttl_hours: u64,
    compact: bool,
) -> Result<()> {
    let scopes: Vec<String> = scopes_str.split(',').map(|s| s.trim().to_string()).collect();

    let session = create_session(CreateSessionOptions {
        public_key: pubkey,
        domain,
        nonce,
        scopes,
        ttl_ms: Some(ttl_hours * 60 * 60 * 1000),
    });

    let value = serde_json::to_value(&session).context("Serialization failed")?;
    print_json(&value, compact);
    Ok(())
}

fn cmd_attest(
    agent_key: String,
    operator_key: String,
    operator_secret_key_file: PathBuf,
    agent_id: String,
    actions_str: String,
    resources_str: String,
    mcp_tools_str: String,
    ttl_hours: u64,
    compact: bool,
) -> Result<()> {
    let key_raw = std::fs::read_to_string(&operator_secret_key_file)
        .context("Failed to read operator secret key file")?;
    let key_bytes = parse_secret_key(key_raw.trim())?;
    let signing_key = SigningKey::from_bytes(&key_bytes);

    let actions: Vec<String> = actions_str.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    let resources: Vec<String> = resources_str.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    let mcp_tools: Vec<String> = mcp_tools_str.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();

    let capabilities = AgentCapabilities { actions, resources, mcp_tools };

    let attestation = create_agent_attestation(CreateAgentAttestationOptions {
        agent_key,
        operator_key,
        operator_signing_key: &signing_key,
        agent_id,
        capabilities,
        ttl_ms: Some(ttl_hours * 60 * 60 * 1000),
    })
    .context("Failed to create attestation")?;

    let value = serde_json::to_value(&attestation).context("Serialization failed")?;
    print_json(&value, compact);
    Ok(())
}

fn cmd_inspect(file: Option<PathBuf>, stdin: bool) -> Result<()> {
    let json = read_input(file, stdin)?;
    let value: Value = serde_json::from_str(&json).context("Invalid JSON")?;

    // Detect artifact type by presence of key fields
    let artifact_type = detect_artifact_type(&value);
    eprintln!("Artifact type: {artifact_type}");

    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_input(file: Option<PathBuf>, _stdin: bool) -> Result<String> {
    if let Some(path) = file {
        std::fs::read_to_string(&path).with_context(|| format!("Failed to read {}", path.display()))
    } else {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf).context("Failed to read stdin")?;
        Ok(buf)
    }
}

fn print_json(value: &Value, compact: bool) {
    if compact {
        println!("{}", serde_json::to_string(value).unwrap());
    } else {
        println!("{}", serde_json::to_string_pretty(value).unwrap());
    }
}

fn parse_secret_key(raw: &str) -> Result<[u8; 32]> {
    // Try hex first (64 chars = 32 bytes)
    if raw.len() == 64 && raw.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes = hex::decode(raw).context("Invalid hex secret key")?;
        return bytes.try_into().map_err(|_| anyhow::anyhow!("Expected 32-byte key"));
    }
    // Try base64
    let decoded = BASE64.decode(raw).context("Invalid base64 secret key")?;
    decoded.try_into().map_err(|_| anyhow::anyhow!("Expected 32-byte key after base64 decode"))
}

fn detect_artifact_type(value: &Value) -> &'static str {
    if value.get("attestationId").is_some() {
        "AgentAttestation"
    } else if value.get("sessionId").is_some() {
        "Session"
    } else if value.get("challenge").is_some() && value.get("signature").is_some() {
        "SignedChallenge"
    } else if value.get("nonce").is_some() && value.get("domain").is_some() && value.get("issuedAt").is_some() {
        "Challenge"
    } else if value.get("issuer").is_some() && value.get("subject").is_some() {
        "Proof"
    } else {
        "Unknown"
    }
}
