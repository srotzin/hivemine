// src/main.rs — HiveMine prover agent
//
// Wraps snarkVM's Puzzle::prove() and connects to ZKWork pool.
// Masquerades as an Ice River AE1 ASIC miner (300 MH/s, 500W).
//
// snarkVM 4.x API:
//   Puzzle::prove(epoch_hash: N::BlockHash, address: Address<N>, counter: u64,
//                 minimum_proof_target: Option<u64>) -> Result<Solution<N>>
//
// Usage:
//   # Benchmark mode (runs 60s, reports MH/s)
//   hivemine --benchmark
//
//   # Pool mining mode
//   hivemine --wallet aleo1... --pool aleo.hk.zk.work:10003
//
//   # Run N parallel agents
//   hivemine --wallet aleo1... --pool aleo.hk.zk.work:10003 --agents 4

mod agent;
mod pool_client;

use agent::{AgentIdentity, AE1_FINGERPRINT, agents_to_match_ae1};
use pool_client::PoolClient;

use anyhow::{bail, Context, Result};
use clap::Parser;
use rand::RngCore;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

// snarkVM 4.x imports
use snarkvm_ledger_puzzle::Puzzle;
use snarkvm_ledger_puzzle_epoch::SynthesisPuzzle;
use snarkvm_console_network::MainnetV0 as Network;
use snarkvm_console_account::Address;
// N::BlockHash for epoch hash type
use snarkvm_console_network::Network as NetworkTrait;
// AleoV0 is the circuit environment for MainnetV0 (second generic param of SynthesisPuzzle)
use snarkvm_circuit_network::AleoV0;

/// Default benchmark wallet address (placeholder)
const BENCHMARK_WALLET: &str = "aleo1qgqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqanmpl0";

/// Benchmark duration in seconds
const BENCHMARK_SECS: u64 = 60;

/// Default pool endpoint
const DEFAULT_POOL: &str = "aleo.hk.zk.work:10003";

/// Minimum proof target in benchmark mode (1 = accept any solution)
const BENCHMARK_MIN_TARGET: u64 = 1;

#[derive(Parser, Debug)]
#[command(
    name = "hivemine",
    about = "HiveMine — Aleo prover agent masquerading as Ice River AE1 (300 MH/s)",
    version = "0.1.0"
)]
struct Args {
    /// Aleo wallet address to receive mining rewards
    #[arg(long, default_value = BENCHMARK_WALLET)]
    wallet: String,

    /// Worker name (default: ae1-agent-0001)
    #[arg(long, default_value = "ae1-agent-0001")]
    worker: String,

    /// Pool address host:port
    #[arg(long, default_value = DEFAULT_POOL)]
    pool: String,

    /// Run in benchmark mode: solve for 60s, report MH/s, then exit
    #[arg(long, default_value_t = false)]
    benchmark: bool,

    /// Number of parallel prover agents (threads)
    #[arg(long, default_value_t = 1)]
    agents: u32,

    /// Verbosity level (0=error, 1=warn, 2=info, 3=debug)
    #[arg(long, default_value_t = 2)]
    verbosity: u8,

    /// Base agent ID offset (for running multiple processes)
    #[arg(long, default_value_t = 0)]
    agent_id_base: u32,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let log_level = match args.verbosity {
        0 => "error",
        1 => "warn",
        2 => "info",
        _ => "debug",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(format!("hivemine={}", log_level))),
        )
        .init();

    info!(
        "HiveMine v0.1.0 — {} @ {:.0} MH/s (nominal)",
        AE1_FINGERPRINT.model, AE1_FINGERPRINT.nominal_mhs
    );
    info!("Wallet: {}", args.wallet);
    info!("Pool:   {}", args.pool);

    if args.benchmark {
        run_benchmark(&args)?;
    } else {
        run_mining(&args)?;
    }

    Ok(())
}

/// Benchmark mode: hammer Puzzle::prove() in a tight loop for BENCHMARK_SECS seconds.
/// Reports MH/s (attempts per second / 1e6) and estimates agents-per-AE1.
fn run_benchmark(args: &Args) -> Result<()> {
    info!("=== BENCHMARK MODE ===");
    info!("Running for {}s on {} thread(s)...", BENCHMARK_SECS, args.agents);

    let num_agents = args.agents.max(1);
    let wallet = args.wallet.clone();
    let duration = Duration::from_secs(BENCHMARK_SECS);

    // Shared counters
    let total_attempts = Arc::new(AtomicU64::new(0));
    let total_solutions = Arc::new(AtomicU64::new(0));

    // Parse wallet address
    let address = Address::<Network>::from_str(&wallet)
        .context("Invalid wallet address")?;

    // Use a zero epoch hash for benchmarking — any valid BlockHash works
    let epoch_hash = <Network as NetworkTrait>::BlockHash::default();

    let start = Instant::now();
    let deadline = start + duration;

    // Spawn worker threads
    let mut handles = Vec::new();
    for i in 0..num_agents {
        let attempts_clone = Arc::clone(&total_attempts);
        let solutions_clone = Arc::clone(&total_solutions);
        let address_clone = address.clone();
        let epoch_hash_clone = epoch_hash;
        let deadline_clone = deadline;
        // Stagger starting nonces across agents
        let base_nonce = (i as u64).wrapping_mul(u64::MAX / num_agents.max(1) as u64);

        let handle = std::thread::spawn(move || {
            // Create puzzle once per thread (SynthesisPuzzle is the production puzzle)
            let puzzle = Puzzle::<Network>::new::<SynthesisPuzzle<Network, AleoV0>>();

            let mut counter = base_nonce;
            let mut local_solutions: u64 = 0;

            loop {
                if Instant::now() >= deadline_clone {
                    break;
                }

                match puzzle.prove(epoch_hash_clone, address_clone, counter, Some(BENCHMARK_MIN_TARGET)) {
                    Ok(_solution) => {
                        local_solutions += 1;
                    }
                    Err(_) => {
                        // Target not met — normal, count the attempt
                    }
                }

                // Update shared counter every attempt (each prove() takes seconds on CPU anyway)
                attempts_clone.fetch_add(1, Ordering::Relaxed);
                counter = counter.wrapping_add(1);
            }

            if local_solutions > 0 {
                solutions_clone.fetch_add(local_solutions, Ordering::Relaxed);
            }
        });
        handles.push(handle);
    }

    // Progress reporter thread
    let start_clone = start;
    let attempts_reporter = Arc::clone(&total_attempts);
    let reporter = std::thread::spawn(move || {
        let mut last_attempts: u64 = 0;
        let mut last_time = Instant::now();
        loop {
            std::thread::sleep(Duration::from_secs(10));
            let elapsed = start_clone.elapsed().as_secs_f64();
            if elapsed >= BENCHMARK_SECS as f64 + 1.0 {
                break;
            }
            let attempts = attempts_reporter.load(Ordering::Relaxed);
            let delta = attempts.saturating_sub(last_attempts);
            let delta_t = last_time.elapsed().as_secs_f64().max(0.001);
            let cur_mhs = (delta as f64 / 1_000_000.0) / delta_t;
            let cum_mhs = (attempts as f64 / 1_000_000.0) / elapsed.max(0.001);
            info!(
                "[{:.0}s] Current: {:.5} MH/s | Cumulative: {:.5} MH/s | Attempts: {}",
                elapsed, cur_mhs, cum_mhs, attempts
            );
            last_attempts = attempts;
            last_time = Instant::now();
        }
    });

    for h in handles {
        let _ = h.join();
    }
    let _ = reporter.join();

    let elapsed = start.elapsed().as_secs_f64();
    let attempts = total_attempts.load(Ordering::Relaxed);
    let solutions = total_solutions.load(Ordering::Relaxed);
    let mhs_per_agent = (attempts as f64 / 1_000_000.0) / elapsed / num_agents as f64;
    let total_mhs = (attempts as f64 / 1_000_000.0) / elapsed;

    let (agents_needed, aggregate_mhs) = agents_to_match_ae1(mhs_per_agent);

    println!("\n========== BENCHMARK RESULTS ==========");
    println!("Hardware:         {} (nominal {} MH/s, {} W)", AE1_FINGERPRINT.model, AE1_FINGERPRINT.nominal_mhs, AE1_FINGERPRINT.tdp_watts);
    println!("snarkVM API:      Puzzle::prove() (4.x, SynthesisPuzzle)");
    println!("Duration:         {:.1}s", elapsed);
    println!("Threads:          {}", num_agents);
    println!("Total attempts:   {}", attempts);
    println!("Solutions found:  {}", solutions);
    println!("MH/s per agent:   {:.6}", mhs_per_agent);
    println!("Total MH/s:       {:.6}", total_mhs);
    println!("---------------------------------------");
    println!("Agents to match 1x AE1 (300 MH/s): {}", agents_needed);
    println!("Aggregate at {}x agents: {:.2} MH/s", agents_needed, aggregate_mhs);
    println!("=======================================\n");

    let report = format!(
        "# HiveMine Benchmark Results\n\n\
         **Hardware (simulated):** {} ({:.0} MH/s nominal, {} W TDP)  \n\
         **snarkVM API:** `Puzzle::prove()` (4.x, SynthesisPuzzle)  \n\
         **Duration:** {:.1}s  \n\
         **Threads:** {}  \n\
         **Total attempts:** {}  \n\
         **Solutions found:** {}  \n\
         **MH/s per agent:** {:.6}  \n\
         **Total MH/s:** {:.6}  \n\
         \n\
         ## AE1 Equivalence\n\
         - Agents to match 1x AE1 ({:.0} MH/s): **{}**  \n\
         - Aggregate at {} agents: **{:.2} MH/s**  \n",
        AE1_FINGERPRINT.model, AE1_FINGERPRINT.nominal_mhs, AE1_FINGERPRINT.tdp_watts,
        elapsed, num_agents, attempts, solutions,
        mhs_per_agent, total_mhs,
        AE1_FINGERPRINT.nominal_mhs, agents_needed,
        agents_needed, aggregate_mhs,
    );
    let _ = std::fs::write("/home/user/workspace/hivemine-benchmark-results.md", &report);
    info!("Results saved to /home/user/workspace/hivemine-benchmark-results.md");

    Ok(())
}

/// Pool mining mode: connect to ZKWork, receive jobs, prove, submit.
fn run_mining(args: &Args) -> Result<()> {
    info!("=== POOL MINING MODE ===");

    let num_agents = args.agents.max(1);
    let wallet_str = args.wallet.clone();

    // Validate wallet address
    Address::<Network>::from_str(&wallet_str)
        .context("Invalid wallet address")?;

    let mut handles = Vec::new();
    for i in 0..num_agents {
        let agent_id = args.agent_id_base + i;
        let identity = AgentIdentity::new(agent_id, wallet_str.clone());
        let pool_addr = args.pool.clone();
        let wallet = wallet_str.clone();

        let handle = std::thread::spawn(move || {
            if let Err(e) = run_agent(identity, &pool_addr, &wallet) {
                error!("Agent {}: fatal: {:#}", agent_id, e);
            }
        });
        handles.push(handle);
    }

    for h in handles {
        let _ = h.join();
    }
    Ok(())
}

/// Single agent mining loop: connect → handshake → receive jobs → prove → submit.
fn run_agent(identity: AgentIdentity, pool_addr: &str, wallet_str: &str) -> Result<()> {
    info!("{} → pool {}", identity, pool_addr);

    let address = Address::<Network>::from_str(wallet_str)
        .context("Invalid wallet address")?;

    let mut reconnect_delay = Duration::from_secs(5);

    loop {
        match run_agent_session(&identity, pool_addr, &address) {
            Ok(()) => info!("{} session ended cleanly, reconnecting...", identity.worker_name),
            Err(e) => warn!("{} session error: {:#}. Reconnect in {:?}", identity.worker_name, e, reconnect_delay),
        }
        std::thread::sleep(reconnect_delay);
        reconnect_delay = (reconnect_delay * 2).min(Duration::from_secs(60));
    }
}

/// One pool session (connect, work, reconnect on error).
fn run_agent_session(
    identity: &AgentIdentity,
    pool_addr: &str,
    address: &Address<Network>,
) -> Result<()> {
    let mut client = PoolClient::connect(pool_addr)
        .with_context(|| format!("TCP connect to {} failed", pool_addr))?;

    let accepted = client.handshake(
        identity.worker_type(),
        identity.address_type(),
        identity.firmware_version(),
        &identity.worker_name,
        &identity.wallet_address,
    )?;
    if !accepted {
        bail!("Pool rejected {}", identity.worker_name);
    }
    info!("{} registered, worker_id={:?}", identity.worker_name, client.worker_id);

    // Create puzzle instance for this agent thread
    let puzzle = Puzzle::<Network>::new::<SynthesisPuzzle<Network, AleoV0>>();

    let mut solutions_submitted: u64 = 0;
    let mut counter: u64 = rand::thread_rng().next_u64();
    let session_start = Instant::now();

    loop {
        // Wait for next job from pool
        let job = match client.recv_message()? {
            Some(job) => job,
            None => {
                info!("{} pool shutdown", identity.worker_name);
                return Ok(());
            }
        };

        info!(
            "{} job {}: target={}, epoch_len={}",
            identity.worker_name, job.job_id, job.target, job.epoch_challenge_bytes.len()
        );

        // Deserialize epoch hash from pool job bytes
        let epoch_hash = match deserialize_epoch_hash(&job.epoch_challenge_bytes) {
            Ok(h) => h,
            Err(e) => {
                warn!("{} bad epoch_hash: {:#}", identity.worker_name, e);
                continue;
            }
        };

        let job_start = Instant::now();
        let mut attempts: u64 = 0;

        loop {
            if job_start.elapsed() > Duration::from_secs(30) {
                info!("{} job timeout, waiting for new job", identity.worker_name);
                break;
            }

            match puzzle.prove(epoch_hash, *address, counter, Some(job.target)) {
                Ok(solution) => {
                    match serialize_solution(&solution) {
                        Ok(sol_bytes) => {
                            if let Err(e) = client.send_submit(job.job_id, &sol_bytes) {
                                warn!("{} submit error: {:#}", identity.worker_name, e);
                            } else {
                                solutions_submitted += 1;
                                let mhs = (attempts as f64 / 1_000_000.0)
                                    / job_start.elapsed().as_secs_f64().max(0.001);
                                info!(
                                    "{} solution #{}: job={}, counter={}, attempts={}, {:.5} MH/s, session_uptime={:.0}s",
                                    identity.worker_name, solutions_submitted, job.job_id,
                                    counter, attempts, mhs, session_start.elapsed().as_secs_f64()
                                );
                            }
                        }
                        Err(e) => warn!("{} serialize error: {:#}", identity.worker_name, e),
                    }
                    break; // Wait for new job
                }
                Err(_) => {} // Target not met — try next counter
            }

            counter = counter.wrapping_add(1);
            attempts += 1;

            // Periodic ping every ~10M attempts to keep TCP alive
            if attempts % 10_000_000 == 0 {
                let _ = client.send_ping();
            }
        }
    }
}

/// Deserialize the epoch hash from the pool's raw bytes.
/// The pool sends a 32-byte block hash (N::BlockHash).
fn deserialize_epoch_hash(bytes: &[u8]) -> Result<<Network as NetworkTrait>::BlockHash> {
    use snarkvm_console_network::prelude::FromBytes;
    <Network as NetworkTrait>::BlockHash::from_bytes_le(bytes)
        .context("Failed to deserialize epoch BlockHash")
}

/// Serialize a Solution for submission to the pool.
fn serialize_solution(
    solution: &snarkvm_ledger_puzzle::Solution<Network>,
) -> Result<Vec<u8>> {
    use snarkvm_console_network::prelude::ToBytes;
    solution.to_bytes_le()
        .context("Failed to serialize Solution")
}
