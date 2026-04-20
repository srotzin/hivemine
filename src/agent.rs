// src/agent.rs — Agent identity, AE1 fingerprint, wallet management
//
// Each HiveMine agent masquerades as an Ice River AE1 miner (300 MH/s, 500W).
// Worker names follow the pattern: ae1-agent-NNNN

use std::fmt;

/// Ice River AE1 hardware fingerprint constants.
/// These values are sent during pool handshake to identify the worker
/// as an AE1 class device.
pub struct Ae1Fingerprint {
    /// Hardware model identifier
    pub model: &'static str,
    /// Nominal hashrate in MH/s
    pub nominal_mhs: f64,
    /// TDP in watts
    pub tdp_watts: u32,
    /// Firmware version string sent to pool
    pub firmware_version: (u8, u8, u8),
    /// Worker type byte (AE1 class = 2)
    pub worker_type: u8,
    /// Address type byte (Aleo mainnet = 0)
    pub address_type: u8,
}

pub const AE1_FINGERPRINT: Ae1Fingerprint = Ae1Fingerprint {
    model: "Ice River AE1",
    nominal_mhs: 300.0,
    tdp_watts: 500,
    // Firmware version sent in the connect handshake (v_major, v_minor, v_patch)
    firmware_version: (1, 5, 0),
    // worker_type = 2 → AE1 ASIC class (0 = CPU, 1 = GPU, 2 = ASIC)
    worker_type: 2,
    // address_type = 0 → Aleo mainnet address
    address_type: 0,
};

/// Unique agent identity, one per logical mining thread.
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    /// Sequential agent ID (0-based)
    pub id: u32,
    /// Worker name sent to pool: "ae1-agent-NNNN"
    pub worker_name: String,
    /// Aleo wallet address string
    pub wallet_address: String,
}

impl AgentIdentity {
    /// Create a new agent identity with a given ID and wallet address.
    pub fn new(id: u32, wallet_address: impl Into<String>) -> Self {
        let wallet_address = wallet_address.into();
        let worker_name = format!("ae1-agent-{:04}", id);
        AgentIdentity {
            id,
            worker_name,
            wallet_address,
        }
    }

    /// Returns (v_major, v_minor, v_patch) firmware version for AE1 handshake.
    pub fn firmware_version(&self) -> (u8, u8, u8) {
        AE1_FINGERPRINT.firmware_version
    }

    /// Returns the worker_type byte for the pool connect message.
    pub fn worker_type(&self) -> u8 {
        AE1_FINGERPRINT.worker_type
    }

    /// Returns the address_type byte for the pool connect message.
    pub fn address_type(&self) -> u8 {
        AE1_FINGERPRINT.address_type
    }

    /// Encode the worker name as raw bytes (UTF-8).
    pub fn worker_name_bytes(&self) -> Vec<u8> {
        self.worker_name.as_bytes().to_vec()
    }

    /// Build the worker name prefix used for pool identification.
    /// Format: "ae1-agent-NNNN" where NNNN is zero-padded to 4 digits.
    pub fn pool_worker_label(&self) -> String {
        format!("{}.{}", self.wallet_address, self.worker_name)
    }
}

impl fmt::Display for AgentIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Agent[id={}, name={}, wallet={}..., hw={}@{}MH/s]",
            self.id,
            self.worker_name,
            &self.wallet_address[..12.min(self.wallet_address.len())],
            AE1_FINGERPRINT.model,
            AE1_FINGERPRINT.nominal_mhs,
        )
    }
}

/// Compute how many software agents are needed to approximate one AE1.
/// Based on measured throughput vs the AE1's 300 MH/s nominal rating.
///
/// # Arguments
/// * `measured_mhs_per_agent` — actual measured MH/s for a single agent on this hardware
///
/// # Returns
/// (agents_needed, aggregate_mhs)
pub fn agents_to_match_ae1(measured_mhs_per_agent: f64) -> (u32, f64) {
    let target = AE1_FINGERPRINT.nominal_mhs;
    if measured_mhs_per_agent <= 0.0 {
        return (1, 0.0);
    }
    let n = (target / measured_mhs_per_agent).ceil() as u32;
    let aggregate = measured_mhs_per_agent * n as f64;
    (n, aggregate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_worker_name_format() {
        let agent = AgentIdentity::new(42, "aleo1test");
        assert_eq!(agent.worker_name, "ae1-agent-0042");
    }

    #[test]
    fn test_pool_label() {
        let agent = AgentIdentity::new(1, "aleo1abc");
        assert_eq!(agent.pool_worker_label(), "aleo1abc.ae1-agent-0001");
    }

    #[test]
    fn test_agents_to_match_ae1() {
        // At 1 MH/s per agent, need ceil(300/1) = 300 agents
        let (n, agg) = agents_to_match_ae1(1.0);
        assert_eq!(n, 300);
        assert!((agg - 300.0).abs() < 0.01);
    }
}
