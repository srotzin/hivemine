// src/pool_client.rs — ZKWork binary TCP protocol client
//
// Implements the 6block ZKWork Aleo pool protocol as described at:
// https://github.com/6block/zkwork_aleo_protocol
//
// Protocol summary (binary TCP, no framing length prefix on outer message,
// fields are directly concatenated):
//
// CLIENT → SERVER:
//   128 (connect)      : [128][worker_type:u8][address_type:u8][v_major:u8][v_minor:u8][v_patch:u8][name_len:u16_le][name:bytes][address:bytes(63)]
//   129 (submit)       : [129][worker_id:u32_le][job_id:u32_le][solution:var]
//   130 (disconnect)   : [130][worker_id:u32_le]
//   131 (ping)         : [131]
//
// SERVER → CLIENT:
//   0   (connect ack)  : [0][is_accept:u8][pool_addr:bytes(63)][worker_id:u32_le][signature:64 bytes]
//   1   (notify_job)   : [1][job_id:u32_le][target:u64_le][epoch_challenge:var]
//   2   (pool shutdown): [2]
//   3   (pong)         : [3]
//
// Note: Aleo addresses are 63 bytes ASCII (aleo1...).
// EpochChallenge / ProverSolution are snarkVM-serialized (bincode/canonical).

use anyhow::{anyhow, bail, Context, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Aleo address length (ASCII): "aleo1" + 58 chars = 63 total
pub const ALEO_ADDRESS_LEN: usize = 63;

/// Message type bytes
pub mod msg_type {
    pub const CONNECT: u8 = 128;
    pub const SUBMIT: u8 = 129;
    pub const DISCONNECT: u8 = 130;
    pub const PING: u8 = 131;

    pub const CONNECT_ACK: u8 = 0;
    pub const NOTIFY_JOB: u8 = 1;
    pub const POOL_SHUTDOWN: u8 = 2;
    pub const PONG: u8 = 3;
}

/// A pool job received from the server via notify_job.
#[derive(Debug, Clone)]
pub struct PoolJob {
    pub job_id: u32,
    /// Proof target (minimum proof target the solution must meet)
    pub target: u64,
    /// Raw serialized EpochChallenge bytes (snarkVM canonical encoding)
    pub epoch_challenge_bytes: Vec<u8>,
}

/// Pool connection state
pub struct PoolClient {
    stream: TcpStream,
    pub worker_id: Option<u32>,
    /// Pool's canonical Aleo address (for reward routing)
    pub pool_address: Option<String>,
    /// Read buffer for partial messages
    read_buf: Vec<u8>,
}

impl PoolClient {
    /// Connect to the pool TCP server.
    pub fn connect(addr: &str) -> Result<Self> {
        info!("Connecting to ZKWork pool at {}", addr);
        let stream = TcpStream::connect(addr)
            .with_context(|| format!("Failed to TCP connect to pool {}", addr))?;
        stream.set_read_timeout(Some(Duration::from_secs(120)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        stream.set_nodelay(true)?;
        Ok(Self {
            stream,
            worker_id: None,
            pool_address: None,
            read_buf: Vec::new(),
        })
    }

    /// Send the connect/registration handshake (message type 128).
    ///
    /// Format: [128][worker_type:u8][address_type:u8][v_major:u8][v_minor:u8][v_patch:u8]
    ///         [name_len:u16_le][name:bytes][address:63 bytes]
    pub fn send_connect(
        &mut self,
        worker_type: u8,
        address_type: u8,
        firmware: (u8, u8, u8),
        worker_name: &str,
        wallet_address: &str,
    ) -> Result<()> {
        let name_bytes = worker_name.as_bytes();
        let addr_bytes = wallet_address.as_bytes();

        if addr_bytes.len() != ALEO_ADDRESS_LEN {
            bail!(
                "Wallet address must be exactly {} bytes, got {}",
                ALEO_ADDRESS_LEN,
                addr_bytes.len()
            );
        }

        let mut msg = Vec::new();
        msg.push(msg_type::CONNECT);
        msg.push(worker_type);
        msg.push(address_type);
        msg.push(firmware.0);
        msg.push(firmware.1);
        msg.push(firmware.2);
        msg.write_u16::<LittleEndian>(name_bytes.len() as u16)?;
        msg.extend_from_slice(name_bytes);
        msg.extend_from_slice(addr_bytes);

        debug!("Sending connect: name={} addr={}", worker_name, wallet_address);
        self.stream.write_all(&msg)?;
        self.stream.flush()?;
        Ok(())
    }

    /// Read the connect acknowledgment (message type 0).
    ///
    /// Format: [0][is_accept:u8][pool_addr:63 bytes][worker_id:u32_le][signature:64 bytes]
    pub fn recv_connect_ack(&mut self) -> Result<bool> {
        let msg_type_byte = self.read_byte()?;
        if msg_type_byte != msg_type::CONNECT_ACK {
            bail!(
                "Expected connect ack (0), got message type {}",
                msg_type_byte
            );
        }

        let is_accept = self.read_byte()? != 0;

        // Pool address: 63 bytes
        let mut pool_addr_bytes = vec![0u8; ALEO_ADDRESS_LEN];
        self.stream.read_exact(&mut pool_addr_bytes)?;
        let pool_addr = String::from_utf8_lossy(&pool_addr_bytes).to_string();
        self.pool_address = Some(pool_addr.clone());

        // Worker ID: u32 LE
        let worker_id = self.stream.read_u32::<LittleEndian>()?;
        self.worker_id = Some(worker_id);

        // Signature: 64 bytes (ignored for now)
        let mut sig = [0u8; 64];
        let _ = self.stream.read_exact(&mut sig);

        info!(
            "Connect ack: accepted={}, pool_addr={}, worker_id={}",
            is_accept, pool_addr, worker_id
        );
        Ok(is_accept)
    }

    /// Read the next server message.
    /// Returns `None` on pool shutdown, `Some(PoolJob)` on notify_job,
    /// handles pong automatically.
    pub fn recv_message(&mut self) -> Result<Option<PoolJob>> {
        loop {
            let msg_type_byte = self.read_byte()?;
            match msg_type_byte {
                msg_type::NOTIFY_JOB => {
                    let job = self.read_notify_job()?;
                    return Ok(Some(job));
                }
                msg_type::PONG => {
                    debug!("Received pong");
                    continue;
                }
                msg_type::POOL_SHUTDOWN => {
                    warn!("Pool sent shutdown message");
                    return Ok(None);
                }
                other => {
                    warn!("Unknown message type from pool: {}", other);
                    continue;
                }
            }
        }
    }

    /// Read a notify_job message body.
    /// Format: [job_id:u32_le][target:u64_le][epoch_challenge:var_le_prefixed]
    fn read_notify_job(&mut self) -> Result<PoolJob> {
        let job_id = self.stream.read_u32::<LittleEndian>()?;
        let target = self.stream.read_u64::<LittleEndian>()?;

        // EpochChallenge is length-prefixed: [len:u32_le][bytes]
        let ec_len = self.stream.read_u32::<LittleEndian>()? as usize;
        if ec_len > 1_048_576 {
            bail!("EpochChallenge suspiciously large: {} bytes", ec_len);
        }
        let mut ec_bytes = vec![0u8; ec_len];
        self.stream.read_exact(&mut ec_bytes)?;

        debug!(
            "Received notify_job: job_id={}, target={}, epoch_challenge_len={}",
            job_id, target, ec_len
        );
        Ok(PoolJob {
            job_id,
            target,
            epoch_challenge_bytes: ec_bytes,
        })
    }

    /// Submit a prover solution to the pool (message type 129).
    ///
    /// Format: [129][worker_id:u32_le][job_id:u32_le][solution_len:u32_le][solution:bytes]
    pub fn send_submit(&mut self, job_id: u32, solution_bytes: &[u8]) -> Result<()> {
        let worker_id = self.worker_id.ok_or_else(|| anyhow!("Not connected (no worker_id)"))?;

        let mut msg = Vec::new();
        msg.push(msg_type::SUBMIT);
        msg.write_u32::<LittleEndian>(worker_id)?;
        msg.write_u32::<LittleEndian>(job_id)?;
        msg.write_u32::<LittleEndian>(solution_bytes.len() as u32)?;
        msg.extend_from_slice(solution_bytes);

        debug!(
            "Submitting solution: job_id={}, solution_bytes={}",
            job_id,
            solution_bytes.len()
        );
        self.stream.write_all(&msg)?;
        self.stream.flush()?;
        Ok(())
    }

    /// Send a ping (message type 131).
    pub fn send_ping(&mut self) -> Result<()> {
        self.stream.write_all(&[msg_type::PING])?;
        self.stream.flush()?;
        Ok(())
    }

    /// Send a disconnect (message type 130).
    pub fn send_disconnect(&mut self) -> Result<()> {
        let worker_id = self.worker_id.unwrap_or(0);
        let mut msg = Vec::new();
        msg.push(msg_type::DISCONNECT);
        msg.write_u32::<LittleEndian>(worker_id)?;
        let _ = self.stream.write_all(&msg);
        let _ = self.stream.flush();
        Ok(())
    }

    /// Read a single byte from the stream.
    fn read_byte(&mut self) -> Result<u8> {
        Ok(self.stream.read_u8()?)
    }

    /// Perform the full handshake: connect → recv_ack.
    /// Returns true if the pool accepted the worker.
    pub fn handshake(
        &mut self,
        worker_type: u8,
        address_type: u8,
        firmware: (u8, u8, u8),
        worker_name: &str,
        wallet_address: &str,
    ) -> Result<bool> {
        self.send_connect(worker_type, address_type, firmware, worker_name, wallet_address)?;
        self.recv_connect_ack()
    }
}

impl Drop for PoolClient {
    fn drop(&mut self) {
        let _ = self.send_disconnect();
    }
}
