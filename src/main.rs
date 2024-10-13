use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    path::PathBuf,
};

use anyhow::Context;
use clap::Parser;
use sha2::Digest;

/// RaptorQ over UDP transmitter
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// UDP source address
    #[arg(short, long)]
    source: SocketAddr,

    /// UDP target address
    #[arg(short, long)]
    target: SocketAddr,

    /// Transmit interval in us
    #[arg(long, default_value = "1000")]
    interval_us: u64,

    /// Maximum transmission unit
    #[arg(long, default_value = "1280")]
    mtu: u16,

    /// Multicast address
    #[arg(long)]
    ipv4_multicast_address: Option<Ipv4Addr>,

    /// Multicast interface
    #[arg(long, default_value = "0.0.0.0")]
    ipv4_multicast_interface: Ipv4Addr,

    /// File path
    #[arg(long)]
    path: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    if args.interval_us == 0 {
        anyhow::bail!("--interval-us must be greater than 0");
    }

    let file = std::fs::read(&args.path).with_context(|| "failed to read file")?;
    let hash = sha2::Sha256::digest(&file);
    println!(
        "file hash = {}, size = {}",
        faster_hex::hex_string(&hash),
        file.len()
    );

    let body_size = args.mtu.checked_sub(36).unwrap_or(0);
    if body_size == 0 {
        anyhow::bail!("mtu is too small");
    }

    let transmission_batch_num_symbols = (file.len() / (body_size as usize) + 1) * 16;
    if transmission_batch_num_symbols > std::u32::MAX as usize / 2 {
        anyhow::bail!("file is too large");
    }

    println!("batch size = {} symbols", transmission_batch_num_symbols);

    let socket = UdpSocket::bind(&args.source).with_context(|| "failed to bind source")?;

    if let Some(addr) = args.ipv4_multicast_address {
        socket
            .set_multicast_loop_v4(true)
            .with_context(|| "failed to set multicast loop")?;
        socket
            .join_multicast_v4(&addr, &args.ipv4_multicast_interface)
            .with_context(|| "failed to join multicast")?;
    }

    if args.target.ip() == IpAddr::V4(Ipv4Addr::BROADCAST) {
        socket
            .set_broadcast(true)
            .with_context(|| "failed to set broadcast")?;
    }
    let encoder = raptorq::Encoder::with_defaults(&file, body_size);
    println!("encoder: {:?}", encoder.get_config());

    let mut current_repair_symbols_per_block = 0u32;
    const REPAIR_PACKETS_PER_BLOCK: u32 = 15u32;

    let mut num_bytes = 0usize;
    let mut num_packets = 0usize;
    loop {
        for encoder in encoder.get_block_encoders() {
            let packets =
                encoder.repair_packets(current_repair_symbols_per_block, REPAIR_PACKETS_PER_BLOCK);
            for pkt in &packets {
                let pkt = pkt.serialize();
                let mut header = [0u8; 32];
                header[0..16].copy_from_slice(&hash[0..16]);
                header[16..32].copy_from_slice(&sha2::Sha256::digest(&pkt)[0..16]);
                let pkt = [&header[..], &pkt[..]].concat();
                num_bytes += pkt.len();
                num_packets += 1;
                socket.send_to(&pkt, args.target).expect("send_to failed");
                std::thread::sleep(std::time::Duration::from_micros(args.interval_us));
            }
        }

        assert!(num_bytes > 0);

        if num_packets > 1000 {
            println!(
                "[{}] sent {} packets, {} bytes, current symbol index {}/{}",
                chrono::Utc::now(),
                num_packets,
                num_bytes,
                current_repair_symbols_per_block,
                transmission_batch_num_symbols,
            );
            num_packets = 0;
            num_bytes = 0;
        }

        current_repair_symbols_per_block += REPAIR_PACKETS_PER_BLOCK;
        if current_repair_symbols_per_block > transmission_batch_num_symbols as u32 {
            current_repair_symbols_per_block = 0;
        }
    }
}
