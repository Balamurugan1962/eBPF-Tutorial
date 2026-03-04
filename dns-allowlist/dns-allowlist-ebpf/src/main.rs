#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

//! DNS Domain Allowlist — eBPF TC Egress Program
//!
//! Attaches to a network interface's **egress** TC hook.
//! For every outgoing UDP packet destined for port 53 (DNS query):
//!   1. Parse the DNS QNAME (first question record).
//!   2. Normalise to lowercase dot-separated ASCII, e.g. "geeksforgeeks.org".
//!   3. Look up the domain in the ALLOWLIST BPF HashMap.
//!      - Found  → TC_ACT_OK  (pass the packet through)
//!      - Missing → TC_ACT_SHOT (drop the packet silently)
//! All non-DNS traffic is passed without inspection.

use aya_ebpf::{
    bindings::TC_ACT_OK,
    macros::{classifier, map},
    maps::HashMap,
    programs::TcContext,
};
use aya_log_ebpf::info;

use core::mem;

use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
    udp::UdpHdr,
};

use dns_allowlist_common::{DomainKey, DOMAIN_KEY_LEN};

// Safety: DomainKey is #[repr(C)] with no uninitialized padding — safe to use
// as a BPF map key. The impl lives here (not in common) so that the common
// crate compiles without aya-ebpf as a dependency.
unsafe impl aya_ebpf::Pod for DomainKey {}

/// Kernel decides to drop the packet (equivalent to XDP_DROP for TC).
const TC_ACT_SHOT: i32 = 2;

// ─── Panic handler (required in no_std) ──────────────────────────────────────

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// ─── BPF Map ─────────────────────────────────────────────────────────────────

/// Domain allowlist.  Keys are `DomainKey` (128-byte lowercase ASCII domain
/// strings).  Values are unused (just `u32`); presence of the key means
/// "allowed".  Populated by the userspace binary before the program runs.
#[map]
static ALLOWLIST: HashMap<DomainKey, u32> =
    HashMap::<DomainKey, u32>::with_max_entries(256, 0);

// ─── Entry point ─────────────────────────────────────────────────────────────

#[classifier]
pub fn dns_allowlist(ctx: TcContext) -> i32 {
    match try_dns_allowlist(&ctx) {
        Ok(action) => action,
        Err(_) => TC_ACT_OK, // on parse error: let packet through (fail-open)
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Safe pointer-at-offset helper — returns Err(()) if out of packet bounds.
#[inline(always)]
unsafe fn ptr_at<T>(ctx: &TcContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let size = mem::size_of::<T>();
    if start + offset + size > end {
        return Err(());
    }
    Ok((start + offset) as *const T)
}

/// Read one byte from the packet at `offset`.
#[inline(always)]
fn read_byte(ctx: &TcContext, offset: usize) -> Result<u8, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    if start + offset + 1 > end {
        return Err(());
    }
    Ok(unsafe { *((start + offset) as *const u8) })
}

// ─── DNS header layout ────────────────────────────────────────────────────────
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Transaction ID      |            Flags              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           QDCOUNT             |            ANCOUNT            |
// ...
//
// DNS header is 12 bytes.  After it comes the QNAME section.
const DNS_HDR_LEN: usize = 12;

/// Core filtering logic.
fn try_dns_allowlist(ctx: &TcContext) -> Result<i32, ()> {
    // ── 1. Ethernet header ───────────────────────────────────────────────────
    let ethhdr: *const EthHdr = unsafe { ptr_at(ctx, 0)? };
    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(TC_ACT_OK), // not IPv4 → pass
    }

    // ── 2. IPv4 header ───────────────────────────────────────────────────────
    let ip_offset = EthHdr::LEN;
    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(ctx, ip_offset)? };
    // proto == 17 → UDP
    if unsafe { (*ipv4hdr).proto } != network_types::ip::IpProto::Udp {
        return Ok(TC_ACT_OK); // not UDP → pass
    }
    let ihl = unsafe { ((*ipv4hdr).version_ihl & 0x0f) as usize * 4 };

    // ── 3. UDP header ────────────────────────────────────────────────────────
    let udp_offset = ip_offset + ihl;
    let udphdr: *const UdpHdr = unsafe { ptr_at(ctx, udp_offset)? };
    let dst_port = u16::from_be(unsafe { (*udphdr).dest });
    if dst_port != 53 {
        return Ok(TC_ACT_OK); // not DNS → pass
    }

    // ── 4. DNS header — check QR flag (bit 15 of Flags word) ─────────────────
    // QR=0 means query; QR=1 means response.  We only filter queries.
    let dns_offset = udp_offset + UdpHdr::LEN;
    // Flags are at bytes 2-3 of the DNS header.
    let flags_hi = read_byte(ctx, dns_offset + 2)?;
    if flags_hi & 0x80 != 0 {
        return Ok(TC_ACT_OK); // DNS response — pass (don't block replies)
    }
    // OPCODE must be 0 (standard query) — bits 3-6 of flags_hi
    if (flags_hi >> 3) & 0x0f != 0 {
        return Ok(TC_ACT_OK); // not a standard query — pass
    }

    // ── 5. Parse QNAME ───────────────────────────────────────────────────────
    // QNAME starts at dns_offset + DNS_HDR_LEN.
    // Format: <len><label bytes><len><label bytes>...<0x00>
    // We flatten it into "label.label.tld" (dot-separated lowercase).
    let qname_start = dns_offset + DNS_HDR_LEN;

    let mut key = DomainKey::zeroed();
    let mut key_pos: usize = 0;  // write cursor in key.data
    let mut pkt_off = qname_start; // read cursor in packet

    // Bounded loop: at most DOMAIN_KEY_LEN iterations (verifier-safe).
    let mut iterations = 0usize;
    loop {
        if iterations >= DOMAIN_KEY_LEN {
            break;
        }
        iterations += 1;

        let label_len = read_byte(ctx, pkt_off)? as usize;
        pkt_off += 1;

        if label_len == 0 {
            // Root label — end of QNAME.
            // Remove trailing dot if present.
            if key_pos > 0 && key.data[key_pos - 1] == b'.' {
                key.data[key_pos - 1] = 0;
            }
            break;
        }

        // Sanity: label length must be ≤ 63 per RFC 1035.
        if label_len > 63 {
            return Ok(TC_ACT_OK); // malformed — pass
        }

        // Add separating dot between labels (not before the first label).
        if key_pos > 0 {
            if key_pos >= DOMAIN_KEY_LEN - 1 {
                break;
            }
            key.data[key_pos] = b'.';
            key_pos += 1;
        }

        // Copy label bytes, lowercasing as we go.
        let mut i = 0usize;
        while i < label_len {
            if key_pos >= DOMAIN_KEY_LEN - 1 {
                break;
            }
            let b = read_byte(ctx, pkt_off + i)?;
            key.data[key_pos] = if b.is_ascii_uppercase() { b + 32 } else { b };
            key_pos += 1;
            i += 1;
        }
        pkt_off += label_len;
    }

    // ── 6. Allowlist lookup ──────────────────────────────────────────────────
    let allowed = unsafe { ALLOWLIST.get(&key).is_some() };

    info!(ctx, "DNS query: allowed={}", allowed as u32);

    if allowed {
        Ok(TC_ACT_OK)
    } else {
        Ok(TC_ACT_SHOT)
    }
}
