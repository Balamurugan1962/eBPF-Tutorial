//! Shared types between the eBPF kernel program and the userspace loader.
//!
//! `DomainKey` is a fixed-size 128-byte buffer that holds a null-terminated,
//! lowercase ASCII domain name string.  It is used as the key type in the
//! `ALLOWLIST` BPF HashMap so that both kernel and userspace agree on the
//! binary layout without any heap allocation.
//!
//! Note: `unsafe impl aya_ebpf::Pod for DomainKey` is declared in
//! `dns-allowlist-ebpf` (the eBPF crate) rather than here, so that this
//! common crate stays dependency-free and builds in both std and no_std
//! environments without pulling in the aya-ebpf crate.

#![no_std]

/// Maximum domain-name length we support (including the trailing null byte).
/// 128 bytes is well above the 253-char DNS limit and is a power-of-two,
/// giving verifier-friendly bounded-loop arithmetic.
pub const DOMAIN_KEY_LEN: usize = 128;

/// A fixed-size domain-name key suitable for use in a BPF HashMap.
///
/// Stored as a lowercase, null-terminated ASCII byte slice,
/// e.g. `b"geeksforgeeks.org\0..."`.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct DomainKey {
    pub data: [u8; DOMAIN_KEY_LEN],
}

impl DomainKey {
    /// Create a zeroed (all-null) `DomainKey`.
    #[inline]
    pub const fn zeroed() -> Self {
        Self {
            data: [0u8; DOMAIN_KEY_LEN],
        }
    }

    /// Populate a `DomainKey` from a byte slice.
    /// Copies up to `DOMAIN_KEY_LEN - 1` bytes, lowercasing ASCII,
    /// and always null-terminates.
    #[inline]
    pub fn from_bytes(src: &[u8]) -> Self {
        let mut key = Self::zeroed();
        let copy_len = if src.len() < DOMAIN_KEY_LEN {
            src.len()
        } else {
            DOMAIN_KEY_LEN - 1
        };
        let mut i = 0;
        while i < copy_len {
            let b = src[i];
            key.data[i] = if b.is_ascii_uppercase() { b + 32 } else { b };
            i += 1;
        }
        key
    }
}
