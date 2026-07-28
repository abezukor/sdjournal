use crate::error::{Result, SdJournalError};
use crate::util::{hex_decode, hex_encode};
use std::cmp::Ordering;
use std::fmt;

const PREFIX_V1: &str = "SJ1:";

const TAG_FILE_OFFSET: u8 = 0x01;
const TAG_SYSTEMD_RAW: u8 = 0x02;
const TAG_SYSTEMD_FIELDS: u8 = 0x03;
const TAG_ENTRY_KEY: u8 = 0x04;
const TAG_LOCATION_KEY: u8 = 0x05;

const SYSTEMD_MASK_SEQNUM_ID: u8 = 1 << 0;
const SYSTEMD_MASK_SEQNUM: u8 = 1 << 1;
const SYSTEMD_MASK_BOOT_ID: u8 = 1 << 2;
const SYSTEMD_MASK_MONOTONIC: u8 = 1 << 3;
const SYSTEMD_MASK_REALTIME: u8 = 1 << 4;
const SYSTEMD_MASK_XOR_HASH: u8 = 1 << 5;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum CursorKind {
    FileOffset {
        file_id: [u8; 16],
        entry_offset: u64,
    },
    LegacyEntryKey(LegacyEntryKey),
    LocationKey(SdJournalEntryKey),
    Systemd(SystemdCursor),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct LegacyEntryKey {
    pub(crate) file_id: [u8; 16],
    pub(crate) entry_offset: u64,
    pub(crate) seqnum: u64,
    pub(crate) realtime_usec: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SdJournalEntryKey {
    pub(crate) file_id: [u8; 16],
    pub(crate) entry_offset: u64,
    pub(crate) seqnum_id: [u8; 16],
    pub(crate) seqnum: u64,
    pub(crate) boot_id: [u8; 16],
    pub(crate) monotonic_usec: u64,
    pub(crate) realtime_usec: u64,
    pub(crate) xor_hash: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct SystemdCursor {
    pub(crate) seqnum_id: Option<[u8; 16]>,
    pub(crate) seqnum: Option<u64>,
    pub(crate) boot_id: Option<[u8; 16]>,
    pub(crate) monotonic_usec: Option<u64>,
    pub(crate) realtime_usec: Option<u64>,
    pub(crate) xor_hash: Option<u64>,
}

impl SystemdCursor {
    fn is_valid(&self) -> bool {
        (self.seqnum_id.is_some() && self.seqnum.is_some())
            || (self.boot_id.is_some() && self.monotonic_usec.is_some())
            || self.realtime_usec.is_some()
    }

    fn systemd_wire_string(&self) -> Option<String> {
        let seqnum_id = self.seqnum_id?;
        let seqnum = self.seqnum?;
        let boot_id = self.boot_id?;
        let monotonic_usec = self.monotonic_usec?;
        let realtime_usec = self.realtime_usec?;
        let xor_hash = self.xor_hash?;

        Some(format!(
            "s={};i={seqnum:x};b={};m={monotonic_usec:x};t={realtime_usec:x};x={xor_hash:x}",
            crate::util::hex_encode(&seqnum_id),
            crate::util::hex_encode(&boot_id),
        ))
    }
}

/// Compare two complete journal locations using systemd's stable merge ordering.
///
/// This intentionally may return [`Ordering::Equal`] for the same logical entry copied into two
/// different files. The conditional relation is not transitive across unrelated sequence/boot
/// streams, so it must only be used for systemd-style pairwise selection or boundary comparison;
/// it must not back [`Ord`], `sort_by`, or a binary heap.
pub(crate) fn compare_entry_keys(left: &SdJournalEntryKey, right: &SdJournalEntryKey) -> Ordering {
    if left.seqnum_id == right.seqnum_id {
        let ord = left.seqnum.cmp(&right.seqnum);
        if ord != Ordering::Equal {
            return ord;
        }
    }

    if left.boot_id == right.boot_id {
        let ord = left.monotonic_usec.cmp(&right.monotonic_usec);
        if ord != Ordering::Equal {
            return ord;
        }
    }

    left.realtime_usec
        .cmp(&right.realtime_usec)
        .then_with(|| left.xor_hash.cmp(&right.xor_hash))
}

pub(crate) fn same_entry(left: &SdJournalEntryKey, right: &SdJournalEntryKey) -> bool {
    left.seqnum_id == right.seqnum_id
        && left.seqnum == right.seqnum
        && left.boot_id == right.boot_id
        && left.monotonic_usec == right.monotonic_usec
        && left.realtime_usec == right.realtime_usec
        && left.xor_hash == right.xor_hash
}

/// Opaque cursor for checkpointing and resuming journal iteration.
///
/// A cursor can be round-tripped through [`std::string::ToString::to_string`] and
/// [`Cursor::parse`]. The textual representation is stable for `sdjournal`-generated cursors and
/// also accepts native systemd cursor strings for resume interoperability.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Cursor {
    kind: CursorKind,
}

impl Cursor {
    #[cfg(test)]
    pub(crate) fn new_entry_key(
        file_id: [u8; 16],
        entry_offset: u64,
        seqnum: u64,
        realtime_usec: u64,
    ) -> Self {
        Self {
            kind: CursorKind::LegacyEntryKey(LegacyEntryKey {
                file_id,
                entry_offset,
                seqnum,
                realtime_usec,
            }),
        }
    }

    pub(crate) fn new_location_key(key: SdJournalEntryKey) -> Self {
        Self {
            kind: CursorKind::LocationKey(key),
        }
    }

    pub(crate) fn file_offset(&self) -> Option<([u8; 16], u64)> {
        match &self.kind {
            CursorKind::FileOffset {
                file_id,
                entry_offset,
            } => Some((*file_id, *entry_offset)),
            CursorKind::LegacyEntryKey(k) => Some((k.file_id, k.entry_offset)),
            CursorKind::LocationKey(k) => Some((k.file_id, k.entry_offset)),
            CursorKind::Systemd(_) => None,
        }
    }

    pub(crate) fn sdjournal_entry_key(&self) -> Option<SdJournalEntryKey> {
        match &self.kind {
            CursorKind::LocationKey(k) => Some(*k),
            CursorKind::FileOffset { .. }
            | CursorKind::LegacyEntryKey(_)
            | CursorKind::Systemd(_) => None,
        }
    }

    pub(crate) fn legacy_entry_key(&self) -> Option<LegacyEntryKey> {
        match &self.kind {
            CursorKind::LegacyEntryKey(k) => Some(*k),
            CursorKind::FileOffset { .. } | CursorKind::LocationKey(_) | CursorKind::Systemd(_) => {
                None
            }
        }
    }

    pub(crate) fn systemd(&self) -> Option<&SystemdCursor> {
        match &self.kind {
            CursorKind::Systemd(v) => Some(v),
            CursorKind::FileOffset { .. }
            | CursorKind::LegacyEntryKey(_)
            | CursorKind::LocationKey(_) => None,
        }
    }

    /// Parse a cursor from a string.
    ///
    /// This accepts both the `sdjournal` versioned format (`SJ1:...`) and native systemd cursor
    /// strings.
    ///
    /// The returned cursor can be passed to [`crate::Journal::seek_cursor`] or
    /// [`crate::JournalQuery::after_cursor`].
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if let Some(rest) = s.strip_prefix(PREFIX_V1) {
            let bytes = hex_decode(rest)?;
            let tag = *bytes.first().ok_or_else(|| SdJournalError::InvalidQuery {
                reason: "empty cursor payload".to_string(),
            })?;
            match tag {
                TAG_FILE_OFFSET => {
                    if bytes.len() != 1 + 16 + 8 {
                        return Err(SdJournalError::InvalidQuery {
                            reason: "invalid cursor length for SJ1 FileOffset".to_string(),
                        });
                    }
                    let mut file_id = [0u8; 16];
                    file_id.copy_from_slice(&bytes[1..17]);
                    let mut off = [0u8; 8];
                    off.copy_from_slice(&bytes[17..25]);
                    Ok(Cursor {
                        kind: CursorKind::FileOffset {
                            file_id,
                            entry_offset: u64::from_le_bytes(off),
                        },
                    })
                }
                TAG_ENTRY_KEY => {
                    if bytes.len() != 1 + 16 + 8 + 8 + 8 {
                        return Err(SdJournalError::InvalidQuery {
                            reason: "invalid cursor length for SJ1 EntryKey".to_string(),
                        });
                    }

                    let mut file_id = [0u8; 16];
                    file_id.copy_from_slice(&bytes[1..17]);

                    let mut entry_offset = [0u8; 8];
                    entry_offset.copy_from_slice(&bytes[17..25]);

                    let mut seqnum = [0u8; 8];
                    seqnum.copy_from_slice(&bytes[25..33]);

                    let mut realtime = [0u8; 8];
                    realtime.copy_from_slice(&bytes[33..41]);

                    Ok(Cursor {
                        kind: CursorKind::LegacyEntryKey(LegacyEntryKey {
                            file_id,
                            entry_offset: u64::from_le_bytes(entry_offset),
                            seqnum: u64::from_le_bytes(seqnum),
                            realtime_usec: u64::from_le_bytes(realtime),
                        }),
                    })
                }
                TAG_LOCATION_KEY => {
                    const LOCATION_KEY_LEN: usize = 1 + 16 + 8 + 16 + 8 + 16 + 8 + 8 + 8;
                    if bytes.len() != LOCATION_KEY_LEN {
                        return Err(SdJournalError::InvalidQuery {
                            reason: "invalid cursor length for SJ1 LocationKey".to_string(),
                        });
                    }

                    let mut input = &bytes[1..];
                    fn take<const N: usize>(input: &mut &[u8]) -> Result<[u8; N]> {
                        let (head, tail) = input.split_at_checked(N).ok_or_else(|| {
                            SdJournalError::InvalidQuery {
                                reason: "truncated SJ1 LocationKey".to_string(),
                            }
                        })?;
                        *input = tail;
                        head.try_into().map_err(|_| SdJournalError::InvalidQuery {
                            reason: "invalid SJ1 LocationKey field width".to_string(),
                        })
                    }

                    let file_id = take::<16>(&mut input)?;
                    let entry_offset = u64::from_le_bytes(take::<8>(&mut input)?);
                    let seqnum_id = take::<16>(&mut input)?;
                    let seqnum = u64::from_le_bytes(take::<8>(&mut input)?);
                    let boot_id = take::<16>(&mut input)?;
                    let monotonic_usec = u64::from_le_bytes(take::<8>(&mut input)?);
                    let realtime_usec = u64::from_le_bytes(take::<8>(&mut input)?);
                    let xor_hash = u64::from_le_bytes(take::<8>(&mut input)?);

                    Ok(Cursor {
                        kind: CursorKind::LocationKey(SdJournalEntryKey {
                            file_id,
                            entry_offset,
                            seqnum_id,
                            seqnum,
                            boot_id,
                            monotonic_usec,
                            realtime_usec,
                            xor_hash,
                        }),
                    })
                }
                TAG_SYSTEMD_RAW => {
                    let raw = String::from_utf8(bytes[1..].to_vec()).map_err(|_| {
                        SdJournalError::InvalidQuery {
                            reason: "invalid UTF-8 in SJ1 systemd cursor".to_string(),
                        }
                    })?;
                    Ok(Cursor {
                        kind: CursorKind::Systemd(parse_systemd_cursor(&raw)?),
                    })
                }
                TAG_SYSTEMD_FIELDS => Ok(Cursor {
                    kind: CursorKind::Systemd(parse_systemd_fields(&bytes[1..])?),
                }),
                _ => Err(SdJournalError::Unsupported {
                    reason: "unknown SJ1 cursor variant".to_string(),
                }),
            }
        } else {
            Ok(Cursor {
                kind: CursorKind::Systemd(parse_systemd_cursor(s)?),
            })
        }
    }
}

impl fmt::Display for Cursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut bytes = Vec::new();
        match &self.kind {
            CursorKind::FileOffset {
                file_id,
                entry_offset,
            } => {
                bytes.push(TAG_FILE_OFFSET);
                bytes.extend_from_slice(file_id);
                bytes.extend_from_slice(&entry_offset.to_le_bytes());
            }
            CursorKind::LegacyEntryKey(k) => {
                bytes.push(TAG_ENTRY_KEY);
                bytes.extend_from_slice(&k.file_id);
                bytes.extend_from_slice(&k.entry_offset.to_le_bytes());
                bytes.extend_from_slice(&k.seqnum.to_le_bytes());
                bytes.extend_from_slice(&k.realtime_usec.to_le_bytes());
            }
            CursorKind::LocationKey(k) => {
                // Emit the long-supported systemd cursor variant so checkpoints remain readable
                // by older sdjournal releases during a rolling upgrade or rollback. We still
                // accept TAG_LOCATION_KEY above for checkpoints produced by intermediate builds.
                bytes.push(TAG_SYSTEMD_RAW);
                let raw = format!(
                    "s={};i={:x};b={};m={:x};t={:x};x={:x}",
                    crate::util::hex_encode(&k.seqnum_id),
                    k.seqnum,
                    crate::util::hex_encode(&k.boot_id),
                    k.monotonic_usec,
                    k.realtime_usec,
                    k.xor_hash,
                );
                bytes.extend_from_slice(raw.as_bytes());
            }
            CursorKind::Systemd(fields) => {
                if let Some(raw) = fields.systemd_wire_string() {
                    bytes.push(TAG_SYSTEMD_RAW);
                    bytes.extend_from_slice(raw.as_bytes());
                } else {
                    bytes.push(TAG_SYSTEMD_FIELDS);
                    let mut mask = 0u8;
                    if fields.seqnum_id.is_some() {
                        mask |= SYSTEMD_MASK_SEQNUM_ID;
                    }
                    if fields.seqnum.is_some() {
                        mask |= SYSTEMD_MASK_SEQNUM;
                    }
                    if fields.boot_id.is_some() {
                        mask |= SYSTEMD_MASK_BOOT_ID;
                    }
                    if fields.monotonic_usec.is_some() {
                        mask |= SYSTEMD_MASK_MONOTONIC;
                    }
                    if fields.realtime_usec.is_some() {
                        mask |= SYSTEMD_MASK_REALTIME;
                    }
                    if fields.xor_hash.is_some() {
                        mask |= SYSTEMD_MASK_XOR_HASH;
                    }

                    bytes.push(mask);
                    if let Some(v) = fields.seqnum_id {
                        bytes.extend_from_slice(&v);
                    }
                    if let Some(v) = fields.seqnum {
                        bytes.extend_from_slice(&v.to_le_bytes());
                    }
                    if let Some(v) = fields.boot_id {
                        bytes.extend_from_slice(&v);
                    }
                    if let Some(v) = fields.monotonic_usec {
                        bytes.extend_from_slice(&v.to_le_bytes());
                    }
                    if let Some(v) = fields.realtime_usec {
                        bytes.extend_from_slice(&v.to_le_bytes());
                    }
                    if let Some(v) = fields.xor_hash {
                        bytes.extend_from_slice(&v.to_le_bytes());
                    }
                }
            }
        }
        write!(f, "{PREFIX_V1}{}", hex_encode(&bytes))
    }
}

fn parse_systemd_fields(mut bytes: &[u8]) -> Result<SystemdCursor> {
    let mask = *bytes.first().ok_or_else(|| SdJournalError::InvalidQuery {
        reason: "missing systemd cursor mask".to_string(),
    })?;
    bytes = &bytes[1..];

    fn take<const N: usize>(bytes: &mut &[u8], reason: &'static str) -> Result<[u8; N]> {
        if bytes.len() < N {
            return Err(SdJournalError::InvalidQuery {
                reason: reason.to_string(),
            });
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&bytes[..N]);
        *bytes = &bytes[N..];
        Ok(out)
    }

    let seqnum_id = if mask & SYSTEMD_MASK_SEQNUM_ID != 0 {
        Some(take::<16>(&mut bytes, "systemd cursor missing seqnum_id")?)
    } else {
        None
    };
    let seqnum = if mask & SYSTEMD_MASK_SEQNUM != 0 {
        Some(u64::from_le_bytes(take::<8>(
            &mut bytes,
            "systemd cursor missing seqnum",
        )?))
    } else {
        None
    };
    let boot_id = if mask & SYSTEMD_MASK_BOOT_ID != 0 {
        Some(take::<16>(&mut bytes, "systemd cursor missing boot_id")?)
    } else {
        None
    };
    let monotonic_usec = if mask & SYSTEMD_MASK_MONOTONIC != 0 {
        Some(u64::from_le_bytes(take::<8>(
            &mut bytes,
            "systemd cursor missing monotonic_usec",
        )?))
    } else {
        None
    };
    let realtime_usec = if mask & SYSTEMD_MASK_REALTIME != 0 {
        Some(u64::from_le_bytes(take::<8>(
            &mut bytes,
            "systemd cursor missing realtime_usec",
        )?))
    } else {
        None
    };
    let xor_hash = if mask & SYSTEMD_MASK_XOR_HASH != 0 {
        Some(u64::from_le_bytes(take::<8>(
            &mut bytes,
            "systemd cursor missing xor_hash",
        )?))
    } else {
        None
    };

    if !bytes.is_empty() {
        return Err(SdJournalError::InvalidQuery {
            reason: "trailing bytes in systemd cursor payload".to_string(),
        });
    }

    let out = SystemdCursor {
        seqnum_id,
        seqnum,
        boot_id,
        monotonic_usec,
        realtime_usec,
        xor_hash,
    };
    if !out.is_valid() {
        return Err(SdJournalError::InvalidQuery {
            reason: "systemd cursor missing required fields".to_string(),
        });
    }

    Ok(out)
}

fn parse_systemd_cursor(s: &str) -> Result<SystemdCursor> {
    let s = s.trim();
    if s.is_empty() {
        return Err(SdJournalError::InvalidQuery {
            reason: "empty cursor".to_string(),
        });
    }

    fn parse_id128(s: &str, kind: &'static str) -> Result<[u8; 16]> {
        use std::borrow::Cow;

        let cleaned = if s.contains('-') {
            Cow::Owned(s.chars().filter(|&c| c != '-').collect::<String>())
        } else {
            Cow::Borrowed(s)
        };

        let bytes = hex_decode(cleaned.as_ref())?;
        if bytes.len() != 16 {
            return Err(SdJournalError::InvalidQuery {
                reason: format!("{kind} must be 16 bytes (32 hex chars)"),
            });
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(&bytes);
        Ok(out)
    }

    fn parse_hex_u64(s: &str, kind: &'static str) -> Result<u64> {
        u64::from_str_radix(s, 16).map_err(|_| SdJournalError::InvalidQuery {
            reason: format!("{kind} is not valid hex"),
        })
    }

    let mut out = SystemdCursor {
        seqnum_id: None,
        seqnum: None,
        boot_id: None,
        monotonic_usec: None,
        realtime_usec: None,
        xor_hash: None,
    };

    for part in s.split(';') {
        if part.is_empty() {
            return Err(SdJournalError::InvalidQuery {
                reason: "invalid systemd cursor: empty segment".to_string(),
            });
        }
        let bytes = part.as_bytes();
        if bytes.len() < 2 || bytes[1] != b'=' {
            return Err(SdJournalError::InvalidQuery {
                reason: "invalid systemd cursor segment".to_string(),
            });
        }
        let key = bytes[0];
        let value = &part[2..];
        match key {
            b's' => out.seqnum_id = Some(parse_id128(value, "seqnum_id")?),
            b'i' => out.seqnum = Some(parse_hex_u64(value, "seqnum")?),
            b'b' => out.boot_id = Some(parse_id128(value, "boot_id")?),
            b'm' => out.monotonic_usec = Some(parse_hex_u64(value, "monotonic_usec")?),
            b't' => out.realtime_usec = Some(parse_hex_u64(value, "realtime_usec")?),
            b'x' => out.xor_hash = Some(parse_hex_u64(value, "xor_hash")?),
            _ => {}
        }
    }

    if !out.is_valid() {
        return Err(SdJournalError::InvalidQuery {
            reason: "systemd cursor missing required fields".to_string(),
        });
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_file_offset_roundtrip() {
        let file_id = [0x11u8; 16];
        let entry_offset = 0x1122334455667788u64;

        let mut bytes = Vec::new();
        bytes.push(TAG_FILE_OFFSET);
        bytes.extend_from_slice(&file_id);
        bytes.extend_from_slice(&entry_offset.to_le_bytes());
        let s = format!("{PREFIX_V1}{}", hex_encode(&bytes));
        assert!(s.starts_with(PREFIX_V1));

        let parsed = Cursor::parse(&s).unwrap();
        assert_eq!(parsed.file_offset(), Some((file_id, entry_offset)));
        assert_eq!(parsed.to_string(), s);
    }

    #[test]
    fn cursor_systemd_string_is_parsed() {
        let c = Cursor::parse(
            "s=0123456789abcdef0123456789abcdef;i=1;b=11111111111111111111111111111111;m=2;t=3;x=4",
        )
        .unwrap();
        let s = c.to_string();
        assert!(s.starts_with(PREFIX_V1));

        let parsed = Cursor::parse(&s).unwrap();
        assert_eq!(parsed.to_string(), s);
        assert!(parsed.file_offset().is_none());
        assert!(parsed.systemd().is_some());
    }

    #[test]
    fn cursor_entry_key_roundtrip() {
        let file_id = [0x11u8; 16];
        let entry_offset = 0x1122334455667788u64;
        let seqnum = 0x99aabbccddu64;
        let realtime_usec = 0x11220000u64;
        let c = Cursor::new_entry_key(file_id, entry_offset, seqnum, realtime_usec);
        let s = c.to_string();
        assert!(s.starts_with(PREFIX_V1));

        let parsed = Cursor::parse(&s).unwrap();
        assert_eq!(
            parsed.legacy_entry_key(),
            Some(LegacyEntryKey {
                file_id,
                entry_offset,
                seqnum,
                realtime_usec
            })
        );
        assert!(parsed.sdjournal_entry_key().is_none());
        assert_eq!(parsed.to_string(), s);
    }

    #[test]
    fn cursor_location_key_roundtrip() {
        let key = SdJournalEntryKey {
            file_id: [0x11; 16],
            entry_offset: 0x1122_3344_5566_7788,
            seqnum_id: [0x22; 16],
            seqnum: 0x99aa_bbcc,
            boot_id: [0x33; 16],
            monotonic_usec: 0x4455,
            realtime_usec: 0x6677,
            xor_hash: 0x8899,
        };
        let cursor = Cursor::new_location_key(key);
        let encoded = cursor.to_string();

        let parsed = Cursor::parse(&encoded).unwrap();
        let systemd = parsed.systemd().unwrap();
        assert_eq!(systemd.seqnum_id, Some(key.seqnum_id));
        assert_eq!(systemd.seqnum, Some(key.seqnum));
        assert_eq!(systemd.boot_id, Some(key.boot_id));
        assert_eq!(systemd.monotonic_usec, Some(key.monotonic_usec));
        assert_eq!(systemd.realtime_usec, Some(key.realtime_usec));
        assert_eq!(systemd.xor_hash, Some(key.xor_hash));
        assert_eq!(parsed.file_offset(), None);
        assert_eq!(parsed.to_string(), encoded);
    }

    #[test]
    fn entry_key_comparison_uses_systemd_priority() {
        let base = SdJournalEntryKey {
            file_id: [1; 16],
            entry_offset: 1,
            seqnum_id: [2; 16],
            seqnum: 10,
            boot_id: [3; 16],
            monotonic_usec: 100,
            realtime_usec: 1_000,
            xor_hash: 9,
        };

        let mut later_sequence = base;
        later_sequence.seqnum = 11;
        later_sequence.realtime_usec = 1;
        assert_eq!(compare_entry_keys(&base, &later_sequence), Ordering::Less);

        let mut later_monotonic = base;
        later_monotonic.seqnum_id = [4; 16];
        later_monotonic.monotonic_usec = 101;
        later_monotonic.realtime_usec = 1;
        assert_eq!(compare_entry_keys(&base, &later_monotonic), Ordering::Less);

        let mut copied = base;
        copied.file_id = [5; 16];
        copied.entry_offset = 99;
        assert_eq!(compare_entry_keys(&base, &copied), Ordering::Equal);
        assert!(same_entry(&base, &copied));
    }

    #[test]
    fn cursor_systemd_fields_variant_roundtrip() {
        let c = Cursor::parse("t=3").unwrap();
        let s = c.to_string();
        assert!(s.starts_with(PREFIX_V1));

        let parsed = Cursor::parse(&s).unwrap();
        assert_eq!(parsed.to_string(), s);
        assert!(parsed.systemd().is_some());
        assert!(parsed.file_offset().is_none());
    }

    #[test]
    fn cursor_rejects_empty_systemd_cursor() {
        match Cursor::parse("") {
            Ok(_) => panic!("expected InvalidQuery"),
            Err(err) => assert!(matches!(err, SdJournalError::InvalidQuery { .. })),
        }
    }

    #[test]
    fn cursor_rejects_empty_sj1_payload() {
        match Cursor::parse(PREFIX_V1) {
            Ok(_) => panic!("expected InvalidQuery"),
            Err(err) => assert!(matches!(err, SdJournalError::InvalidQuery { .. })),
        }
    }

    #[test]
    fn cursor_rejects_invalid_entry_key_length() {
        let mut bytes = Vec::new();
        bytes.push(TAG_ENTRY_KEY);
        bytes.extend_from_slice(&[0x11u8; 16]);
        let s = format!("{PREFIX_V1}{}", hex_encode(&bytes));

        match Cursor::parse(&s) {
            Ok(_) => panic!("expected InvalidQuery"),
            Err(err) => assert!(matches!(err, SdJournalError::InvalidQuery { .. })),
        }
    }

    #[test]
    fn cursor_rejects_unknown_sj1_variant() {
        let s = format!("{PREFIX_V1}{}", hex_encode(&[0xff]));

        match Cursor::parse(&s) {
            Err(SdJournalError::Unsupported { reason }) => {
                assert_eq!(reason, "unknown SJ1 cursor variant");
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn cursor_rejects_invalid_utf8_in_systemd_raw_variant() {
        let s = format!("{PREFIX_V1}{}", hex_encode(&[TAG_SYSTEMD_RAW, 0xff]));

        match Cursor::parse(&s) {
            Err(SdJournalError::InvalidQuery { reason }) => {
                assert_eq!(reason, "invalid UTF-8 in SJ1 systemd cursor");
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn cursor_rejects_trailing_bytes_in_systemd_fields_payload() {
        let mut bytes = Vec::new();
        bytes.push(TAG_SYSTEMD_FIELDS);
        bytes.push(SYSTEMD_MASK_REALTIME);
        bytes.extend_from_slice(&3u64.to_le_bytes());
        bytes.push(0xaa);
        let s = format!("{PREFIX_V1}{}", hex_encode(&bytes));

        match Cursor::parse(&s) {
            Err(SdJournalError::InvalidQuery { reason }) => {
                assert_eq!(reason, "trailing bytes in systemd cursor payload");
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn cursor_rejects_systemd_cursor_without_required_fields() {
        match Cursor::parse("x=1") {
            Err(SdJournalError::InvalidQuery { reason }) => {
                assert_eq!(reason, "systemd cursor missing required fields");
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn cursor_rejects_invalid_systemd_segment_syntax() {
        match Cursor::parse("broken-segment") {
            Err(SdJournalError::InvalidQuery { reason }) => {
                assert_eq!(reason, "invalid systemd cursor segment");
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }
}
