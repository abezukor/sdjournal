use super::fsprg::{FsprgParams, FsprgState};
use super::key::VerificationKey;
use super::{HmacSha256, TAG_LENGTH, VERIFY_READ_CHUNK_SIZE};
use crate::error::{LimitKind, Result, SdJournalError};
use crate::file::JournalFile;
use crate::format::{
    HEADER_SIZE_MIN, OBJECT_DATA, OBJECT_DATA_HASH_TABLE, OBJECT_ENTRY, OBJECT_ENTRY_ARRAY,
    OBJECT_FIELD, OBJECT_FIELD_HASH_TABLE, OBJECT_TAG, ObjectHeader,
};
use crate::util::{checked_add_u64, read_u64_le};
use hmac::{KeyInit as _, Mac as _};

pub(crate) fn verify_file_seal(
    file: &JournalFile,
    params: &FsprgParams,
    key: &VerificationKey,
) -> Result<()> {
    let header = file.header();
    if !header.is_sealed() {
        return Ok(());
    }

    let header_size = header.header_size;
    let tail_object_offset = header.tail_object_offset;
    let used_size = file.used_size();

    if header_size < HEADER_SIZE_MIN || header_size > used_size || !header_size.is_multiple_of(8) {
        return Err(SdJournalError::Corrupt {
            path: Some(file.path().to_path_buf()),
            offset: Some(88),
            reason: format!("invalid header_size: {header_size}"),
        });
    }

    if tail_object_offset == 0 {
        return Err(SdJournalError::Corrupt {
            path: Some(file.path().to_path_buf()),
            offset: Some(136),
            reason: "sealed journal contains no objects".to_string(),
        });
    }
    if tail_object_offset < header_size || tail_object_offset >= used_size {
        return Err(SdJournalError::Corrupt {
            path: Some(file.path().to_path_buf()),
            offset: Some(136),
            reason: format!(
                "invalid tail_object_offset: {tail_object_offset} (header_size={header_size}, used_size={used_size})"
            ),
        });
    }

    let mut fsprg = FsprgState::new(params);
    let mut n_tags: u64 = 0;
    let mut last_epoch: u64 = 0;
    let mut last_tag_end: u64 = 0;
    let mut last_tag_realtime: Option<u64> = None;
    let mut min_entry_realtime: Option<u64> = None;
    let mut max_entry_realtime: Option<u64> = None;

    let mut p = header_size;
    let mut found_tail = false;
    while p <= tail_object_offset {
        let oh = read_object_header(file, p)?;

        if oh.object_type == OBJECT_ENTRY {
            if n_tags == 0 {
                return Err(SdJournalError::Corrupt {
                    path: Some(file.path().to_path_buf()),
                    offset: Some(p),
                    reason: "sealed journal has ENTRY before first TAG".to_string(),
                });
            }

            let realtime = read_entry_realtime(file, p, &oh)?;
            if last_tag_realtime.is_some_and(|start| realtime < start) {
                return Err(SdJournalError::Corrupt {
                    path: Some(file.path().to_path_buf()),
                    offset: Some(p),
                    reason: format!(
                        "ENTRY realtime is older than the preceding TAG window ({realtime} < {})",
                        last_tag_realtime.unwrap_or_default()
                    ),
                });
            }
            min_entry_realtime =
                Some(min_entry_realtime.map_or(realtime, |current| current.min(realtime)));
            max_entry_realtime =
                Some(max_entry_realtime.map_or(realtime, |current| current.max(realtime)));
        }

        if oh.object_type == OBJECT_TAG {
            let tag = read_tag_object(file, p, &oh)?;

            let expected_seqnum = n_tags
                .checked_add(1)
                .ok_or_else(|| SdJournalError::Corrupt {
                    path: Some(file.path().to_path_buf()),
                    offset: Some(p),
                    reason: "TAG sequence number overflow".to_string(),
                })?;
            if tag.seqnum != expected_seqnum {
                return Err(SdJournalError::Corrupt {
                    path: Some(file.path().to_path_buf()),
                    offset: Some(p),
                    reason: format!(
                        "tag sequence number out of sync ({} != {})",
                        tag.seqnum, expected_seqnum
                    ),
                });
            }

            if header.is_sealed_continuous() {
                let next_epoch = last_epoch.checked_add(1);
                if !(n_tags == 0
                    || (n_tags == 1 && tag.epoch == last_epoch)
                    || next_epoch == Some(tag.epoch))
                {
                    return Err(SdJournalError::Corrupt {
                        path: Some(file.path().to_path_buf()),
                        offset: Some(p),
                        reason: format!(
                            "epoch sequence not continuous ({} vs {})",
                            tag.epoch, last_epoch
                        ),
                    });
                }
            } else if tag.epoch < last_epoch {
                return Err(SdJournalError::Corrupt {
                    path: Some(file.path().to_path_buf()),
                    offset: Some(p),
                    reason: format!(
                        "epoch sequence out of sync ({} < {})",
                        tag.epoch, last_epoch
                    ),
                });
            }

            let (tag_realtime, tag_realtime_end) = tag_realtime_window(file, key, p, tag.epoch)?;
            if let Some(max_realtime) = max_entry_realtime
                && max_realtime >= tag_realtime_end
            {
                return Err(SdJournalError::Corrupt {
                    path: Some(file.path().to_path_buf()),
                    offset: Some(p),
                    reason: format!(
                        "ENTRY realtime is too late for TAG epoch {} ({max_realtime} >= {tag_realtime_end})",
                        tag.epoch
                    ),
                });
            }
            if let Some(min_realtime) = min_entry_realtime
                && min_realtime < tag_realtime
            {
                return Err(SdJournalError::Corrupt {
                    path: Some(file.path().to_path_buf()),
                    offset: Some(p),
                    reason: format!(
                        "ENTRY realtime is too early for TAG epoch {} ({min_realtime} < {tag_realtime})",
                        tag.epoch
                    ),
                });
            }

            fsprg.seek(tag.epoch)?;
            let hmac_key = fsprg.get_key(TAG_LENGTH, 0);
            let mut mac =
                HmacSha256::new_from_slice(&hmac_key).map_err(|_| SdJournalError::Corrupt {
                    path: Some(file.path().to_path_buf()),
                    offset: Some(p),
                    reason: "failed to initialize HMAC".to_string(),
                })?;

            if last_tag_end == 0 {
                hmac_put_header(file, &mut mac)?;
            }

            let mut q = if last_tag_end == 0 {
                header_size
            } else {
                last_tag_end
            };
            while q <= p {
                let qh = read_object_header(file, q)?;
                hmac_put_object(file, &mut mac, q, &qh)?;
                let adv = align64(qh.size)?;
                q = checked_add_u64(q, adv, "verify-seal next object")?;
            }

            let digest = mac.finalize().into_bytes();
            if digest.as_slice() != tag.tag.as_slice() {
                return Err(SdJournalError::Corrupt {
                    path: Some(file.path().to_path_buf()),
                    offset: Some(p),
                    reason: "tag failed verification".to_string(),
                });
            }

            last_tag_end = checked_add_u64(p, align64(oh.size)?, "verify-seal tag end")?;
            last_tag_realtime = Some(tag_realtime);
            min_entry_realtime = None;
            max_entry_realtime = None;
            last_epoch = tag.epoch;
            n_tags = expected_seqnum;
        }

        if p == tail_object_offset {
            found_tail = true;
            break;
        }
        p = checked_add_u64(p, align64(oh.size)?, "verify-seal advance")?;
    }

    if !found_tail {
        return Err(SdJournalError::Corrupt {
            path: Some(file.path().to_path_buf()),
            offset: Some(tail_object_offset),
            reason: "tail_object_offset does not point to an object boundary".to_string(),
        });
    }

    if n_tags == 0 {
        return Err(SdJournalError::Corrupt {
            path: Some(file.path().to_path_buf()),
            offset: Some(136),
            reason: "sealed journal contains no TAG objects".to_string(),
        });
    }

    Ok(())
}

fn read_object_header(file: &JournalFile, offset: u64) -> Result<ObjectHeader> {
    file.validate_object_offset(offset)?;
    if !offset.is_multiple_of(8) {
        return Err(SdJournalError::Corrupt {
            path: Some(file.path().to_path_buf()),
            offset: Some(offset),
            reason: format!("object offset is not 8-byte aligned: {offset}"),
        });
    }

    let buf = file.read_bytes(offset, 16)?;
    let oh = ObjectHeader::parse(buf.as_slice(), file.path(), offset)?;

    if oh.size < 16 {
        return Err(SdJournalError::Corrupt {
            path: Some(file.path().to_path_buf()),
            offset: Some(offset),
            reason: format!("object size too small: {}", oh.size),
        });
    }
    if oh.size > file.config().max_object_size_bytes {
        return Err(SdJournalError::LimitExceeded {
            kind: LimitKind::ObjectSizeBytes,
            limit: file.config().max_object_size_bytes,
        });
    }
    let raw_end = checked_add_u64(offset, oh.size, "verify-seal object end")?;
    let padded_end = checked_add_u64(offset, align64(oh.size)?, "verify-seal padded object end")?;
    if raw_end > file.used_size() || padded_end > file.used_size() {
        return Err(SdJournalError::Corrupt {
            path: Some(file.path().to_path_buf()),
            offset: Some(offset),
            reason: format!(
                "object extends beyond used journal data (raw_end={raw_end}, padded_end={padded_end}, used_size={})",
                file.used_size()
            ),
        });
    }

    Ok(oh)
}

fn read_entry_realtime(file: &JournalFile, offset: u64, oh: &ObjectHeader) -> Result<u64> {
    const ENTRY_HEADER_SIZE: u64 = 64;
    if oh.size < ENTRY_HEADER_SIZE {
        return Err(SdJournalError::Corrupt {
            path: Some(file.path().to_path_buf()),
            offset: Some(offset),
            reason: format!("ENTRY object too small: {}", oh.size),
        });
    }

    let buf = file.read_bytes(offset, usize::try_from(ENTRY_HEADER_SIZE).unwrap_or(64))?;
    read_u64_le(buf.as_slice(), 24).ok_or_else(|| SdJournalError::Corrupt {
        path: Some(file.path().to_path_buf()),
        offset: Some(offset.saturating_add(24)),
        reason: "ENTRY realtime truncated".to_string(),
    })
}

fn tag_realtime_window(
    file: &JournalFile,
    key: &VerificationKey,
    tag_offset: u64,
    epoch: u64,
) -> Result<(u64, u64)> {
    let epoch_offset =
        epoch
            .checked_mul(key.interval_usec())
            .ok_or_else(|| SdJournalError::Corrupt {
                path: Some(file.path().to_path_buf()),
                offset: Some(tag_offset),
                reason: format!("TAG epoch {epoch} overflows the verification-key time range"),
            })?;
    let start =
        key.start_usec()
            .checked_add(epoch_offset)
            .ok_or_else(|| SdJournalError::Corrupt {
                path: Some(file.path().to_path_buf()),
                offset: Some(tag_offset),
                reason: format!("TAG epoch {epoch} overflows the verification-key start time"),
            })?;
    let end = start
        .checked_add(key.interval_usec())
        .ok_or_else(|| SdJournalError::Corrupt {
            path: Some(file.path().to_path_buf()),
            offset: Some(tag_offset),
            reason: format!("TAG epoch {epoch} overflows the verification-key end time"),
        })?;
    Ok((start, end))
}

fn hmac_put_header(file: &JournalFile, mac: &mut HmacSha256) -> Result<()> {
    let header_bytes = file.read_bytes(0, 136)?;
    let b = header_bytes.as_slice();

    mac.update(b.get(0..16).ok_or_else(|| SdJournalError::Corrupt {
        path: Some(file.path().to_path_buf()),
        offset: Some(0),
        reason: "header too short for sealing verification".to_string(),
    })?);
    mac.update(b.get(24..56).ok_or_else(|| SdJournalError::Corrupt {
        path: Some(file.path().to_path_buf()),
        offset: Some(24),
        reason: "header too short for sealing verification".to_string(),
    })?);
    mac.update(b.get(72..96).ok_or_else(|| SdJournalError::Corrupt {
        path: Some(file.path().to_path_buf()),
        offset: Some(72),
        reason: "header too short for sealing verification".to_string(),
    })?);
    mac.update(b.get(104..136).ok_or_else(|| SdJournalError::Corrupt {
        path: Some(file.path().to_path_buf()),
        offset: Some(104),
        reason: "header too short for sealing verification".to_string(),
    })?);

    Ok(())
}

fn hmac_put_object(
    file: &JournalFile,
    mac: &mut HmacSha256,
    offset: u64,
    oh: &ObjectHeader,
) -> Result<()> {
    hmac_update_range(file, mac, offset, 16)?;

    match oh.object_type {
        OBJECT_DATA => {
            hmac_update_range(file, mac, checked_add_u64(offset, 16, "data.hash")?, 8)?;

            let payload_offset = if file.header().is_compact() {
                72u64
            } else {
                64u64
            };
            if oh.size < payload_offset {
                return Err(SdJournalError::Corrupt {
                    path: Some(file.path().to_path_buf()),
                    offset: Some(offset),
                    reason: format!("DATA object too small: {}", oh.size),
                });
            }

            let payload_len = oh.size - payload_offset;
            hmac_update_range(
                file,
                mac,
                checked_add_u64(offset, payload_offset, "data.payload")?,
                payload_len,
            )?;
        }
        OBJECT_FIELD => {
            const PAYLOAD_OFFSET: u64 = 40;
            hmac_update_range(file, mac, checked_add_u64(offset, 16, "field.hash")?, 8)?;
            if oh.size < PAYLOAD_OFFSET {
                return Err(SdJournalError::Corrupt {
                    path: Some(file.path().to_path_buf()),
                    offset: Some(offset),
                    reason: format!("FIELD object too small: {}", oh.size),
                });
            }
            hmac_update_range(
                file,
                mac,
                checked_add_u64(offset, PAYLOAD_OFFSET, "field.payload")?,
                oh.size - PAYLOAD_OFFSET,
            )?;
        }
        OBJECT_ENTRY => {
            let payload_len = oh
                .size
                .checked_sub(16)
                .ok_or_else(|| SdJournalError::Corrupt {
                    path: Some(file.path().to_path_buf()),
                    offset: Some(offset),
                    reason: "ENTRY object too small".to_string(),
                })?;
            hmac_update_range(
                file,
                mac,
                checked_add_u64(offset, 16, "entry.payload")?,
                payload_len,
            )?;
        }
        OBJECT_DATA_HASH_TABLE | OBJECT_FIELD_HASH_TABLE | OBJECT_ENTRY_ARRAY => {}
        OBJECT_TAG => {
            if oh.size != 64 {
                return Err(SdJournalError::Corrupt {
                    path: Some(file.path().to_path_buf()),
                    offset: Some(offset),
                    reason: format!("TAG object has invalid size: {}", oh.size),
                });
            }
            hmac_update_range(file, mac, checked_add_u64(offset, 16, "tag.seqnum")?, 16)?;
        }
        other => {
            return Err(SdJournalError::Unsupported {
                reason: format!("unsupported object type in sealing verification: {other}"),
            });
        }
    }

    Ok(())
}

fn hmac_update_range(
    file: &JournalFile,
    mac: &mut HmacSha256,
    offset: u64,
    len: u64,
) -> Result<()> {
    let mut off = offset;
    let mut remaining = len;
    while remaining > 0 {
        let take_u64 = std::cmp::min(remaining, VERIFY_READ_CHUNK_SIZE as u64);
        let take = usize::try_from(take_u64).unwrap_or(VERIFY_READ_CHUNK_SIZE);
        let buf = file.read_bytes(off, take)?;
        mac.update(buf.as_slice());
        off = checked_add_u64(off, take_u64, "verify-seal range")?;
        remaining -= take_u64;
    }
    Ok(())
}

#[derive(Debug)]
struct TagObject {
    seqnum: u64,
    epoch: u64,
    tag: [u8; TAG_LENGTH],
}

fn read_tag_object(file: &JournalFile, offset: u64, oh: &ObjectHeader) -> Result<TagObject> {
    if oh.size != 64 {
        return Err(SdJournalError::Corrupt {
            path: Some(file.path().to_path_buf()),
            offset: Some(offset),
            reason: format!("TAG object has invalid size: {}", oh.size),
        });
    }

    let buf = file.read_bytes(offset, 64)?;
    let b = buf.as_slice();
    let seqnum = read_u64_le(b, 16).ok_or_else(|| SdJournalError::Corrupt {
        path: Some(file.path().to_path_buf()),
        offset: Some(offset + 16),
        reason: "TAG.seqnum truncated".to_string(),
    })?;
    let epoch = read_u64_le(b, 24).ok_or_else(|| SdJournalError::Corrupt {
        path: Some(file.path().to_path_buf()),
        offset: Some(offset + 24),
        reason: "TAG.epoch truncated".to_string(),
    })?;
    let tag_bytes = b.get(32..64).ok_or_else(|| SdJournalError::Corrupt {
        path: Some(file.path().to_path_buf()),
        offset: Some(offset + 32),
        reason: "TAG.tag truncated".to_string(),
    })?;
    let mut tag = [0u8; TAG_LENGTH];
    tag.copy_from_slice(tag_bytes);

    Ok(TagObject { seqnum, epoch, tag })
}

fn align64(size: u64) -> Result<u64> {
    let added = checked_add_u64(size, 7, "align64")?;
    Ok(added & !7u64)
}

#[cfg(test)]
mod tests {
    use super::{read_object_header, tag_realtime_window};
    use crate::config::JournalConfig;
    use crate::file::JournalFile;
    use crate::format::{HEADER_SIGNATURE, HEADER_SIZE_MIN, OBJECT_FIELD, STATE_ARCHIVED};
    use crate::seal::parse_verification_key;
    use std::fs;

    fn journal_with_unaligned_field() -> (tempfile::TempDir, JournalFile) {
        const HEADER_SIZE: usize = HEADER_SIZE_MIN as usize;
        const FIELD_SIZE: usize = 41;
        const USED_SIZE: usize = 256;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unaligned-field.journal");
        let mut bytes = vec![0u8; USED_SIZE];
        bytes[..8].copy_from_slice(HEADER_SIGNATURE);
        bytes[16] = STATE_ARCHIVED;
        bytes[88..96].copy_from_slice(&(HEADER_SIZE as u64).to_le_bytes());
        bytes[96..104].copy_from_slice(&((USED_SIZE - HEADER_SIZE) as u64).to_le_bytes());
        bytes[136..144].copy_from_slice(&(HEADER_SIZE as u64).to_le_bytes());
        bytes[HEADER_SIZE] = OBJECT_FIELD;
        bytes[HEADER_SIZE + 8..HEADER_SIZE + 16]
            .copy_from_slice(&(FIELD_SIZE as u64).to_le_bytes());
        fs::write(&path, bytes).unwrap();

        let config = JournalConfig::default();
        #[cfg(feature = "mmap")]
        let config = {
            let mut config = config;
            config.mmap_policy = crate::config::MmapPolicy::Never;
            config
        };
        let file = JournalFile::open(path, &config).unwrap();
        (dir, file)
    }

    #[test]
    fn object_header_accepts_unaligned_raw_size_with_aligned_padding() {
        let (_dir, file) = journal_with_unaligned_field();
        let header = read_object_header(&file, HEADER_SIZE_MIN).unwrap();
        assert_eq!(header.size, 41);
    }

    #[test]
    fn tag_realtime_window_uses_key_start_interval_and_epoch() {
        let (_dir, file) = journal_with_unaligned_field();
        let key = parse_verification_key("01-23-45-67-89-ab-cd-ef-01-23-45-67/1-10").unwrap();

        assert_eq!(
            tag_realtime_window(&file, &key, HEADER_SIZE_MIN, 2).unwrap(),
            (48, 64)
        );
        assert!(tag_realtime_window(&file, &key, HEADER_SIZE_MIN, u64::MAX).is_err());
    }
}
