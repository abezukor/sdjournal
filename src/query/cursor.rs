use super::JournalQuery;
use crate::cursor::{
    LegacyEntryKey, SdJournalEntryKey, SystemdCursor, compare_entry_keys, same_entry,
};
use crate::error::{Result, SdJournalError};
use crate::file::EntryMeta;
use std::cmp::Ordering;

#[derive(Debug, Clone)]
pub(super) struct CursorStart {
    boundary: CursorBoundary,
    inclusive: bool,
    exact_meta: Option<EntryMeta>,
}

#[derive(Debug, Clone)]
enum CursorBoundary {
    Full(SdJournalEntryKey),
    Legacy(LegacyEntryKey),
    Systemd(SystemdCursor),
}

impl CursorStart {
    pub(super) fn exact_meta(&self) -> Option<EntryMeta> {
        self.exact_meta
    }

    pub(super) fn matches_exact(&self, meta: &EntryMeta) -> bool {
        match &self.boundary {
            CursorBoundary::Full(key) => same_entry(&entry_key_from_meta(meta), key),
            CursorBoundary::Legacy(_) | CursorBoundary::Systemd(_) => false,
        }
    }

    pub(super) fn inclusive(&self) -> bool {
        self.inclusive
    }

    pub(super) fn accepts(&self, meta: &EntryMeta) -> bool {
        let ordering = match &self.boundary {
            CursorBoundary::Full(key) => compare_entry_keys(&entry_key_from_meta(meta), key),
            CursorBoundary::Legacy(key) => compare_legacy(meta, key),
            CursorBoundary::Systemd(cursor) => compare_systemd(meta, cursor),
        };

        if self.inclusive {
            ordering != Ordering::Less
        } else {
            ordering == Ordering::Greater
        }
    }
}

pub(super) fn entry_key_from_meta(meta: &EntryMeta) -> SdJournalEntryKey {
    SdJournalEntryKey {
        file_id: meta.file_id,
        entry_offset: meta.entry_offset,
        seqnum_id: meta.seqnum_id,
        seqnum: meta.seqnum,
        boot_id: meta.boot_id,
        monotonic_usec: meta.monotonic_usec,
        realtime_usec: meta.realtime_usec,
        xor_hash: meta.xor_hash,
    }
}

pub(super) fn build_cursor_start(query: &JournalQuery) -> Result<Option<CursorStart>> {
    let (cursor, inclusive) = match &query.cursor_start {
        Some(value) => value,
        None => return Ok(None),
    };

    if let Some(key) = cursor.sdjournal_entry_key() {
        let Some(exact_meta) = resolve_full_key(query, &key)? else {
            return Err(SdJournalError::NotFound);
        };
        return Ok(Some(CursorStart {
            boundary: CursorBoundary::Full(key),
            inclusive: *inclusive,
            exact_meta: Some(exact_meta),
        }));
    }

    if let Some(key) = cursor.legacy_entry_key() {
        let (boundary, exact_meta) = match resolve_file_offset(query, key.file_id, key.entry_offset)
        {
            Ok(meta) if meta.seqnum == key.seqnum && meta.realtime_usec == key.realtime_usec => {
                let full = entry_key_from_meta(&meta);
                (CursorBoundary::Full(full), Some(meta))
            }
            Ok(_) => return Err(SdJournalError::NotFound),
            // Legacy SJ1 cursors were intentionally self-contained. Keep their historical
            // ordering available when the original rotated file is no longer present.
            Err(SdJournalError::NotFound) => (CursorBoundary::Legacy(key), None),
            Err(error) => return Err(error),
        };
        return Ok(Some(CursorStart {
            boundary,
            inclusive: *inclusive,
            exact_meta,
        }));
    }

    if let Some((file_id, entry_offset)) = cursor.file_offset() {
        let meta = resolve_file_offset(query, file_id, entry_offset)?;
        let full = entry_key_from_meta(&meta);
        return Ok(Some(CursorStart {
            boundary: CursorBoundary::Full(full),
            inclusive: *inclusive,
            exact_meta: Some(meta),
        }));
    }

    if let Some(systemd) = cursor.systemd() {
        if !systemd_cursor_is_unique(systemd) {
            return Ok(Some(CursorStart {
                boundary: CursorBoundary::Systemd(systemd.clone()),
                inclusive: *inclusive,
                exact_meta: None,
            }));
        }
        let (boundary, exact_meta) = match find_exact_systemd_cursor(query, systemd) {
            Ok(Some(meta)) => {
                let full = entry_key_from_meta(&meta);
                (CursorBoundary::Full(full), Some(meta))
            }
            Ok(None) => return Err(SdJournalError::NotFound),
            Err(error) => return Err(error),
        };
        return Ok(Some(CursorStart {
            boundary,
            inclusive: *inclusive,
            exact_meta,
        }));
    }

    Err(SdJournalError::InvalidQuery {
        reason: "unsupported cursor format".to_string(),
    })
}

fn systemd_cursor_is_unique(cursor: &SystemdCursor) -> bool {
    cursor.seqnum_id.is_some() && cursor.seqnum.is_some()
}

fn resolve_full_key(query: &JournalQuery, key: &SdJournalEntryKey) -> Result<Option<EntryMeta>> {
    for index in 0..query.journal.inner.file_count() {
        let Some(info) = query.journal.inner.file_info(index) else {
            continue;
        };
        if info.file_id != key.file_id {
            continue;
        }

        let file = query.journal.inner.open_file_by_index(index)?;
        let meta = file.read_entry_meta(key.entry_offset)?;
        return Ok(same_entry(&entry_key_from_meta(&meta), key).then_some(meta));
    }

    Ok(None)
}

fn resolve_file_offset(
    query: &JournalQuery,
    file_id: [u8; 16],
    entry_offset: u64,
) -> Result<EntryMeta> {
    for index in 0..query.journal.inner.file_count() {
        let Some(info) = query.journal.inner.file_info(index) else {
            continue;
        };
        if info.file_id != file_id {
            continue;
        }

        let file = query.journal.inner.open_file_by_index(index)?;
        return file.read_entry_meta(entry_offset);
    }

    Err(SdJournalError::NotFound)
}

fn compare_legacy(meta: &EntryMeta, key: &LegacyEntryKey) -> Ordering {
    meta.realtime_usec
        .cmp(&key.realtime_usec)
        .then_with(|| meta.seqnum.cmp(&key.seqnum))
        .then_with(|| meta.file_id.cmp(&key.file_id))
        .then_with(|| meta.entry_offset.cmp(&key.entry_offset))
}

fn compare_systemd(meta: &EntryMeta, cursor: &SystemdCursor) -> Ordering {
    if let (Some(seqnum_id), Some(seqnum)) = (cursor.seqnum_id, cursor.seqnum)
        && meta.seqnum_id == seqnum_id
    {
        let ordering = meta.seqnum.cmp(&seqnum);
        if ordering != Ordering::Equal {
            return ordering;
        }
    }

    if let (Some(boot_id), Some(monotonic_usec)) = (cursor.boot_id, cursor.monotonic_usec)
        && meta.boot_id == boot_id
    {
        let ordering = meta.monotonic_usec.cmp(&monotonic_usec);
        if ordering != Ordering::Equal {
            return ordering;
        }
    }

    if let Some(realtime_usec) = cursor.realtime_usec {
        let ordering = meta.realtime_usec.cmp(&realtime_usec);
        if ordering != Ordering::Equal {
            return ordering;
        }
    }

    cursor
        .xor_hash
        .map_or(Ordering::Equal, |xor_hash| meta.xor_hash.cmp(&xor_hash))
}

fn find_exact_systemd_cursor(
    query: &JournalQuery,
    systemd: &SystemdCursor,
) -> Result<Option<EntryMeta>> {
    let mut first_error = None;

    for index in 0..query.journal.inner.file_count() {
        let Some(info) = query.journal.inner.file_info(index) else {
            continue;
        };
        if let Some(seqnum_id) = systemd.seqnum_id
            && info.seqnum_id != seqnum_id
        {
            continue;
        }

        let file = match query.journal.inner.open_file_by_index(index) {
            Ok(file) => file,
            Err(error) => {
                first_error.get_or_insert(error);
                continue;
            }
        };

        let iter = match file.entry_iter_seek_realtime(false, None, None) {
            Ok(iter) => iter,
            Err(error) => {
                first_error.get_or_insert(error);
                continue;
            }
        };

        for item in iter {
            let meta = match item {
                Ok(meta) => meta,
                Err(error) => {
                    first_error.get_or_insert(error);
                    break;
                }
            };
            if systemd_cursor_matches(&meta, systemd) {
                return Ok(Some(meta));
            }
        }
    }

    match first_error {
        Some(error) => Err(error),
        None => Ok(None),
    }
}

fn systemd_cursor_matches(meta: &EntryMeta, cursor: &SystemdCursor) -> bool {
    cursor.seqnum_id.is_none_or(|value| meta.seqnum_id == value)
        && cursor.seqnum.is_none_or(|value| meta.seqnum == value)
        && cursor.boot_id.is_none_or(|value| meta.boot_id == value)
        && cursor
            .monotonic_usec
            .is_none_or(|value| meta.monotonic_usec == value)
        && cursor
            .realtime_usec
            .is_none_or(|value| meta.realtime_usec == value)
        && cursor.xor_hash.is_none_or(|value| meta.xor_hash == value)
}
