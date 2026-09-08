use crate::config::JournalConfig;
use crate::cursor::SdJournalEntryKey;
use crate::error::{LimitKind, Result, SdJournalError};
use crate::file::{JournalFile, LiveFileState};
use crate::journal::{Journal, journal_from_snapshot_files};
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use super::{compare_keys, is_skippable_live_file_error, warn_skipped_live_file};

#[derive(Clone)]
pub(super) struct TrackedFile {
    pub(super) path: PathBuf,
    pub(super) file_id: [u8; 16],
    pub(super) seqnum_id: [u8; 16],
    pub(super) live_state: LiveFileState,
    pub(super) tail: FileTailCursor,
    pub(super) last_key: Option<SdJournalEntryKey>,
    pub(super) modified: Option<SystemTime>,
}

pub(super) struct TrackedFiles {
    pub(super) files: Vec<TrackedFile>,
    pub(super) path_index: HashMap<PathBuf, usize>,
    pub(super) last_seen: Option<SdJournalEntryKey>,
}

pub(super) struct LiveSnapshot {
    pub(super) tracked: TrackedFiles,
    pub(super) journal: Journal,
}

pub(super) struct OffsetBatch {
    pub(super) offsets: Vec<u64>,
    pub(super) exhausted: bool,
}

pub(super) struct FallbackDirState {
    pub(super) path: PathBuf,
    pub(super) modified: Option<SystemTime>,
}

pub(super) fn file_metadata_changed(
    known_file_len: u64,
    known_modified: Option<SystemTime>,
    metadata: &std::fs::Metadata,
) -> bool {
    let modified = metadata.modified().ok();
    metadata.len() != known_file_len || modified.is_none() || modified != known_modified
}

#[derive(Clone)]
pub(super) struct FileTailCursor {
    current_array_offset: Option<u64>,
    next_item_idx: usize,
    last_entry_offset: Option<u64>,
    consumed_entries: u64,
}

impl FileTailCursor {
    pub(super) fn at_start() -> Self {
        Self {
            current_array_offset: None,
            next_item_idx: 0,
            last_entry_offset: None,
            consumed_entries: 0,
        }
    }

    pub(super) fn last_entry_offset(&self) -> Option<u64> {
        self.last_entry_offset
    }

    fn at_end(file: &JournalFile) -> Result<Self> {
        let mut next = file.live_state().entry_array_offset;
        let mut current_array_offset = None;
        let mut next_item_idx = 0usize;
        let mut last_entry_offset = None;
        let mut remaining = file.live_state().n_entries;
        let mut steps = 0usize;

        while next != 0 && remaining != 0 {
            current_array_offset = Some(next);
            let items = file.read_entry_array_items(next)?;
            let used = usize::try_from(remaining)
                .unwrap_or(usize::MAX)
                .min(items.len());
            next_item_idx = used;
            for &entry_offset in &items[..used] {
                validate_tail_entry_offset(file, entry_offset, last_entry_offset)?;
                last_entry_offset = Some(entry_offset);
            }
            remaining = remaining.saturating_sub(u64::try_from(used).unwrap_or(u64::MAX));
            if remaining == 0 {
                break;
            }
            next = file.read_entry_array_next_offset(next)?;

            steps = steps.saturating_add(1);
            if steps > file.max_object_chain_steps() {
                return Err(SdJournalError::LimitExceeded {
                    kind: LimitKind::ObjectChainSteps,
                    limit: u64::try_from(file.max_object_chain_steps()).unwrap_or(u64::MAX),
                });
            }
        }

        if remaining != 0 {
            return Err(SdJournalError::Transient {
                path: Some(file.path().to_path_buf()),
                reason: format!(
                    "ENTRY_ARRAY exposes fewer committed entries than header n_entries ({remaining} missing)"
                ),
            });
        }

        Ok(Self {
            current_array_offset,
            next_item_idx,
            last_entry_offset,
            consumed_entries: file.live_state().n_entries,
        })
    }

    pub(super) fn drain_new_offsets(
        &mut self,
        file: &JournalFile,
        limit: usize,
    ) -> Result<OffsetBatch> {
        let mut out = Vec::new();
        let mut steps = 0usize;
        let target_entries = file.live_state().n_entries;
        if self.consumed_entries > target_entries {
            return Err(SdJournalError::Transient {
                path: Some(file.path().to_path_buf()),
                reason: "journal n_entries moved backwards while tailing".to_string(),
            });
        }
        let mut remaining = target_entries.saturating_sub(self.consumed_entries);
        if remaining == 0 {
            return Ok(OffsetBatch {
                offsets: out,
                exhausted: true,
            });
        }

        let mut current = match self.current_array_offset {
            Some(offset) => {
                let items = file.read_entry_array_items(offset)?;
                let mut item_idx = self.next_item_idx.min(items.len());
                while item_idx < items.len() && remaining != 0 {
                    let entry_offset = items[item_idx];
                    item_idx = item_idx.saturating_add(1);
                    validate_tail_entry_offset(file, entry_offset, self.last_entry_offset)?;
                    out.push(entry_offset);
                    self.last_entry_offset = Some(entry_offset);
                    self.consumed_entries = self.consumed_entries.saturating_add(1);
                    remaining = remaining.saturating_sub(1);
                    if out.len() >= limit {
                        self.next_item_idx = item_idx;
                        return Ok(OffsetBatch {
                            offsets: out,
                            exhausted: false,
                        });
                    }
                }
                self.next_item_idx = item_idx;
                if remaining == 0 {
                    0
                } else {
                    file.read_entry_array_next_offset(offset)?
                }
            }
            None => file.live_state().entry_array_offset,
        };

        while current != 0 && remaining != 0 {
            let items = file.read_entry_array_items(current)?;
            let mut item_idx = 0usize;
            while item_idx < items.len() && remaining != 0 {
                let entry_offset = items[item_idx];
                item_idx = item_idx.saturating_add(1);
                validate_tail_entry_offset(file, entry_offset, self.last_entry_offset)?;
                out.push(entry_offset);
                self.last_entry_offset = Some(entry_offset);
                self.consumed_entries = self.consumed_entries.saturating_add(1);
                remaining = remaining.saturating_sub(1);
                if out.len() >= limit {
                    self.current_array_offset = Some(current);
                    self.next_item_idx = item_idx;
                    return Ok(OffsetBatch {
                        offsets: out,
                        exhausted: false,
                    });
                }
            }
            self.current_array_offset = Some(current);
            self.next_item_idx = item_idx;
            current = if remaining == 0 {
                0
            } else {
                file.read_entry_array_next_offset(current)?
            };

            steps = steps.saturating_add(1);
            if steps > file.max_object_chain_steps() {
                return Err(SdJournalError::Transient {
                    path: Some(file.path().to_path_buf()),
                    reason: "entry array chain refresh exceeded expected growth".to_string(),
                });
            }
        }

        if remaining != 0 {
            return Err(SdJournalError::Transient {
                path: Some(file.path().to_path_buf()),
                reason: format!(
                    "ENTRY_ARRAY exposes fewer committed entries than header n_entries ({remaining} missing)"
                ),
            });
        }

        if self.current_array_offset.is_none() && target_entries == 0 {
            self.next_item_idx = 0;
            self.last_entry_offset = None;
            return Ok(OffsetBatch {
                offsets: Vec::new(),
                exhausted: true,
            });
        }

        Ok(OffsetBatch {
            offsets: out,
            exhausted: true,
        })
    }
}

fn validate_tail_entry_offset(
    file: &JournalFile,
    offset: u64,
    previous: Option<u64>,
) -> Result<()> {
    if offset == 0 || previous.is_some_and(|previous| offset <= previous) {
        return Err(SdJournalError::Transient {
            path: Some(file.path().to_path_buf()),
            reason: format!(
                "committed ENTRY_ARRAY offsets must be nonzero and strictly increasing ({previous:?} -> {offset})"
            ),
        });
    }
    Ok(())
}

struct TrackedFileBuilder {
    tracked_files: Vec<TrackedFile>,
    path_index: HashMap<PathBuf, usize>,
    last_seen: Option<SdJournalEntryKey>,
    first_skipped_error: Option<SdJournalError>,
    seen: HashSet<[u8; 16]>,
}

impl TrackedFileBuilder {
    fn new(capacity: usize) -> Self {
        Self {
            tracked_files: Vec::with_capacity(capacity),
            path_index: HashMap::with_capacity(capacity),
            last_seen: None,
            first_skipped_error: None,
            seen: HashSet::new(),
        }
    }

    fn push(&mut self, file: &JournalFile) -> Result<bool> {
        let file_id = file.file_id();
        if self.seen.contains(&file_id) {
            return Ok(false);
        }

        match track_file(file) {
            Ok((tracked, key)) => {
                self.seen.insert(file_id);
                if key.as_ref().is_some_and(|key| {
                    self.last_seen
                        .as_ref()
                        .is_none_or(|last| compare_keys(key, last).is_gt())
                }) {
                    self.last_seen = key;
                }
                self.path_index
                    .insert(tracked.path.clone(), self.tracked_files.len());
                self.tracked_files.push(tracked);
                Ok(true)
            }
            Err(err) if is_skippable_live_file_error(&err) => {
                warn_skipped_live_file(file.path(), &err);
                if self.first_skipped_error.is_none() {
                    self.first_skipped_error = Some(err);
                }
                Ok(false)
            }
            Err(err) => Err(err),
        }
    }

    fn skip_path(&mut self, path: &Path, err: SdJournalError) {
        warn_skipped_live_file(path, &err);
        if self.first_skipped_error.is_none() {
            self.first_skipped_error = Some(err);
        }
    }

    fn finish(self) -> Result<TrackedFiles> {
        finish_tracked_files(
            self.tracked_files,
            self.path_index,
            self.last_seen,
            self.first_skipped_error,
        )
    }
}

#[cfg(target_os = "linux")]
pub(super) fn collect_watch_paths(
    roots: &[PathBuf],
    tracked_files: &[TrackedFile],
) -> Vec<PathBuf> {
    let mut watch_paths = collect_live_dirs(roots, tracked_files);
    for tracked in tracked_files {
        watch_paths.push(tracked.path.clone());
    }
    watch_paths.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));
    watch_paths.dedup();
    watch_paths
}

pub(super) fn collect_fallback_dirs(
    roots: &[PathBuf],
    tracked_files: &[TrackedFile],
) -> Vec<FallbackDirState> {
    collect_live_dirs(roots, tracked_files)
        .into_iter()
        .map(|path| FallbackDirState {
            modified: std::fs::metadata(&path)
                .and_then(|meta| meta.modified())
                .ok(),
            path,
        })
        .collect()
}

fn collect_live_dirs(roots: &[PathBuf], tracked_files: &[TrackedFile]) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = roots.to_vec();
    for root in roots {
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir()
                && !file_type.is_symlink()
                && is_machine_id_dir(&entry.file_name())
            {
                dirs.push(entry.path());
            }
        }
    }
    for tracked in tracked_files {
        if let Some(parent) = tracked.path.parent() {
            dirs.push(parent.to_path_buf());
        }
    }
    dirs.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));
    dirs.dedup();
    dirs
}

fn is_machine_id_dir(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    name.len() == 32 && name.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(super) fn build_tracked_files_from_open_files(files: &[JournalFile]) -> Result<TrackedFiles> {
    let mut builder = TrackedFileBuilder::new(files.len());

    for file in files {
        builder.push(file)?;
    }

    builder.finish()
}

pub(super) fn build_tracked_files_from_paths(
    paths: &[PathBuf],
    config: &JournalConfig,
) -> Result<TrackedFiles> {
    let mut builder = TrackedFileBuilder::new(paths.len());

    for path in paths {
        let file = match JournalFile::open(path.clone(), config) {
            Ok(file) => file,
            Err(err) if is_skippable_live_file_error(&err) => {
                builder.skip_path(path, err);
                continue;
            }
            Err(err) => return Err(err),
        };
        builder.push(&file)?;
    }

    builder.finish()
}

pub(super) fn build_live_snapshot(
    paths: &[PathBuf],
    config: &JournalConfig,
) -> Result<LiveSnapshot> {
    let mut opened = Vec::with_capacity(paths.len());
    let mut first_skipped_error = None;
    for path in paths {
        match JournalFile::open(path.clone(), config) {
            Ok(file) => opened.push(file),
            Err(error) if is_skippable_live_file_error(&error) => {
                warn_skipped_live_file(path, &error);
                first_skipped_error.get_or_insert(error);
            }
            Err(error) => return Err(error),
        }
    }
    if opened.is_empty() {
        return Err(first_skipped_error.unwrap_or(SdJournalError::NotFound));
    }

    let tracked = build_tracked_files_from_open_files(&opened)?;
    let tracked_ids: HashSet<[u8; 16]> = tracked
        .files
        .iter()
        .map(|tracked| tracked.file_id)
        .collect();
    opened.retain(|file| tracked_ids.contains(&file.file_id()));
    let journal = journal_from_snapshot_files(Vec::new(), &opened, config.clone())?;

    debug_assert_eq!(
        tracked
            .files
            .iter()
            .map(|tracked| tracked.file_id)
            .collect::<HashSet<_>>(),
        opened
            .iter()
            .map(JournalFile::file_id)
            .collect::<HashSet<_>>()
    );

    Ok(LiveSnapshot { tracked, journal })
}

fn track_file(file: &JournalFile) -> Result<(TrackedFile, Option<SdJournalEntryKey>)> {
    let tail = FileTailCursor::at_end(file)?;
    let key = match tail.last_entry_offset {
        Some(offset) => {
            let meta = file.read_entry_meta(offset)?;
            Some(SdJournalEntryKey {
                file_id: meta.file_id,
                entry_offset: meta.entry_offset,
                seqnum_id: meta.seqnum_id,
                seqnum: meta.seqnum,
                boot_id: meta.boot_id,
                monotonic_usec: meta.monotonic_usec,
                realtime_usec: meta.realtime_usec,
                xor_hash: meta.xor_hash,
            })
        }
        None => None,
    };

    Ok((
        TrackedFile {
            path: file.path().to_path_buf(),
            file_id: file.file_id(),
            seqnum_id: file.seqnum_id(),
            live_state: file.live_state(),
            tail,
            last_key: key,
            modified: file.modified_at_open(),
        },
        key,
    ))
}

fn finish_tracked_files(
    tracked_files: Vec<TrackedFile>,
    path_index: HashMap<PathBuf, usize>,
    last_seen: Option<SdJournalEntryKey>,
    first_skipped_error: Option<SdJournalError>,
) -> Result<TrackedFiles> {
    if tracked_files.is_empty()
        && let Some(err) = first_skipped_error
    {
        return Err(err);
    }

    Ok(TrackedFiles {
        files: tracked_files,
        path_index,
        last_seen,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn live_dirs_include_empty_machine_id_directories() {
        let root = tempfile::tempdir().expect("create live root");
        let machine_dir = root.path().join("0123456789abcdef0123456789abcdef");
        fs::create_dir(&machine_dir).expect("create machine-id directory");

        let dirs = collect_live_dirs(&[root.path().to_path_buf()], &[]);
        assert!(dirs.contains(&root.path().to_path_buf()));
        assert!(dirs.contains(&machine_dir));
    }

    #[test]
    fn fallback_metadata_detects_same_length_timestamp_change() {
        let root = tempfile::tempdir().expect("create metadata root");
        let path = root.path().join("active.journal");
        fs::write(&path, [0u8; 16]).expect("write test file");
        let metadata = fs::metadata(&path).expect("read metadata");

        assert!(!file_metadata_changed(
            metadata.len(),
            metadata.modified().ok(),
            &metadata
        ));
        assert!(file_metadata_changed(
            metadata.len(),
            Some(SystemTime::UNIX_EPOCH),
            &metadata
        ));
    }
}
