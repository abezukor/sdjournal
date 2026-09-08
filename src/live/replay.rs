use crate::config::JournalConfig;
use crate::cursor::{Cursor, SdJournalEntryKey};
use crate::entry::EntryRef;
use crate::error::Result;
use crate::journal::Journal;
use std::collections::VecDeque;

use super::filter::{CompiledFilter, MatchTerm};
use super::{is_skippable_live_file_error, warn_live_file_error};

pub(super) struct JournalSnapshot {
    pub(super) journal: Option<Journal>,
    pub(super) last_seen: Option<SdJournalEntryKey>,
}

pub(super) struct ReplayState {
    pub(super) journal: Option<Journal>,
    pub(super) remaining: Option<usize>,
    cursor: Option<Cursor>,
    since_realtime: Option<u64>,
    iter: Option<Box<dyn Iterator<Item = Result<EntryRef>> + Send + Sync>>,
    buffered: VecDeque<EntryRef>,
    exhausted: bool,
}

impl ReplayState {
    pub(super) fn new(
        snapshot: JournalSnapshot,
        after_cursor: Option<Cursor>,
        since_realtime: Option<u64>,
        config: &JournalConfig,
    ) -> Self {
        Self {
            journal: snapshot.journal,
            cursor: after_cursor,
            since_realtime,
            remaining: config.max_live_replay_entries,
            iter: None,
            buffered: VecDeque::new(),
            exhausted: false,
        }
    }
}

pub(super) struct EntryBatch {
    pub(super) entries: Vec<EntryRef>,
    pub(super) exhausted: bool,
}

pub(super) fn collect_replay_batch(
    replay: &mut ReplayState,
    filter: &CompiledFilter,
    limit: usize,
) -> Result<EntryBatch> {
    let Some(journal) = replay.journal.as_ref() else {
        return Ok(EntryBatch {
            entries: Vec::new(),
            exhausted: true,
        });
    };
    if replay.iter.is_none() {
        let mut q = journal.query();
        apply_compiled_filter(&mut q, filter);
        if let Some(since) = replay.since_realtime {
            q.since_realtime(since);
        }
        if let Some(cursor) = replay.cursor.clone() {
            q.after_cursor(cursor);
        }
        // Resolve the starting cursor only once. A previous batch's source may be vacuumed
        // before the next poll; replay must still advance through the other snapshot files.
        replay.iter = Some(Box::new(q.iter()?));
    }

    if let Some(iter) = replay.iter.as_mut() {
        while !replay.exhausted && replay.buffered.len() <= limit {
            match iter.next() {
                Some(Ok(entry)) => replay.buffered.push_back(entry),
                Some(Err(err)) if is_skippable_live_file_error(&err) => {
                    warn_live_file_error("skipping live replay entry", &err);
                }
                // Retain already decoded entries if the caller handles this error and polls
                // again. The buffer is bounded to one batch plus its lookahead entry.
                Some(Err(err)) => return Err(err),
                None => replay.exhausted = true,
            }
        }
    }
    let entries = replay
        .buffered
        .drain(..limit.min(replay.buffered.len()))
        .collect();
    Ok(EntryBatch {
        entries,
        exhausted: replay.exhausted && replay.buffered.is_empty(),
    })
}

pub(super) fn snapshot_contains_key(replay: &ReplayState, key: SdJournalEntryKey) -> Result<bool> {
    let Some(journal) = replay.journal.as_ref() else {
        return Ok(false);
    };
    for index in 0..journal.inner.file_count() {
        let Some(info) = journal.inner.file_info(index) else {
            continue;
        };
        if info.seqnum_id != key.seqnum_id
            || info.entry_range.is_some_and(|range| {
                key.seqnum < range.first.seqnum || key.seqnum > range.last.seqnum
            })
        {
            continue;
        }
        let file = journal.inner.open_file_by_index(index)?;
        for item in file.entry_iter_seek_realtime(false, None, None)? {
            let meta = item?;
            if meta.seqnum > key.seqnum {
                break;
            }
            if meta.seqnum == key.seqnum
                && meta.seqnum_id == key.seqnum_id
                && meta.boot_id == key.boot_id
                && meta.monotonic_usec == key.monotonic_usec
                && meta.realtime_usec == key.realtime_usec
                && meta.xor_hash == key.xor_hash
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn apply_compiled_filter(query: &mut crate::JournalQuery, filter: &CompiledFilter) {
    for term in &filter.global_terms {
        apply_term_to_query(query, term);
    }
    for branch in &filter.or_groups {
        query.or_group(|group| {
            for term in branch {
                apply_term_to_or_group(group, term);
            }
        });
    }
    if filter.global_terms.is_empty() && filter.or_groups.is_empty() {
        for branch in &filter.branches {
            for term in branch {
                apply_term_to_query(query, term);
            }
        }
    }
}

fn apply_term_to_query(query: &mut crate::JournalQuery, term: &MatchTerm) {
    match term {
        MatchTerm::Exact { field, value } => {
            query.match_exact(field, value);
        }
        MatchTerm::Present { field } => {
            query.match_present(field);
        }
    }
}

fn apply_term_to_or_group(group: &mut crate::query::OrGroupBuilder, term: &MatchTerm) {
    match term {
        MatchTerm::Exact { field, value } => {
            group.match_exact(field, value);
        }
        MatchTerm::Present { field } => {
            group.match_present(field);
        }
    }
}
