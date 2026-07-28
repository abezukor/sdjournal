use crate::config::JournalConfig;
use crate::cursor::{Cursor, SdJournalEntryKey};
use crate::entry::EntryRef;
use crate::error::Result;
use crate::journal::Journal;

use super::filter::{CompiledFilter, MatchTerm};
use super::{
    cursor_from_key, is_skippable_live_file_error, key_from_entry_ref, warn_live_file_error,
};

pub(super) struct JournalSnapshot {
    pub(super) journal: Option<Journal>,
    pub(super) last_seen: Option<SdJournalEntryKey>,
}

pub(super) struct ReplayState {
    pub(super) journal: Option<Journal>,
    pub(super) cursor: Option<Cursor>,
    pub(super) since_realtime: Option<u64>,
    pub(super) last_key: Option<SdJournalEntryKey>,
    pub(super) remaining: Option<usize>,
}

impl ReplayState {
    pub(super) fn new(
        snapshot: JournalSnapshot,
        after_cursor: Option<Cursor>,
        since_realtime: Option<u64>,
        config: &JournalConfig,
    ) -> Self {
        let (cursor, last_key) = match after_cursor {
            Some(cursor) => match cursor.sdjournal_entry_key() {
                Some(key) => (None, Some(key)),
                None => (Some(cursor), None),
            },
            None => (None, None),
        };

        Self {
            journal: snapshot.journal,
            cursor,
            since_realtime,
            last_key,
            remaining: config.max_live_replay_entries,
        }
    }
}

pub(super) struct EntryBatch {
    pub(super) entries: Vec<EntryRef>,
    pub(super) last_key: Option<SdJournalEntryKey>,
    pub(super) exhausted: bool,
}

pub(super) fn collect_replay_batch(
    replay: &ReplayState,
    filter: &CompiledFilter,
    limit: usize,
) -> Result<EntryBatch> {
    let Some(journal) = replay.journal.as_ref() else {
        return Ok(EntryBatch {
            entries: Vec::new(),
            last_key: None,
            exhausted: true,
        });
    };
    let mut q = journal.query();
    apply_compiled_filter(&mut q, filter);
    if let Some(since) = replay.since_realtime {
        q.since_realtime(since);
    }
    if let Some(key) = replay.last_key {
        q.after_cursor(cursor_from_key(key));
    } else if let Some(cursor) = replay.cursor.clone() {
        q.after_cursor(cursor);
    }
    q.limit(limit.saturating_add(1));

    collect_entry_batch(q, limit, "skipping live replay entry")
}

fn collect_entry_batch(
    query: crate::JournalQuery,
    limit: usize,
    skip_message: &'static str,
) -> Result<EntryBatch> {
    let mut entries = Vec::with_capacity(limit.min(64));
    let mut exhausted = true;
    for item in query.iter()? {
        match item {
            Ok(entry) => {
                if entries.len() >= limit {
                    exhausted = false;
                    break;
                }
                entries.push(entry);
            }
            Err(err) if is_skippable_live_file_error(&err) => {
                warn_live_file_error(skip_message, &err);
            }
            Err(err) => return Err(err),
        }
    }

    let last_key = entries.last().map(key_from_entry_ref);
    Ok(EntryBatch {
        entries,
        last_key,
        exhausted,
    })
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
