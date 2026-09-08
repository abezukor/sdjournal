#[allow(dead_code)]
mod support;

use sdjournal::{Journal, JournalConfig, MmapPolicy, SdJournalError};
use std::fs;
use support::synthetic_journal::SyntheticJournalFile;

#[test]
fn malformed_hash_table_locations_fall_back_to_matching_entries() {
    for corruption in [
        "missing-table",
        "inside-header",
        "wrong-object-type",
        "wrong-object-size",
    ] {
        let layout = SyntheticJournalFile::new(&["alpha.service"]);
        let path = layout.root().join("synthetic.journal");
        let mut bytes = fs::read(&path).unwrap();
        bytes[16] = 0; // Exercise the index optimization for an immutable file.
        let table_offset = u64::from_le_bytes(bytes[104..112].try_into().unwrap()) as usize;
        match corruption {
            "missing-table" => bytes[104..120].fill(0),
            "inside-header" => bytes[104..112].copy_from_slice(&208u64.to_le_bytes()),
            "wrong-object-type" => {
                bytes[table_offset - 16] = 6;
                bytes[table_offset..table_offset + 16].fill(0);
            }
            "wrong-object-size" => {
                bytes[table_offset - 8..table_offset].copy_from_slice(&48u64.to_le_bytes());
                bytes[table_offset..table_offset + 16].fill(0);
            }
            _ => unreachable!(),
        }
        fs::write(&path, bytes).unwrap();
        let journal = Journal::open_dir_with_config(
            layout.root(),
            JournalConfig {
                mmap_policy: MmapPolicy::Never,
                ..Default::default()
            },
        )
        .unwrap();
        let mut query = journal.query();
        query.match_exact("_SYSTEMD_UNIT", b"alpha.service");
        let entries = query.collect_owned().unwrap();
        assert_eq!(entries.len(), 1, "{corruption}");
    }
}

#[test]
fn data_postings_cannot_return_entries_outside_the_file_entry_array() {
    for orphan_index in [1, 2] {
        let layout = SyntheticJournalFile::new(&["alpha.service"; 3]);
        let path = layout.root().join("synthetic.journal");
        let mut bytes = fs::read(&path).unwrap();
        bytes[16] = 0;
        let array_offset = u64::from_le_bytes(bytes[176..184].try_into().unwrap()) as usize;
        let third = bytes[array_offset + 40..array_offset + 48].to_vec();
        // Leave one otherwise valid ENTRY in the object arena and DATA postings, but remove
        // it from the committed file-level index. Test both an interior and a tail orphan.
        if orphan_index == 1 {
            bytes[array_offset + 32..array_offset + 40].copy_from_slice(&third);
        }
        bytes[array_offset + 40..array_offset + 48].fill(0);
        bytes[152..160].copy_from_slice(&2u64.to_le_bytes());
        fs::write(&path, bytes).unwrap();

        let journal = Journal::open_dir_with_config(
            layout.root(),
            JournalConfig {
                mmap_policy: MmapPolicy::Never,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(journal.query().collect_owned().unwrap().len(), 2);

        for reverse in [false, true] {
            let mut query = journal.query();
            query.match_exact("_SYSTEMD_UNIT", b"alpha.service");
            query.reverse(reverse);
            assert!(
                matches!(query.collect_owned(), Err(SdJournalError::Corrupt { .. })),
                "indexed query accepted orphan {orphan_index} (reverse={reverse})"
            );
        }
    }
}
