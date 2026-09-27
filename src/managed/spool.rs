//! Durable append-only spool of pending usage-event batches.
//!
//! Each enqueued event is length-prefixed JSON, fsynced before the enqueue
//! returns. A separate ack file records the first unacknowledged offset.
//! Acknowledged prefixes are removed by truncation (when the file drains) or
//! by rewriting the unacked tail (when a new append would exceed the byte
//! bound). A crash replays from the ack offset; a torn tail is truncated.
//! Replaying an already-delivered event is safe: the control plane dedupes
//! by `event_id`.

use super::client::ManagedEvent;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

const HEADER: &[u8] = b"RSEV";
const VERSION: u32 = 1;
const HEADER_LEN: u64 = 8;
/// A single record larger than this is treated as corruption, not a payload.
const MAX_RECORD: u32 = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppendOutcome {
    Stored,
    /// The spool is at its byte bound. The new event was not written.
    Dropped,
}

#[derive(Debug)]
pub struct PendingBatch {
    pub events: Vec<ManagedEvent>,
    pub end_offset: u64,
    /// Bumped when the file is rewritten. An ack from an older generation is
    /// ignored so a compact during an in-flight send cannot skip the tail.
    pub generation: u64,
}

struct SpoolInner {
    dir: PathBuf,
    wal: File,
    ack: u64,
    len: u64,
    generation: u64,
}

#[derive(Clone)]
pub struct EventSpool {
    inner: Arc<Mutex<SpoolInner>>,
    max_bytes: u64,
}

impl EventSpool {
    pub fn open(dir: impl Into<PathBuf>, max_bytes: u64) -> io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        // A crashed compact leaves this beside the still-valid wal.
        let _ = fs::remove_file(dir.join("wal.next"));
        let wal_path = dir.join("wal");
        let mut wal = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&wal_path)?;
        if wal.metadata()?.len() < HEADER_LEN {
            wal.set_len(0)?;
            write_header(&mut wal)?;
            wal.sync_all()?;
            fsync_dir(&dir)?;
        } else {
            validate_header(&mut wal)?;
        }
        let len = repair_tail(&mut wal)?;
        let ack = read_ack(&dir, len)?;
        Ok(Self {
            inner: Arc::new(Mutex::new(SpoolInner {
                dir,
                wal,
                ack,
                len,
                generation: 0,
            })),
            max_bytes,
        })
    }

    pub fn append(&self, event: &ManagedEvent) -> io::Result<AppendOutcome> {
        let payload = serde_json::to_vec(event)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        if payload.len() > MAX_RECORD as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "managed event exceeds the spool record limit",
            ));
        }
        let record_len = 4 + payload.len() as u64;
        let mut inner = lock(&self.inner);
        if inner.len + record_len > self.max_bytes && inner.ack > HEADER_LEN {
            compact_tail(&mut inner)?;
        }
        if inner.len + record_len > self.max_bytes {
            return Ok(AppendOutcome::Dropped);
        }
        let len = inner.len;
        inner.wal.seek(SeekFrom::Start(len))?;
        inner.wal.write_all(&(payload.len() as u32).to_le_bytes())?;
        inner.wal.write_all(&payload)?;
        inner.wal.sync_all()?;
        inner.len += record_len;
        Ok(AppendOutcome::Stored)
    }

    pub fn read_batch(&self, max_events: usize) -> io::Result<PendingBatch> {
        let mut inner = lock(&self.inner);
        let ack = inner.ack;
        inner.wal.seek(SeekFrom::Start(ack))?;
        let mut events = Vec::new();
        let mut offset = inner.ack;
        while events.len() < max_events && offset + 4 <= inner.len {
            let mut len_buf = [0u8; 4];
            inner.wal.read_exact(&mut len_buf)?;
            let n = u32::from_le_bytes(len_buf);
            let record_end = offset + 4 + u64::from(n);
            if n == 0 || n > MAX_RECORD || record_end > inner.len {
                truncate_wal(&mut inner, offset)?;
                break;
            }
            let mut payload = vec![0u8; n as usize];
            inner.wal.read_exact(&mut payload)?;
            match serde_json::from_slice::<ManagedEvent>(&payload) {
                Ok(event) => {
                    events.push(event);
                    offset = record_end;
                }
                Err(_) => {
                    truncate_wal(&mut inner, offset)?;
                    break;
                }
            }
        }
        Ok(PendingBatch {
            events,
            end_offset: offset,
            generation: inner.generation,
        })
    }

    /// Advance the ack to `end_offset` when it still refers to this file
    /// generation. Fully drained files are truncated so acknowledged batches
    /// do not occupy the bound.
    pub fn ack(&self, end_offset: u64, generation: u64) -> io::Result<()> {
        let mut inner = lock(&self.inner);
        if inner.generation != generation {
            return Ok(());
        }
        if end_offset > inner.ack && end_offset <= inner.len {
            inner.ack = end_offset;
            write_ack(&inner.dir, inner.ack)?;
        }
        if inner.ack >= inner.len && inner.len > HEADER_LEN {
            truncate_wal(&mut inner, HEADER_LEN)?;
            inner.ack = HEADER_LEN;
            write_ack(&inner.dir, HEADER_LEN)?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn pending_ids(&self) -> io::Result<Vec<String>> {
        Ok(self
            .read_batch(usize::MAX)?
            .events
            .into_iter()
            .map(|event| event.event_id)
            .collect())
    }
}

fn lock(inner: &Mutex<SpoolInner>) -> std::sync::MutexGuard<'_, SpoolInner> {
    inner
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn write_header(wal: &mut File) -> io::Result<()> {
    wal.seek(SeekFrom::Start(0))?;
    wal.write_all(HEADER)?;
    wal.write_all(&VERSION.to_le_bytes())?;
    Ok(())
}

fn validate_header(wal: &mut File) -> io::Result<()> {
    wal.seek(SeekFrom::Start(0))?;
    let mut magic = [0u8; 4];
    wal.read_exact(&mut magic)?;
    let mut version = [0u8; 4];
    wal.read_exact(&mut version)?;
    if magic.as_slice() != HEADER || u32::from_le_bytes(version) != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "managed event spool header is not a known version",
        ));
    }
    Ok(())
}

/// Drop a torn or corrupt tail so replay starts at the last complete record.
fn repair_tail(wal: &mut File) -> io::Result<u64> {
    let file_len = wal.metadata()?.len();
    wal.seek(SeekFrom::Start(HEADER_LEN))?;
    let mut offset = HEADER_LEN;
    while offset + 4 <= file_len {
        let mut len_buf = [0u8; 4];
        if wal.read_exact(&mut len_buf).is_err() {
            break;
        }
        let n = u32::from_le_bytes(len_buf);
        let record_end = offset + 4 + u64::from(n);
        if n == 0 || n > MAX_RECORD || record_end > file_len {
            break;
        }
        let mut payload = vec![0u8; n as usize];
        if wal.read_exact(&mut payload).is_err()
            || serde_json::from_slice::<ManagedEvent>(&payload).is_err()
        {
            break;
        }
        offset = record_end;
    }
    if offset < file_len {
        wal.set_len(offset)?;
        wal.sync_all()?;
    }
    Ok(offset)
}

fn truncate_wal(inner: &mut SpoolInner, len: u64) -> io::Result<()> {
    inner.wal.set_len(len)?;
    inner.wal.sync_all()?;
    inner.len = len;
    if inner.ack > inner.len {
        inner.ack = HEADER_LEN;
        write_ack(&inner.dir, HEADER_LEN)?;
    }
    Ok(())
}

/// Rewrite the unacked tail into a new file and swap it into place.
///
/// The ack is reset to the header *before* the swap is visible only in the
/// sense that a crash either replays the old file (duplicates, which the
/// control plane dedupes) or replays the new tail. An ack past the new file
/// length is treated as "replay everything" on open.
fn compact_tail(inner: &mut SpoolInner) -> io::Result<()> {
    if inner.ack <= HEADER_LEN || inner.ack > inner.len {
        return Ok(());
    }
    let tail_len = (inner.len - inner.ack) as usize;
    let mut tail = vec![0u8; tail_len];
    inner.wal.seek(SeekFrom::Start(inner.ack))?;
    inner.wal.read_exact(&mut tail)?;

    let next_path = inner.dir.join("wal.next");
    {
        let mut next = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&next_path)?;
        write_header(&mut next)?;
        next.write_all(&tail)?;
        next.sync_all()?;
    }
    // Persist "replay from the start" before the new file becomes visible.
    // A crash here re-sends already-acked events; the control plane dedupes.
    write_ack(&inner.dir, HEADER_LEN)?;
    let wal_path = inner.dir.join("wal");
    fs::rename(&next_path, &wal_path)?;
    fsync_dir(&inner.dir)?;
    inner.wal = OpenOptions::new().read(true).write(true).open(&wal_path)?;
    inner.len = HEADER_LEN + tail_len as u64;
    inner.ack = HEADER_LEN;
    inner.generation = inner.generation.saturating_add(1);
    Ok(())
}

fn read_ack(dir: &Path, len: u64) -> io::Result<u64> {
    let path = dir.join("ack");
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(HEADER_LEN),
        Err(err) => return Err(err),
    };
    if bytes.len() != 8 {
        return Ok(HEADER_LEN);
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes);
    let ack = u64::from_le_bytes(buf);
    // A compact swaps in a shorter file. An ack past the end means "the
    // previous generation's offset"; replaying the whole file is safe.
    if ack < HEADER_LEN || ack > len {
        return Ok(HEADER_LEN);
    }
    Ok(ack)
}

fn write_ack(dir: &Path, ack: u64) -> io::Result<()> {
    let tmp = dir.join("ack.tmp");
    {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        file.write_all(&ack.to_le_bytes())?;
        file.sync_all()?;
    }
    fs::rename(&tmp, dir.join("ack"))?;
    fsync_dir(dir)
}

fn fsync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::managed::client::ManagedEvent;

    fn event(id: &str) -> ManagedEvent {
        ManagedEvent {
            event_id: id.to_string(),
            kind: "download".to_string(),
            tenant_id: "org_1".to_string(),
            package: "demo".to_string(),
            version: Some("1.0.0".to_string()),
            credential_id: None,
            bytes: 4,
            occurred_at: "2026-09-27T12:00:00Z".to_string(),
            ..ManagedEvent::default()
        }
    }

    #[test]
    fn bound_drops_the_newest_event_and_keeps_the_older_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = event("evt-older");
        let probe = EventSpool::open(dir.path(), u64::MAX).expect("open");
        assert_eq!(probe.append(&first).expect("append"), AppendOutcome::Stored);
        let bound = probe.read_batch(1).expect("read").end_offset;
        drop(probe);

        let spool = EventSpool::open(dir.path(), bound).expect("reopen");
        assert_eq!(
            spool.append(&event("evt-newest")).expect("append"),
            AppendOutcome::Dropped
        );
        assert_eq!(
            spool.pending_ids().expect("pending"),
            vec!["evt-older".to_string()]
        );
    }

    #[test]
    fn replay_after_reopen_keeps_event_ids_until_ack() {
        let dir = tempfile::tempdir().expect("tempdir");
        let spool = EventSpool::open(dir.path(), u64::MAX).expect("open");
        spool.append(&event("evt-1")).expect("append");
        spool.append(&event("evt-2")).expect("append");
        drop(spool);

        let spool = EventSpool::open(dir.path(), u64::MAX).expect("reopen");
        let batch = spool.read_batch(10).expect("read");
        assert_eq!(
            batch
                .events
                .iter()
                .map(|event| event.event_id.as_str())
                .collect::<Vec<_>>(),
            vec!["evt-1", "evt-2"]
        );
        spool.ack(batch.end_offset, batch.generation).expect("ack");
        assert!(spool.pending_ids().expect("pending").is_empty());

        let spool = EventSpool::open(dir.path(), u64::MAX).expect("reopen after ack");
        assert!(
            spool.pending_ids().expect("pending").is_empty(),
            "acknowledged batches are removed and not replayed"
        );
    }
}
