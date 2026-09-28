//! Bounded pending events, in memory unless a durable directory is configured.

use super::client::ManagedEvent;
use super::spool::{AppendOutcome, EventSpool, PendingBatch};
use std::{
    collections::VecDeque,
    io,
    sync::{Arc, Mutex},
};

#[derive(Clone)]
pub(super) enum PendingEvents {
    Disk(EventSpool),
    Memory(Arc<Mutex<MemoryEvents>>),
}

pub(super) struct MemoryEvents {
    events: VecDeque<(u64, usize, ManagedEvent)>,
    bytes: u64,
    max_bytes: u64,
    sequence: u64,
}

impl PendingEvents {
    pub fn memory(max_bytes: u64) -> Self {
        Self::Memory(Arc::new(Mutex::new(MemoryEvents {
            events: VecDeque::new(),
            bytes: 0,
            max_bytes,
            sequence: 0,
        })))
    }

    pub fn append(&self, event: &ManagedEvent) -> io::Result<AppendOutcome> {
        match self {
            Self::Disk(spool) => spool.append(event),
            Self::Memory(state) => {
                let size = serde_json::to_vec(event).map_err(io::Error::other)?.len();
                let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
                if size as u64 > state.max_bytes.saturating_sub(state.bytes) {
                    return Ok(AppendOutcome::Dropped);
                }
                state.sequence += 1;
                let sequence = state.sequence;
                state.events.push_back((sequence, size, event.clone()));
                state.bytes += size as u64;
                Ok(AppendOutcome::Stored)
            }
        }
    }

    pub fn read_batch(&self, limit: usize) -> io::Result<PendingBatch> {
        match self {
            Self::Disk(spool) => spool.read_batch(limit),
            Self::Memory(state) => {
                let state = state.lock().unwrap_or_else(|e| e.into_inner());
                let mut batch = PendingBatch {
                    events: Vec::new(),
                    end_offset: 0,
                    generation: 0,
                };
                for (sequence, _, event) in state.events.iter().take(limit) {
                    batch.events.push(event.clone());
                    batch.end_offset = *sequence;
                }
                Ok(batch)
            }
        }
    }

    pub fn ack(&self, end_offset: u64, generation: u64) -> io::Result<()> {
        match self {
            Self::Disk(spool) => spool.ack(end_offset, generation),
            Self::Memory(state) => {
                let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
                while state
                    .events
                    .front()
                    .is_some_and(|(seq, _, _)| *seq <= end_offset)
                {
                    if let Some((_, size, _)) = state.events.pop_front() {
                        state.bytes -= size as u64;
                    }
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_bound_drops_newest_and_ack_reclaims_space() {
        let mut event = ManagedEvent {
            event_id: "first".into(),
            ..ManagedEvent::default()
        };
        let size = serde_json::to_vec(&event).expect("json").len() as u64;
        let spool = PendingEvents::memory(size);
        assert_eq!(spool.append(&event).expect("append"), AppendOutcome::Stored);
        assert_eq!(
            spool.append(&event).expect("append"),
            AppendOutcome::Dropped
        );
        let batch = spool.read_batch(50).expect("read");
        assert_eq!(batch.events[0].event_id, "first");
        spool.ack(batch.end_offset, batch.generation).expect("ack");
        event.event_id = "later".into();
        assert_eq!(spool.append(&event).expect("append"), AppendOutcome::Stored);
        // An old acknowledgement must not remove an event appended later.
        spool
            .ack(batch.end_offset, batch.generation)
            .expect("old ack");
        assert_eq!(
            spool.read_batch(50).expect("read").events[0].event_id,
            "later"
        );
    }
}
