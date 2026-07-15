#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum JournalEvent {
    LeaseBound {
        binding: LeaseBinding,
    },
    InputAccepted {
        stream: StreamKey,
        sequence: u64,
        input_digest: ContentDigest,
        input_bytes: u64,
        frame_truncated: bool,
    },
    Output {
        frame: StoredLogFrame,
    },
    StepFinished {
        step: StepKey,
    },
    RunFinished {
        run_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JournalEnvelope {
    pub(crate) journal_version: u32,
    pub(crate) index: u64,
    pub(crate) previous_hash: ContentDigest,
    pub(crate) event_hash: ContentDigest,
    pub(crate) event: JournalEvent,
}
pub(crate) struct VerifiedJournal {
    pub(crate) next_index: u64,
    pub(crate) previous_hash: ContentDigest,
    pub(crate) leases: BTreeMap<LeaseKey, LeaseBinding>,
    pub(crate) streams: BTreeMap<StreamKey, StreamState>,
    pub(crate) closed_steps: BTreeSet<StepKey>,
    pub(crate) closed_runs: BTreeSet<String>,
    pub(crate) interrupted_runs: BTreeSet<String>,
    pub(crate) frames: Vec<StoredLogFrame>,
}

pub(crate) fn verify_journal(
    path: &Path,
    limits: LogLimits,
    secrets: &SecretSet,
) -> Result<VerifiedJournal, LogError> {
    let file = open_journal_read(path)?;
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    let mut index = 0_u64;
    let mut previous_hash = genesis_hash();
    let mut leases: BTreeMap<LeaseKey, LeaseBinding> = BTreeMap::new();
    let mut streams: BTreeMap<StreamKey, StreamState> = BTreeMap::new();
    let mut closed_steps = BTreeSet::new();
    let mut closed_runs = BTreeSet::new();
    let mut runs_seen = BTreeSet::new();
    let mut frames = Vec::new();

    loop {
        line.clear();
        let read = reader
            .read_until(b'\n', &mut line)
            .map_err(|source| io_failure("read log journal", path, source))?;
        if read == 0 {
            break;
        }
        if line.len() > limits.max_journal_record_bytes || line.last() != Some(&b'\n') {
            return Err(LogError::Integrity(
                "journal record is oversized or incomplete".to_owned(),
            ));
        }
        line.pop();
        let envelope: JournalEnvelope = serde_json::from_slice(&line)
            .map_err(|error| LogError::Integrity(error.to_string()))?;
        if envelope.journal_version != JOURNAL_VERSION
            || envelope.index != index
            || envelope.previous_hash != previous_hash
        {
            return Err(LogError::Integrity(
                "journal index or previous hash mismatch".to_owned(),
            ));
        }
        let event_bytes = serde_json::to_vec(&envelope.event).map_err(LogError::Serialize)?;
        let expected_hash = journal_hash(index, &previous_hash, &event_bytes)?;
        if envelope.event_hash != expected_hash {
            return Err(LogError::Integrity(
                "journal event hash mismatch".to_owned(),
            ));
        }

        match &envelope.event {
            JournalEvent::LeaseBound { binding } => {
                validate_binding(binding, limits)?;
                runs_seen.insert(binding.run_id.clone());
                let key = LeaseKey {
                    run_id: binding.run_id.clone(),
                    job_id: binding.job_id.clone(),
                };
                if let Some(current) = leases.get(&key) {
                    if binding.fencing_generation <= current.fencing_generation {
                        return Err(LogError::Integrity(
                            "journal lease fencing did not increase".to_owned(),
                        ));
                    }
                }
                leases.insert(key, binding.clone());
            }
            JournalEvent::InputAccepted {
                stream,
                sequence,
                input_digest,
                ..
            } => {
                validate_stream_key(stream, limits)?;
                runs_seen.insert(stream.run_id.clone());
                let state = streams
                    .entry(stream.clone())
                    .or_insert_with(|| StreamState::new(secrets, limits));
                if *sequence != state.expected_sequence || *sequence >= limits.max_frames_per_stream
                {
                    return Err(LogError::Integrity(
                        "journal stream sequence is not contiguous".to_owned(),
                    ));
                }
                state.input_digests.insert(*sequence, input_digest.clone());
                state.expected_sequence += 1;
            }
            JournalEvent::Output { frame } => {
                validate_stored_frame(frame, limits)?;
                if frame.journal_index != envelope.index {
                    return Err(LogError::Integrity(
                        "stored frame index does not match journal".to_owned(),
                    ));
                }
                frame.payload.decode()?;
                runs_seen.insert(frame.run_id.clone());
                frames.push(frame.clone());
            }
            JournalEvent::StepFinished { step } => {
                validate_step_key(step, limits)?;
                runs_seen.insert(step.run_id.clone());
                if !closed_steps.insert(step.clone()) {
                    return Err(LogError::Integrity(
                        "duplicate step-finished journal event".to_owned(),
                    ));
                }
                for (key, state) in &mut streams {
                    if key.step_key() == *step {
                        state.finished = true;
                    }
                }
            }
            JournalEvent::RunFinished { run_id } => {
                validate_identifier("run_id", run_id, limits)?;
                if !closed_runs.insert(run_id.clone()) {
                    return Err(LogError::Integrity(
                        "duplicate run-finished journal event".to_owned(),
                    ));
                }
            }
        }
        previous_hash = envelope.event_hash;
        index += 1;
    }

    let interrupted_runs = runs_seen
        .difference(&closed_runs)
        .cloned()
        .collect::<BTreeSet<_>>();
    for (key, state) in &mut streams {
        if interrupted_runs.contains(&key.run_id) {
            state.interrupted = true;
        }
    }
    Ok(VerifiedJournal {
        next_index: index,
        previous_hash,
        leases,
        streams,
        closed_steps,
        closed_runs,
        interrupted_runs,
        frames,
    })
}
pub(crate) fn input_digest(
    frame: &LogInputFrame,
    key: &InputDigestKey,
) -> Result<ContentDigest, LogError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.expose())
        .map_err(|_| LogError::InvalidInputDigestKey)?;
    mac.update(INPUT_DIGEST_DOMAIN);
    hmac_field(&mut mac, frame.run_id.as_bytes());
    hmac_field(&mut mac, frame.job_id.as_bytes());
    hmac_field(&mut mac, frame.step_id.as_bytes());
    hmac_field(&mut mac, frame.lease_id.as_bytes());
    mac.update(&frame.fencing_generation.to_be_bytes());
    mac.update(&[match frame.stream {
        LogStream::Stdout => 0,
        LogStream::Stderr => 1,
        LogStream::System => 2,
    }]);
    mac.update(&frame.sequence.to_be_bytes());
    hmac_field(&mut mac, &frame.payload);
    digest_from_bytes(&mac.finalize().into_bytes())
}

fn hmac_field(mac: &mut Hmac<Sha256>, bytes: &[u8]) {
    mac.update(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    mac.update(bytes);
}

pub(crate) fn journal_hash(
    index: u64,
    previous: &ContentDigest,
    event_bytes: &[u8],
) -> Result<ContentDigest, LogError> {
    let mut hasher = Sha256::new();
    hasher.update(JOURNAL_DIGEST_DOMAIN);
    hasher.update(index.to_be_bytes());
    hash_field(&mut hasher, previous.as_str().as_bytes());
    hash_field(&mut hasher, event_bytes);
    digest_from_hasher(hasher)
}

fn genesis_hash() -> ContentDigest {
    ContentDigest::sha256(b"runtrue.log.journal.genesis.v1")
}

fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}

fn digest_from_hasher(hasher: Sha256) -> Result<ContentDigest, LogError> {
    let bytes = hasher.finalize();
    digest_from_bytes(&bytes)
}

fn digest_from_bytes(bytes: &[u8]) -> Result<ContentDigest, LogError> {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(*byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(*byte & 0x0f)]));
    }
    ContentDigest::parse(format!("sha256:{encoded}"))
        .map_err(|error| LogError::Integrity(error.to_string()))
}
use crate::{
    model::{LeaseBinding, LeaseKey, LogInputFrame, LogStream, StepKey, StoredLogFrame, StreamKey},
    pipeline::{StreamState, INPUT_DIGEST_DOMAIN, JOURNAL_DIGEST_DOMAIN, JOURNAL_VERSION},
    secure_io::{io_failure, open_journal_read},
    validation::{
        validate_binding, validate_identifier, validate_step_key, validate_stored_frame,
        validate_stream_key,
    },
    InputDigestKey, LogError, LogLimits, SecretSet,
};
use hmac::{Hmac, Mac as _};
use runtrue_model::ContentDigest;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{BufRead, BufReader},
    path::Path,
};
