//! Strict, dependency-free subset of the CometBFT v0.38 ABCI socket wire format.
//!
//! CometBFT's socket protocol is a stream of unsigned-varint-length-delimited
//! protobuf `abci.Request`/`abci.Response` envelopes.  This module recognizes
//! only the methods that Noxis currently implements and rejects unknown fields
//! or non-canonical framing before application state is touched.

use std::{
    fmt,
    io::{self, Read, Write},
};

use crate::{AppInfo, CheckTxResult, FinalizeBlockResult, ProposalStatus};

/// Upper bound for one complete ABCI request or response frame.
///
/// It accommodates Noxis's 64 MiB maximum aggregate transaction bytes plus
/// bounded protobuf framing, while avoiding CometBFT's generic 2 GiB socket
/// decoder limit at this application boundary.
pub const MAX_ABCI_FRAME_BYTES: usize = 80 * 1024 * 1024;

const REQUEST_ECHO: u32 = 1;
const REQUEST_FLUSH: u32 = 2;
const REQUEST_INFO: u32 = 3;
const REQUEST_INIT_CHAIN: u32 = 5;
const REQUEST_QUERY: u32 = 6;
const REQUEST_CHECK_TX: u32 = 8;
const REQUEST_COMMIT: u32 = 11;
const REQUEST_LIST_SNAPSHOTS: u32 = 12;
const REQUEST_OFFER_SNAPSHOT: u32 = 13;
const REQUEST_LOAD_SNAPSHOT_CHUNK: u32 = 14;
const REQUEST_APPLY_SNAPSHOT_CHUNK: u32 = 15;
const REQUEST_PREPARE_PROPOSAL: u32 = 16;
const REQUEST_PROCESS_PROPOSAL: u32 = 17;
const REQUEST_EXTEND_VOTE: u32 = 18;
const REQUEST_VERIFY_VOTE_EXTENSION: u32 = 19;
const REQUEST_FINALIZE_BLOCK: u32 = 20;

const RESPONSE_EXCEPTION: u32 = 1;
const RESPONSE_ECHO: u32 = 2;
const RESPONSE_FLUSH: u32 = 3;
const RESPONSE_INFO: u32 = 4;
const RESPONSE_INIT_CHAIN: u32 = 6;
const RESPONSE_QUERY: u32 = 7;
const RESPONSE_CHECK_TX: u32 = 9;
const RESPONSE_COMMIT: u32 = 12;
const RESPONSE_LIST_SNAPSHOTS: u32 = 13;
const RESPONSE_OFFER_SNAPSHOT: u32 = 14;
const RESPONSE_LOAD_SNAPSHOT_CHUNK: u32 = 15;
const RESPONSE_APPLY_SNAPSHOT_CHUNK: u32 = 16;
const RESPONSE_PREPARE_PROPOSAL: u32 = 17;
const RESPONSE_PROCESS_PROPOSAL: u32 = 18;
const RESPONSE_EXTEND_VOTE: u32 = 19;
const RESPONSE_VERIFY_VOTE_EXTENSION: u32 = 20;
const RESPONSE_FINALIZE_BLOCK: u32 = 21;

/// Decoded raw validator update from a CometBFT `RequestInitChain`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct InitValidatorUpdate {
    pub public_key: [u8; 32],
    pub voting_power: i64,
}

/// ABCI v0.38 requests understood by the transport adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Request {
    Echo(String),
    Flush,
    Info,
    InitChain {
        chain_id: String,
        consensus_parameters: Vec<u8>,
        validators: Vec<InitValidatorUpdate>,
        initial_height: i64,
    },
    Query,
    CheckTx(Vec<u8>),
    Commit,
    ListSnapshots,
    OfferSnapshot,
    LoadSnapshotChunk,
    ApplySnapshotChunk,
    PrepareProposal {
        maximum_transaction_bytes: i64,
        transactions: Vec<Vec<u8>>,
        height: i64,
        next_validators_hash: [u8; 32],
    },
    ProcessProposal {
        transactions: Vec<Vec<u8>>,
        block_hash: [u8; 32],
        height: i64,
        next_validators_hash: [u8; 32],
    },
    ExtendVote,
    VerifyVoteExtension,
    FinalizeBlock {
        transactions: Vec<Vec<u8>>,
        block_hash: [u8; 32],
        height: i64,
        next_validators_hash: [u8; 32],
    },
}

/// Responses emitted by the Noxis ABCI transport adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Response {
    Exception(String),
    Echo(String),
    Flush,
    Info(AppInfo),
    InitChain,
    QueryUnavailable,
    CheckTx(CheckTxResult),
    Commit,
    ListSnapshots,
    OfferSnapshotAbort,
    LoadSnapshotChunk,
    ApplySnapshotChunkAbort,
    PrepareProposal(Vec<Vec<u8>>),
    ProcessProposal(ProposalStatus),
    ExtendVote,
    VerifyVoteExtensionReject,
    FinalizeBlock(FinalizeBlockResult),
}

/// Reads one complete length-delimited ABCI request. A clean peer EOF before a
/// new frame returns `Ok(None)`; a truncated frame is always an error.
pub(crate) fn read_request(reader: &mut impl Read) -> Result<Option<Request>, WireError> {
    let Some(bytes) = read_frame(reader)? else {
        return Ok(None);
    };
    decode_request(&bytes).map(Some)
}

/// Writes one complete length-delimited ABCI response.
pub(crate) fn write_response(
    writer: &mut impl Write,
    response: &Response,
) -> Result<(), WireError> {
    let bytes = encode_response(response);
    write_frame(writer, &bytes)
}

fn decode_request(bytes: &[u8]) -> Result<Request, WireError> {
    let mut reader = ProtoReader::new(bytes);
    let field = reader.next()?.ok_or(WireError::MissingRequestValue)?;
    let message = field.bytes()?;
    let request = match field.number {
        REQUEST_ECHO => Request::Echo(decode_echo(message)?),
        REQUEST_FLUSH => {
            require_empty(message, "RequestFlush")?;
            Request::Flush
        }
        REQUEST_INFO => {
            validate_ignored_message(message, "RequestInfo")?;
            Request::Info
        }
        REQUEST_INIT_CHAIN => decode_init_chain(message)?,
        REQUEST_QUERY => {
            validate_ignored_message(message, "RequestQuery")?;
            Request::Query
        }
        REQUEST_CHECK_TX => Request::CheckTx(decode_check_tx(message)?),
        REQUEST_COMMIT => {
            require_empty(message, "RequestCommit")?;
            Request::Commit
        }
        REQUEST_LIST_SNAPSHOTS => {
            require_empty(message, "RequestListSnapshots")?;
            Request::ListSnapshots
        }
        REQUEST_OFFER_SNAPSHOT => Request::OfferSnapshot,
        REQUEST_LOAD_SNAPSHOT_CHUNK => Request::LoadSnapshotChunk,
        REQUEST_APPLY_SNAPSHOT_CHUNK => Request::ApplySnapshotChunk,
        REQUEST_PREPARE_PROPOSAL => decode_prepare_proposal(message)?,
        REQUEST_PROCESS_PROPOSAL => decode_process_proposal(message)?,
        REQUEST_EXTEND_VOTE => Request::ExtendVote,
        REQUEST_VERIFY_VOTE_EXTENSION => Request::VerifyVoteExtension,
        REQUEST_FINALIZE_BLOCK => decode_finalize_block(message)?,
        other => return Err(WireError::UnsupportedRequest(other)),
    };
    if reader.next()?.is_some() {
        return Err(WireError::MultipleRequestValues);
    }
    Ok(request)
}

fn decode_echo(bytes: &[u8]) -> Result<String, WireError> {
    let mut reader = ProtoReader::new(bytes);
    let field = reader
        .next()?
        .ok_or(WireError::MissingField("echo.message"))?;
    if field.number != 1 {
        return Err(WireError::UnsupportedField {
            message: "RequestEcho",
            field: field.number,
        });
    }
    let value = decode_utf8(field.bytes()?, "echo.message")?;
    if reader.next()?.is_some() {
        return Err(WireError::DuplicateOrTrailingField("echo.message"));
    }
    Ok(value)
}

fn decode_check_tx(bytes: &[u8]) -> Result<Vec<u8>, WireError> {
    let mut reader = ProtoReader::new(bytes);
    let mut transaction = None;
    while let Some(field) = reader.next()? {
        match field.number {
            1 => set_once(&mut transaction, field.bytes()?.to_vec(), "check_tx.tx")?,
            2 => {
                let _ = field.varint()?;
            }
            other => {
                return Err(WireError::UnsupportedField {
                    message: "RequestCheckTx",
                    field: other,
                });
            }
        }
    }
    transaction.ok_or(WireError::MissingField("check_tx.tx"))
}

fn decode_init_chain(bytes: &[u8]) -> Result<Request, WireError> {
    let mut reader = ProtoReader::new(bytes);
    let mut chain_id = None;
    let mut consensus_parameters = None;
    let mut validators = Vec::new();
    let mut initial_height = None;
    while let Some(field) = reader.next()? {
        match field.number {
            1 | 5 => {
                let _ = field.bytes()?;
            }
            2 => set_once(
                &mut chain_id,
                decode_utf8(field.bytes()?, "init_chain.chain_id")?,
                "init_chain.chain_id",
            )?,
            3 => set_once(
                &mut consensus_parameters,
                field.bytes()?.to_vec(),
                "init_chain.consensus_params",
            )?,
            4 => validators.push(decode_validator_update(field.bytes()?)?),
            6 => set_once(
                &mut initial_height,
                field.varint()? as i64,
                "init_chain.initial_height",
            )?,
            other => {
                return Err(WireError::UnsupportedField {
                    message: "RequestInitChain",
                    field: other,
                });
            }
        }
    }
    Ok(Request::InitChain {
        chain_id: chain_id.ok_or(WireError::MissingField("init_chain.chain_id"))?,
        consensus_parameters: consensus_parameters
            .ok_or(WireError::MissingField("init_chain.consensus_params"))?,
        validators,
        initial_height: initial_height.unwrap_or(0),
    })
}

fn decode_validator_update(bytes: &[u8]) -> Result<InitValidatorUpdate, WireError> {
    let mut reader = ProtoReader::new(bytes);
    let mut public_key = None;
    let mut voting_power = None;
    while let Some(field) = reader.next()? {
        match field.number {
            1 => set_once(
                &mut public_key,
                decode_ed25519_public_key(field.bytes()?)?,
                "validator_update.pub_key",
            )?,
            2 => set_once(
                &mut voting_power,
                field.varint()? as i64,
                "validator_update.power",
            )?,
            other => {
                return Err(WireError::UnsupportedField {
                    message: "ValidatorUpdate",
                    field: other,
                });
            }
        }
    }
    Ok(InitValidatorUpdate {
        public_key: public_key.ok_or(WireError::MissingField("validator_update.pub_key"))?,
        voting_power: voting_power.ok_or(WireError::MissingField("validator_update.power"))?,
    })
}

fn decode_ed25519_public_key(bytes: &[u8]) -> Result<[u8; 32], WireError> {
    let mut reader = ProtoReader::new(bytes);
    let field = reader
        .next()?
        .ok_or(WireError::MissingField("validator_update.pub_key.ed25519"))?;
    if field.number != 1 {
        return Err(WireError::UnsupportedField {
            message: "PublicKey",
            field: field.number,
        });
    }
    let key: [u8; 32] = field
        .bytes()?
        .try_into()
        .map_err(|_| WireError::InvalidEd25519KeyLength)?;
    if reader.next()?.is_some() {
        return Err(WireError::DuplicateOrTrailingField(
            "validator_update.pub_key.ed25519",
        ));
    }
    Ok(key)
}

fn decode_prepare_proposal(bytes: &[u8]) -> Result<Request, WireError> {
    let mut reader = ProtoReader::new(bytes);
    let mut maximum_transaction_bytes = None;
    let mut transactions = Vec::new();
    let mut height = None;
    let mut next_validators_hash = None;
    while let Some(field) = reader.next()? {
        match field.number {
            1 => set_once(
                &mut maximum_transaction_bytes,
                field.varint()? as i64,
                "prepare_proposal.max_tx_bytes",
            )?,
            2 => transactions.push(field.bytes()?.to_vec()),
            3 | 4 | 6 | 8 => {
                let _ = field.bytes()?;
            }
            5 => set_once(
                &mut height,
                field.varint()? as i64,
                "prepare_proposal.height",
            )?,
            7 => set_once(
                &mut next_validators_hash,
                decode_hash(field.bytes()?, "prepare_proposal.next_validators_hash")?,
                "prepare_proposal.next_validators_hash",
            )?,
            other => {
                return Err(WireError::UnsupportedField {
                    message: "RequestPrepareProposal",
                    field: other,
                });
            }
        }
    }
    Ok(Request::PrepareProposal {
        maximum_transaction_bytes: maximum_transaction_bytes
            .ok_or(WireError::MissingField("prepare_proposal.max_tx_bytes"))?,
        transactions,
        height: height.ok_or(WireError::MissingField("prepare_proposal.height"))?,
        next_validators_hash: next_validators_hash.ok_or(WireError::MissingField(
            "prepare_proposal.next_validators_hash",
        ))?,
    })
}

fn decode_process_proposal(bytes: &[u8]) -> Result<Request, WireError> {
    let (transactions, block_hash, height, next_validators_hash) =
        decode_decision_request(bytes, "RequestProcessProposal", "process_proposal")?;
    Ok(Request::ProcessProposal {
        transactions,
        block_hash,
        height,
        next_validators_hash,
    })
}

fn decode_finalize_block(bytes: &[u8]) -> Result<Request, WireError> {
    let (transactions, block_hash, height, next_validators_hash) =
        decode_decision_request(bytes, "RequestFinalizeBlock", "finalize_block")?;
    Ok(Request::FinalizeBlock {
        transactions,
        block_hash,
        height,
        next_validators_hash,
    })
}

fn decode_decision_request(
    bytes: &[u8],
    message: &'static str,
    prefix: &'static str,
) -> Result<(Vec<Vec<u8>>, [u8; 32], i64, [u8; 32]), WireError> {
    let mut reader = ProtoReader::new(bytes);
    let mut transactions = Vec::new();
    let mut block_hash = None;
    let mut height = None;
    let mut next_validators_hash = None;
    while let Some(field) = reader.next()? {
        match field.number {
            1 => transactions.push(field.bytes()?.to_vec()),
            2 | 3 | 6 | 8 => {
                let _ = field.bytes()?;
            }
            4 => set_once(
                &mut block_hash,
                decode_hash(field.bytes()?, "decision.hash")?,
                "decision.hash",
            )?,
            5 => set_once(&mut height, field.varint()? as i64, "decision.height")?,
            7 => set_once(
                &mut next_validators_hash,
                decode_hash(field.bytes()?, "decision.next_validators_hash")?,
                "decision.next_validators_hash",
            )?,
            other => {
                return Err(WireError::UnsupportedField {
                    message,
                    field: other,
                });
            }
        }
    }
    let field = match prefix {
        "process_proposal" => "process_proposal",
        "finalize_block" => "finalize_block",
        _ => unreachable!("only fixed decoder prefixes are used"),
    };
    Ok((
        transactions,
        block_hash.ok_or(WireError::MissingField(match field {
            "process_proposal" => "process_proposal.hash",
            _ => "finalize_block.hash",
        }))?,
        height.ok_or(WireError::MissingField(match field {
            "process_proposal" => "process_proposal.height",
            _ => "finalize_block.height",
        }))?,
        next_validators_hash.ok_or(WireError::MissingField(match field {
            "process_proposal" => "process_proposal.next_validators_hash",
            _ => "finalize_block.next_validators_hash",
        }))?,
    ))
}

fn encode_response(response: &Response) -> Vec<u8> {
    let (field, message) = match response {
        Response::Exception(error) => (RESPONSE_EXCEPTION, message_string(1, error)),
        Response::Echo(message) => (RESPONSE_ECHO, message_string(1, message)),
        Response::Flush => (RESPONSE_FLUSH, Vec::new()),
        Response::Info(info) => (RESPONSE_INFO, encode_info(*info)),
        Response::InitChain => (RESPONSE_INIT_CHAIN, Vec::new()),
        Response::QueryUnavailable => {
            let mut message = Vec::new();
            write_varint_field(1, 1, &mut message);
            (RESPONSE_QUERY, message)
        }
        Response::CheckTx(result) => (RESPONSE_CHECK_TX, encode_check_tx(*result)),
        Response::Commit => (RESPONSE_COMMIT, Vec::new()),
        Response::ListSnapshots => (RESPONSE_LIST_SNAPSHOTS, Vec::new()),
        Response::OfferSnapshotAbort => {
            let mut message = Vec::new();
            write_varint_field(1, 2, &mut message);
            (RESPONSE_OFFER_SNAPSHOT, message)
        }
        Response::LoadSnapshotChunk => (RESPONSE_LOAD_SNAPSHOT_CHUNK, Vec::new()),
        Response::ApplySnapshotChunkAbort => {
            let mut message = Vec::new();
            write_varint_field(1, 2, &mut message);
            (RESPONSE_APPLY_SNAPSHOT_CHUNK, message)
        }
        Response::PrepareProposal(transactions) => {
            let mut message = Vec::new();
            for transaction in transactions {
                write_bytes_field(1, transaction, &mut message);
            }
            (RESPONSE_PREPARE_PROPOSAL, message)
        }
        Response::ProcessProposal(status) => {
            let mut message = Vec::new();
            write_varint_field(
                1,
                match status {
                    ProposalStatus::Accept => 1,
                    ProposalStatus::Reject => 2,
                },
                &mut message,
            );
            (RESPONSE_PROCESS_PROPOSAL, message)
        }
        Response::ExtendVote => (RESPONSE_EXTEND_VOTE, Vec::new()),
        Response::VerifyVoteExtensionReject => {
            let mut message = Vec::new();
            write_varint_field(1, 2, &mut message);
            (RESPONSE_VERIFY_VOTE_EXTENSION, message)
        }
        Response::FinalizeBlock(result) => (RESPONSE_FINALIZE_BLOCK, encode_finalize(result)),
    };
    let mut output = Vec::with_capacity(message.len() + 6);
    write_bytes_field(field, &message, &mut output);
    output
}

fn encode_info(info: AppInfo) -> Vec<u8> {
    let mut message = Vec::new();
    write_string_field(1, "noxis-protocol/0.1", &mut message);
    if info.last_block_height != 0 {
        write_varint_field(4, info.last_block_height as u64, &mut message);
    }
    if let Some(hash) = info.app_hash {
        write_bytes_field(5, &hash.0, &mut message);
    }
    message
}

fn encode_check_tx(result: CheckTxResult) -> Vec<u8> {
    let mut message = Vec::new();
    if !result.accepted {
        write_varint_field(1, result.code as u64, &mut message);
    }
    message
}

fn encode_finalize(result: &FinalizeBlockResult) -> Vec<u8> {
    let mut message = Vec::new();
    for transaction in &result.transaction_results {
        let mut transaction_result = Vec::new();
        if transaction.code != 0 {
            write_varint_field(1, transaction.code as u64, &mut transaction_result);
        }
        write_bytes_field(2, &transaction_result, &mut message);
    }
    write_bytes_field(5, &result.app_hash.0, &mut message);
    message
}

fn message_string(field: u32, value: &str) -> Vec<u8> {
    let mut message = Vec::new();
    write_string_field(field, value, &mut message);
    message
}

fn validate_ignored_message(bytes: &[u8], message: &'static str) -> Result<(), WireError> {
    let mut reader = ProtoReader::new(bytes);
    while let Some(field) = reader.next()? {
        match field.wire_type {
            WireType::Varint => {
                let _ = field.varint()?;
            }
            WireType::Bytes => {
                let _ = field.bytes()?;
            }
        }
    }
    if bytes.len() > MAX_ABCI_FRAME_BYTES {
        return Err(WireError::MessageTooLarge {
            actual: bytes.len(),
            maximum: MAX_ABCI_FRAME_BYTES,
        });
    }
    let _ = message;
    Ok(())
}

fn require_empty(bytes: &[u8], message: &'static str) -> Result<(), WireError> {
    if bytes.is_empty() {
        Ok(())
    } else {
        Err(WireError::UnexpectedMessageBytes(message))
    }
}

fn decode_hash(bytes: &[u8], field: &'static str) -> Result<[u8; 32], WireError> {
    bytes.try_into().map_err(|_| WireError::InvalidHashLength {
        field,
        actual: bytes.len(),
    })
}

fn decode_utf8(bytes: &[u8], field: &'static str) -> Result<String, WireError> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| WireError::InvalidUtf8(field))
}

fn set_once<T>(target: &mut Option<T>, value: T, field: &'static str) -> Result<(), WireError> {
    if target.replace(value).is_some() {
        return Err(WireError::DuplicateOrTrailingField(field));
    }
    Ok(())
}

fn read_frame(reader: &mut impl Read) -> Result<Option<Vec<u8>>, WireError> {
    let Some(length) = read_stream_uvarint(reader)? else {
        return Ok(None);
    };
    let length = usize::try_from(length).map_err(|_| WireError::FrameLengthOverflow)?;
    if length > MAX_ABCI_FRAME_BYTES {
        return Err(WireError::MessageTooLarge {
            actual: length,
            maximum: MAX_ABCI_FRAME_BYTES,
        });
    }
    let mut bytes = vec![0; length];
    reader
        .read_exact(&mut bytes)
        .map_err(|source| WireError::Io {
            operation: "read ABCI frame payload",
            source,
        })?;
    Ok(Some(bytes))
}

fn write_frame(writer: &mut impl Write, bytes: &[u8]) -> Result<(), WireError> {
    if bytes.len() > MAX_ABCI_FRAME_BYTES {
        return Err(WireError::MessageTooLarge {
            actual: bytes.len(),
            maximum: MAX_ABCI_FRAME_BYTES,
        });
    }
    let mut prefix = Vec::with_capacity(10);
    write_uvarint(bytes.len() as u64, &mut prefix);
    writer.write_all(&prefix).map_err(|source| WireError::Io {
        operation: "write ABCI frame length",
        source,
    })?;
    writer.write_all(bytes).map_err(|source| WireError::Io {
        operation: "write ABCI frame payload",
        source,
    })?;
    writer.flush().map_err(|source| WireError::Io {
        operation: "flush ABCI response",
        source,
    })
}

fn read_stream_uvarint(reader: &mut impl Read) -> Result<Option<u64>, WireError> {
    let mut value = 0_u64;
    for index in 0..10 {
        let mut byte = [0_u8; 1];
        match reader.read(&mut byte) {
            Ok(0) if index == 0 => return Ok(None),
            Ok(0) => return Err(WireError::TruncatedLengthPrefix),
            Ok(_) => {}
            Err(source) => {
                return Err(WireError::Io {
                    operation: "read ABCI frame length",
                    source,
                });
            }
        }
        let current = byte[0];
        if index == 9 && current > 1 {
            return Err(WireError::InvalidVarint);
        }
        value |= u64::from(current & 0x7f) << (index * 7);
        if current & 0x80 == 0 {
            if uvarint_width(value) != index + 1 {
                return Err(WireError::NonCanonicalVarint);
            }
            return Ok(Some(value));
        }
    }
    Err(WireError::InvalidVarint)
}

struct ProtoReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> ProtoReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn next(&mut self) -> Result<Option<ProtoField<'a>>, WireError> {
        if self.offset == self.bytes.len() {
            return Ok(None);
        }
        let key = self.read_uvarint()?;
        let number = u32::try_from(key >> 3).map_err(|_| WireError::InvalidFieldKey)?;
        if number == 0 {
            return Err(WireError::InvalidFieldKey);
        }
        let wire_type = match key & 0x07 {
            0 => WireType::Varint,
            2 => WireType::Bytes,
            _ => return Err(WireError::UnsupportedWireType(key & 0x07)),
        };
        let value = match wire_type {
            WireType::Varint => ProtoValue::Varint(self.read_uvarint()?),
            WireType::Bytes => {
                let length = usize::try_from(self.read_uvarint()?)
                    .map_err(|_| WireError::FrameLengthOverflow)?;
                let end = self
                    .offset
                    .checked_add(length)
                    .ok_or(WireError::FrameLengthOverflow)?;
                let bytes = self
                    .bytes
                    .get(self.offset..end)
                    .ok_or(WireError::TruncatedMessage)?;
                self.offset = end;
                ProtoValue::Bytes(bytes)
            }
        };
        Ok(Some(ProtoField {
            number,
            wire_type,
            value,
        }))
    }

    fn read_uvarint(&mut self) -> Result<u64, WireError> {
        let start = self.offset;
        let mut value = 0_u64;
        for index in 0..10 {
            let byte = *self
                .bytes
                .get(self.offset)
                .ok_or(WireError::TruncatedMessage)?;
            self.offset += 1;
            if index == 9 && byte > 1 {
                return Err(WireError::InvalidVarint);
            }
            value |= u64::from(byte & 0x7f) << (index * 7);
            if byte & 0x80 == 0 {
                if uvarint_width(value) != index + 1 {
                    return Err(WireError::NonCanonicalVarint);
                }
                return Ok(value);
            }
        }
        let _ = start;
        Err(WireError::InvalidVarint)
    }
}

#[derive(Clone, Copy)]
struct ProtoField<'a> {
    number: u32,
    wire_type: WireType,
    value: ProtoValue<'a>,
}

impl<'a> ProtoField<'a> {
    fn varint(self) -> Result<u64, WireError> {
        match self.value {
            ProtoValue::Varint(value) => Ok(value),
            ProtoValue::Bytes(_) => Err(WireError::UnexpectedWireType {
                field: self.number,
                expected: WireType::Varint,
                actual: self.wire_type,
            }),
        }
    }

    fn bytes(self) -> Result<&'a [u8], WireError> {
        match self.value {
            ProtoValue::Bytes(value) => Ok(value),
            ProtoValue::Varint(_) => Err(WireError::UnexpectedWireType {
                field: self.number,
                expected: WireType::Bytes,
                actual: self.wire_type,
            }),
        }
    }
}

#[derive(Clone, Copy)]
enum ProtoValue<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireType {
    Varint,
    Bytes,
}

fn write_varint_field(number: u32, value: u64, output: &mut Vec<u8>) {
    write_uvarint(u64::from(number << 3), output);
    write_uvarint(value, output);
}

fn write_bytes_field(number: u32, bytes: &[u8], output: &mut Vec<u8>) {
    write_uvarint(u64::from((number << 3) | 2), output);
    write_uvarint(bytes.len() as u64, output);
    output.extend_from_slice(bytes);
}

fn write_string_field(number: u32, value: &str, output: &mut Vec<u8>) {
    write_bytes_field(number, value.as_bytes(), output);
}

fn write_uvarint(mut value: u64, output: &mut Vec<u8>) {
    while value >= 0x80 {
        output.push((value as u8) | 0x80);
        value >>= 7;
    }
    output.push(value as u8);
}

fn uvarint_width(mut value: u64) -> usize {
    let mut width = 1;
    while value >= 0x80 {
        value >>= 7;
        width += 1;
    }
    width
}

/// A malformed or unsupported ABCI v0.38 wire frame.
#[derive(Debug)]
pub enum WireError {
    Io {
        operation: &'static str,
        source: io::Error,
    },
    MessageTooLarge {
        actual: usize,
        maximum: usize,
    },
    FrameLengthOverflow,
    TruncatedLengthPrefix,
    TruncatedMessage,
    InvalidVarint,
    NonCanonicalVarint,
    InvalidFieldKey,
    UnsupportedWireType(u64),
    UnexpectedWireType {
        field: u32,
        expected: WireType,
        actual: WireType,
    },
    MissingRequestValue,
    MultipleRequestValues,
    UnsupportedRequest(u32),
    UnsupportedField {
        message: &'static str,
        field: u32,
    },
    MissingField(&'static str),
    DuplicateOrTrailingField(&'static str),
    InvalidUtf8(&'static str),
    InvalidHashLength {
        field: &'static str,
        actual: usize,
    },
    InvalidEd25519KeyLength,
    UnexpectedMessageBytes(&'static str),
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { operation, source } => write!(formatter, "cannot {operation}: {source}"),
            Self::MessageTooLarge { actual, maximum } => {
                write!(
                    formatter,
                    "ABCI frame is {actual} bytes, above maximum {maximum}"
                )
            }
            Self::FrameLengthOverflow => formatter.write_str("ABCI frame length overflows"),
            Self::TruncatedLengthPrefix => {
                formatter.write_str("truncated ABCI frame length prefix")
            }
            Self::TruncatedMessage => formatter.write_str("truncated protobuf message"),
            Self::InvalidVarint => formatter.write_str("invalid protobuf varint"),
            Self::NonCanonicalVarint => formatter.write_str("noncanonical protobuf varint"),
            Self::InvalidFieldKey => formatter.write_str("invalid protobuf field key"),
            Self::UnsupportedWireType(wire_type) => {
                write!(formatter, "unsupported protobuf wire type {wire_type}")
            }
            Self::UnexpectedWireType { field, .. } => {
                write!(formatter, "unexpected wire type for protobuf field {field}")
            }
            Self::MissingRequestValue => formatter.write_str("ABCI request has no value"),
            Self::MultipleRequestValues => formatter.write_str("ABCI request has multiple values"),
            Self::UnsupportedRequest(value) => {
                write!(formatter, "unsupported ABCI request {value}")
            }
            Self::UnsupportedField { message, field } => {
                write!(formatter, "unsupported field {field} in {message}")
            }
            Self::MissingField(field) => write!(formatter, "missing required ABCI field {field}"),
            Self::DuplicateOrTrailingField(field) => {
                write!(formatter, "duplicate or trailing ABCI field {field}")
            }
            Self::InvalidUtf8(field) => write!(formatter, "ABCI field {field} is not UTF-8"),
            Self::InvalidHashLength { field, actual } => {
                write!(
                    formatter,
                    "ABCI field {field} has {actual} bytes; expected 32"
                )
            }
            Self::InvalidEd25519KeyLength => {
                formatter.write_str("ABCI validator Ed25519 key must have 32 bytes")
            }
            Self::UnexpectedMessageBytes(message) => {
                write!(formatter, "ABCI message {message} must be empty")
            }
        }
    }
}

impl std::error::Error for WireError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_and_encodes_a_framed_echo() {
        let request = [0x04, 0x0a, 0x02, 0x0a, 0x00];
        assert_eq!(
            decode_request(&request[1..]).unwrap(),
            Request::Echo(String::new())
        );
        let response = encode_response(&Response::Echo(String::new()));
        assert_eq!(response, [0x12, 0x02, 0x0a, 0x00]);
    }

    #[test]
    fn rejects_an_overlong_varint() {
        assert_eq!(
            decode_request(&[0x8a, 0x00]),
            Err(WireError::NonCanonicalVarint)
        );
    }
}
