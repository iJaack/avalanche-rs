use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

const CODEC_VERSION: u16 = 0;

const TYPE_SECP_TRANSFER_INPUT: u32 = 5;
const TYPE_SECP_TRANSFER_OUTPUT: u32 = 7;
const TYPE_SECP_CREDENTIAL: u32 = 9;
const TYPE_SECP_INPUT: u32 = 10;
const TYPE_OUTPUT_OWNERS: u32 = 11;

const TYPE_ADD_VALIDATOR_TX: u32 = 12;
const TYPE_ADD_DELEGATOR_TX: u32 = 14;
const TYPE_CREATE_SUBNET_TX: u32 = 16;
const TYPE_ADVANCE_TIME_TX: u32 = 19;
const TYPE_REWARD_VALIDATOR_TX: u32 = 20;
const TYPE_LOCK_IN: u32 = 21;
const TYPE_LOCK_OUT: u32 = 22;
const TYPE_REMOVE_SUBNET_VALIDATOR_TX: u32 = 23;
const TYPE_ADD_PERMISSIONLESS_VALIDATOR_TX: u32 = 25;
const TYPE_ADD_PERMISSIONLESS_DELEGATOR_TX: u32 = 26;
const TYPE_SIGNER_EMPTY: u32 = 27;
const TYPE_SIGNER_PROOF_OF_POSSESSION: u32 = 28;
const TYPE_TRANSFER_SUBNET_OWNERSHIP_TX: u32 = 33;
const TYPE_BASE_TX: u32 = 34;

const TYPE_APRICOT_PROPOSAL_BLOCK: u32 = 0;
const TYPE_APRICOT_ABORT_BLOCK: u32 = 1;
const TYPE_APRICOT_COMMIT_BLOCK: u32 = 2;
const TYPE_APRICOT_STANDARD_BLOCK: u32 = 3;
const TYPE_APRICOT_ATOMIC_BLOCK: u32 = 4;
const TYPE_BANFF_PROPOSAL_BLOCK: u32 = 29;
const TYPE_BANFF_ABORT_BLOCK: u32 = 30;
const TYPE_BANFF_COMMIT_BLOCK: u32 = 31;
const TYPE_BANFF_STANDARD_BLOCK: u32 = 32;

const SECP256K1_SIGNATURE_LEN: usize = 65;
const BLS_PUBLIC_KEY_LEN: usize = 48;
const BLS_SIGNATURE_LEN: usize = 96;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformStakerKind {
    Validator,
    Delegator,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformStakeOutput {
    pub asset_id: [u8; 32],
    pub amount: u64,
    pub addresses: Vec<[u8; 20]>,
    pub raw_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformStakeTxSummary {
    pub kind: PlatformStakerKind,
    pub outputs: Vec<PlatformStakeOutput>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformInputRef {
    pub tx_id: [u8; 32],
    pub output_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformOwnedOutput {
    pub asset_id: [u8; 32],
    pub amount: u64,
    pub owner_locktime: u64,
    pub stakeable_locktime: Option<u64>,
    pub addresses: Vec<[u8; 20]>,
    pub transferable_raw_bytes: Vec<u8>,
    pub output_raw_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformTxLedgerSummary {
    pub kind: Option<PlatformStakerKind>,
    pub inputs: Vec<PlatformInputRef>,
    pub outputs: Vec<PlatformOwnedOutput>,
    pub stake_outputs: Vec<PlatformOwnedOutput>,
    pub reward_validator_tx_id: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformTxSummary {
    Stake(PlatformStakeTxSummary),
    RewardValidator { tx_id: [u8; 32] },
    Other,
}

pub fn parse_platform_tx_json(bytes: &[u8]) -> Result<Value, String> {
    let (tx, consumed) = parse_platform_tx_prefix(bytes)?;
    if consumed != bytes.len() {
        return Err(format!(
            "unexpected trailing bytes: {}",
            bytes.len().saturating_sub(consumed)
        ));
    }
    Ok(tx)
}

pub fn extract_platform_tx_bytes_from_block(raw: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if raw.len() < 6 {
        return Err(format!(
            "P-Chain block too short: {} bytes (need >=6 for typeID)",
            raw.len()
        ));
    }

    let type_id = u32::from_be_bytes(raw[2..6].try_into().unwrap());
    match type_id {
        TYPE_APRICOT_ABORT_BLOCK
        | TYPE_APRICOT_COMMIT_BLOCK
        | TYPE_BANFF_ABORT_BLOCK
        | TYPE_BANFF_COMMIT_BLOCK => Ok(Vec::new()),
        TYPE_APRICOT_STANDARD_BLOCK => extract_counted_txs(raw, 46),
        TYPE_BANFF_STANDARD_BLOCK => extract_counted_txs(raw, 54),
        TYPE_APRICOT_PROPOSAL_BLOCK | TYPE_APRICOT_ATOMIC_BLOCK => extract_trailing_tx(raw, 46),
        TYPE_BANFF_PROPOSAL_BLOCK => extract_banff_proposal_txs(raw),
        other => Err(format!("unsupported platform block type {}", other)),
    }
}

pub fn summarize_platform_tx(bytes: &[u8]) -> Result<PlatformTxSummary, String> {
    let mut cursor = Cursor::new(bytes);
    let version = cursor.read_u16()?;
    if version != CODEC_VERSION {
        return Err(format!("unsupported codec version {}", version));
    }

    match cursor.read_u32()? {
        TYPE_ADD_VALIDATOR_TX => {
            parse_primary_network_staker_summary(&mut cursor, PlatformStakerKind::Validator)
        }
        TYPE_ADD_DELEGATOR_TX => {
            parse_primary_network_staker_summary(&mut cursor, PlatformStakerKind::Delegator)
        }
        TYPE_ADD_PERMISSIONLESS_VALIDATOR_TX => {
            parse_permissionless_staker_summary(&mut cursor, PlatformStakerKind::Validator)
        }
        TYPE_ADD_PERMISSIONLESS_DELEGATOR_TX => {
            parse_permissionless_staker_summary(&mut cursor, PlatformStakerKind::Delegator)
        }
        TYPE_REWARD_VALIDATOR_TX => Ok(PlatformTxSummary::RewardValidator {
            tx_id: cursor.read_array::<32>()?,
        }),
        _ => Ok(PlatformTxSummary::Other),
    }
}

pub fn summarize_platform_tx_ledger(bytes: &[u8]) -> Result<PlatformTxLedgerSummary, String> {
    let mut cursor = Cursor::new(bytes);
    let version = cursor.read_u16()?;
    if version != CODEC_VERSION {
        return Err(format!("unsupported codec version {}", version));
    }

    match cursor.read_u32()? {
        TYPE_BASE_TX => parse_generic_base_tx_ledger_summary(&mut cursor, None),
        TYPE_CREATE_SUBNET_TX => {
            let (outputs, inputs) = parse_base_tx_ledger(&mut cursor)?;
            let _ = parse_owner_interface(&mut cursor)?;
            Ok(PlatformTxLedgerSummary {
                kind: None,
                inputs,
                outputs,
                stake_outputs: Vec::new(),
                reward_validator_tx_id: None,
            })
        }
        TYPE_REMOVE_SUBNET_VALIDATOR_TX => {
            let (outputs, inputs) = parse_base_tx_ledger(&mut cursor)?;
            cursor.read_array::<20>()?;
            cursor.read_array::<32>()?;
            let _ = parse_verifiable(&mut cursor)?;
            Ok(PlatformTxLedgerSummary {
                kind: None,
                inputs,
                outputs,
                stake_outputs: Vec::new(),
                reward_validator_tx_id: None,
            })
        }
        TYPE_TRANSFER_SUBNET_OWNERSHIP_TX => {
            let (outputs, inputs) = parse_base_tx_ledger(&mut cursor)?;
            cursor.read_array::<32>()?;
            let _ = parse_verifiable(&mut cursor)?;
            let _ = parse_owner_interface(&mut cursor)?;
            Ok(PlatformTxLedgerSummary {
                kind: None,
                inputs,
                outputs,
                stake_outputs: Vec::new(),
                reward_validator_tx_id: None,
            })
        }
        TYPE_ADD_VALIDATOR_TX => {
            parse_staker_tx_ledger_summary(&mut cursor, PlatformStakerKind::Validator)
        }
        TYPE_ADD_DELEGATOR_TX => {
            parse_staker_tx_ledger_summary(&mut cursor, PlatformStakerKind::Delegator)
        }
        TYPE_ADD_PERMISSIONLESS_VALIDATOR_TX => {
            parse_permissionless_tx_ledger_summary(&mut cursor, PlatformStakerKind::Validator)
        }
        TYPE_ADD_PERMISSIONLESS_DELEGATOR_TX => {
            parse_permissionless_tx_ledger_summary(&mut cursor, PlatformStakerKind::Delegator)
        }
        TYPE_REWARD_VALIDATOR_TX => Ok(PlatformTxLedgerSummary {
            kind: None,
            inputs: Vec::new(),
            outputs: Vec::new(),
            stake_outputs: Vec::new(),
            reward_validator_tx_id: Some(cursor.read_array::<32>()?),
        }),
        TYPE_ADVANCE_TIME_TX => Ok(PlatformTxLedgerSummary {
            kind: None,
            inputs: Vec::new(),
            outputs: Vec::new(),
            stake_outputs: Vec::new(),
            reward_validator_tx_id: None,
        }),
        other => Err(format!("unsupported platform tx type {}", other)),
    }
}

fn parse_platform_tx_prefix(bytes: &[u8]) -> Result<(Value, usize), String> {
    let mut cursor = Cursor::new(bytes);
    let version = cursor.read_u16()?;
    if version != CODEC_VERSION {
        return Err(format!("unsupported codec version {}", version));
    }

    let unsigned_tx = parse_unsigned_tx(&mut cursor)?;
    let credentials = if cursor.remaining() == 0 {
        Value::Null
    } else {
        parse_credentials(&mut cursor)?
    };
    let consumed = cursor.pos;

    let mut tx_id = [0u8; 32];
    tx_id.copy_from_slice(&Sha256::digest(&bytes[..consumed]));

    Ok((
        json!({
            "unsignedTx": unsigned_tx,
            "credentials": credentials,
            "id": cb58_encode(&tx_id),
        }),
        consumed,
    ))
}

fn extract_counted_txs(raw: &[u8], count_offset: usize) -> Result<Vec<Vec<u8>>, String> {
    if raw.len() < count_offset + 4 {
        return Err(format!(
            "P-Chain block too short: {} bytes (need >= {} for tx count)",
            raw.len(),
            count_offset + 4
        ));
    }

    let count =
        u32::from_be_bytes(raw[count_offset..count_offset + 4].try_into().unwrap()) as usize;
    let mut pos = count_offset + 4;
    let mut txs = Vec::with_capacity(count);
    for _ in 0..count {
        let (_, consumed) = parse_platform_tx_prefix(&raw[pos..])?;
        txs.push(raw[pos..pos + consumed].to_vec());
        pos += consumed;
    }
    Ok(txs)
}

fn extract_trailing_tx(raw: &[u8], tx_offset: usize) -> Result<Vec<Vec<u8>>, String> {
    if raw.len() <= tx_offset {
        return Ok(Vec::new());
    }

    let (_, consumed) = parse_platform_tx_prefix(&raw[tx_offset..])?;
    let end = tx_offset + consumed;
    if end != raw.len() {
        return Err(format!(
            "unexpected trailing block bytes after tx: {}",
            raw.len().saturating_sub(end)
        ));
    }
    Ok(vec![raw[tx_offset..end].to_vec()])
}

fn extract_banff_proposal_txs(raw: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if raw.len() < 18 {
        return Err(format!(
            "Banff proposal block too short: {} bytes (need >=18)",
            raw.len()
        ));
    }

    let decision_count = u32::from_be_bytes(raw[14..18].try_into().unwrap()) as usize;
    let mut pos = 18;
    let mut txs = Vec::with_capacity(decision_count + 1);
    for _ in 0..decision_count {
        let (_, consumed) = parse_platform_tx_prefix(&raw[pos..])?;
        txs.push(raw[pos..pos + consumed].to_vec());
        pos += consumed;
    }

    if raw.len() < pos + 40 {
        return Err(format!(
            "Banff proposal block missing common block fields at offset {}",
            pos
        ));
    }
    pos += 40;

    let (_, consumed) = parse_platform_tx_prefix(&raw[pos..])?;
    let end = pos + consumed;
    if end != raw.len() {
        return Err(format!(
            "unexpected trailing block bytes after proposal tx: {}",
            raw.len().saturating_sub(end)
        ));
    }
    txs.push(raw[pos..end].to_vec());
    Ok(txs)
}

fn parse_generic_base_tx_ledger_summary(
    cursor: &mut Cursor<'_>,
    kind: Option<PlatformStakerKind>,
) -> Result<PlatformTxLedgerSummary, String> {
    let (outputs, inputs) = parse_base_tx_ledger(cursor)?;
    Ok(PlatformTxLedgerSummary {
        kind,
        inputs,
        outputs,
        stake_outputs: Vec::new(),
        reward_validator_tx_id: None,
    })
}

fn parse_primary_network_staker_summary(
    cursor: &mut Cursor<'_>,
    kind: PlatformStakerKind,
) -> Result<PlatformTxSummary, String> {
    skip_base_tx_fields(cursor)?;
    skip_validator(cursor)?;
    let outputs = parse_stake_outputs_summary(cursor)?;
    Ok(PlatformTxSummary::Stake(PlatformStakeTxSummary {
        kind,
        outputs,
    }))
}

fn parse_permissionless_staker_summary(
    cursor: &mut Cursor<'_>,
    kind: PlatformStakerKind,
) -> Result<PlatformTxSummary, String> {
    skip_base_tx_fields(cursor)?;
    skip_validator(cursor)?;
    let subnet_id = cursor.read_array::<32>()?;
    if kind == PlatformStakerKind::Validator {
        skip_signer_interface(cursor)?;
    }
    let outputs = parse_stake_outputs_summary(cursor)?;
    if subnet_id == [0u8; 32] {
        Ok(PlatformTxSummary::Stake(PlatformStakeTxSummary {
            kind,
            outputs,
        }))
    } else {
        Ok(PlatformTxSummary::Other)
    }
}

fn parse_staker_tx_ledger_summary(
    cursor: &mut Cursor<'_>,
    kind: PlatformStakerKind,
) -> Result<PlatformTxLedgerSummary, String> {
    let (outputs, inputs) = parse_base_tx_ledger(cursor)?;
    skip_validator(cursor)?;
    let stake_outputs = parse_owned_transferable_outputs(cursor)?;
    let _ = parse_owner_interface(cursor)?;
    if kind == PlatformStakerKind::Validator {
        cursor.read_u32()?;
    }
    Ok(PlatformTxLedgerSummary {
        kind: Some(kind),
        inputs,
        outputs,
        stake_outputs,
        reward_validator_tx_id: None,
    })
}

fn parse_permissionless_tx_ledger_summary(
    cursor: &mut Cursor<'_>,
    kind: PlatformStakerKind,
) -> Result<PlatformTxLedgerSummary, String> {
    let (outputs, inputs) = parse_base_tx_ledger(cursor)?;
    skip_validator(cursor)?;
    cursor.read_array::<32>()?;
    if kind == PlatformStakerKind::Validator {
        skip_signer_interface(cursor)?;
    }
    let stake_outputs = parse_owned_transferable_outputs(cursor)?;
    let _ = parse_owner_interface(cursor)?;
    if kind == PlatformStakerKind::Validator {
        let _ = parse_owner_interface(cursor)?;
        cursor.read_u32()?;
    }
    Ok(PlatformTxLedgerSummary {
        kind: Some(kind),
        inputs,
        outputs,
        stake_outputs,
        reward_validator_tx_id: None,
    })
}

fn parse_base_tx_ledger(
    cursor: &mut Cursor<'_>,
) -> Result<(Vec<PlatformOwnedOutput>, Vec<PlatformInputRef>), String> {
    cursor.read_u32()?;
    cursor.read_array::<32>()?;

    let outputs_len = cursor.read_u32()? as usize;
    let mut outputs = Vec::with_capacity(outputs_len);
    for _ in 0..outputs_len {
        if let Some(output) = parse_owned_transferable_output(cursor)? {
            outputs.push(output);
        }
    }

    let inputs_len = cursor.read_u32()? as usize;
    let mut inputs = Vec::with_capacity(inputs_len);
    for _ in 0..inputs_len {
        inputs.push(parse_input_ref(cursor)?);
    }

    let memo_len = cursor.read_u32()? as usize;
    cursor.read_exact(memo_len)?;
    Ok((outputs, inputs))
}

fn skip_base_tx_fields(cursor: &mut Cursor<'_>) -> Result<(), String> {
    cursor.read_u32()?;
    cursor.read_array::<32>()?;

    let outputs_len = cursor.read_u32()? as usize;
    for _ in 0..outputs_len {
        parse_transferable_output(cursor)?;
    }

    let inputs_len = cursor.read_u32()? as usize;
    for _ in 0..inputs_len {
        parse_transferable_input(cursor)?;
    }

    let memo_len = cursor.read_u32()? as usize;
    cursor.read_exact(memo_len)?;
    Ok(())
}

fn skip_validator(cursor: &mut Cursor<'_>) -> Result<(), String> {
    cursor.read_array::<20>()?;
    cursor.read_u64()?;
    cursor.read_u64()?;
    cursor.read_u64()?;
    Ok(())
}

fn skip_signer_interface(cursor: &mut Cursor<'_>) -> Result<(), String> {
    match cursor.read_u32()? {
        TYPE_SIGNER_EMPTY => Ok(()),
        TYPE_SIGNER_PROOF_OF_POSSESSION => {
            cursor.read_exact(BLS_PUBLIC_KEY_LEN)?;
            cursor.read_exact(BLS_SIGNATURE_LEN)?;
            Ok(())
        }
        other => Err(format!("unsupported signer type {}", other)),
    }
}

fn parse_stake_outputs_summary(
    cursor: &mut Cursor<'_>,
) -> Result<Vec<PlatformStakeOutput>, String> {
    let outputs_len = cursor.read_u32()? as usize;
    let mut outputs = Vec::with_capacity(outputs_len);
    for _ in 0..outputs_len {
        if let Some(output) = parse_stake_output_summary(cursor)? {
            outputs.push(output);
        }
    }
    Ok(outputs)
}

fn parse_owned_transferable_outputs(
    cursor: &mut Cursor<'_>,
) -> Result<Vec<PlatformOwnedOutput>, String> {
    let outputs_len = cursor.read_u32()? as usize;
    let mut outputs = Vec::with_capacity(outputs_len);
    for _ in 0..outputs_len {
        if let Some(output) = parse_owned_transferable_output(cursor)? {
            outputs.push(output);
        }
    }
    Ok(outputs)
}

fn parse_stake_output_summary(
    cursor: &mut Cursor<'_>,
) -> Result<Option<PlatformStakeOutput>, String> {
    let start = cursor.pos;
    let asset_id = cursor.read_array::<32>()?;
    let output_type = cursor.read_u32()?;
    let Some((amount, addresses)) = parse_stake_output_details(cursor, output_type)? else {
        return Ok(None);
    };
    let end = cursor.pos;
    Ok(Some(PlatformStakeOutput {
        asset_id,
        amount,
        addresses,
        raw_bytes: cursor.bytes[start..end].to_vec(),
    }))
}

fn parse_owned_transferable_output(
    cursor: &mut Cursor<'_>,
) -> Result<Option<PlatformOwnedOutput>, String> {
    let transferable_start = cursor.pos;
    let asset_id = cursor.read_array::<32>()?;
    let output_start = cursor.pos;
    let output_type = cursor.read_u32()?;
    let Some((amount, owner_locktime, stakeable_locktime, addresses)) =
        parse_owned_output_details(cursor, output_type)?
    else {
        return Ok(None);
    };
    let end = cursor.pos;
    Ok(Some(PlatformOwnedOutput {
        asset_id,
        amount,
        owner_locktime,
        stakeable_locktime,
        addresses,
        transferable_raw_bytes: cursor.bytes[transferable_start..end].to_vec(),
        output_raw_bytes: cursor.bytes[output_start..end].to_vec(),
    }))
}

fn parse_stake_output_details(
    cursor: &mut Cursor<'_>,
    type_id: u32,
) -> Result<Option<(u64, Vec<[u8; 20]>)>, String> {
    match type_id {
        TYPE_SECP_TRANSFER_OUTPUT => {
            let amount = cursor.read_u64()?;
            let (_, _, addresses) = parse_output_owners_raw(cursor)?;
            Ok(Some((amount, addresses)))
        }
        TYPE_LOCK_OUT => {
            cursor.read_u64()?;
            let inner_type = cursor.read_u32()?;
            parse_stake_output_details(cursor, inner_type)
        }
        other => Err(format!("unsupported output type {}", other)),
    }
}

fn parse_owned_output_details(
    cursor: &mut Cursor<'_>,
    type_id: u32,
) -> Result<Option<(u64, u64, Option<u64>, Vec<[u8; 20]>)>, String> {
    match type_id {
        TYPE_SECP_TRANSFER_OUTPUT => {
            let amount = cursor.read_u64()?;
            let (owner_locktime, _, addresses) = parse_output_owners_raw(cursor)?;
            Ok(Some((amount, owner_locktime, None, addresses)))
        }
        TYPE_LOCK_OUT => {
            let stakeable_locktime = cursor.read_u64()?;
            let inner_type = cursor.read_u32()?;
            let Some((amount, owner_locktime, _, addresses)) =
                parse_owned_output_details(cursor, inner_type)?
            else {
                return Ok(None);
            };
            Ok(Some((
                amount,
                owner_locktime,
                Some(stakeable_locktime),
                addresses,
            )))
        }
        other => Err(format!("unsupported output type {}", other)),
    }
}

fn parse_output_owners_raw(cursor: &mut Cursor<'_>) -> Result<(u64, u32, Vec<[u8; 20]>), String> {
    let locktime = cursor.read_u64()?;
    let threshold = cursor.read_u32()?;
    let addr_count = cursor.read_u32()? as usize;
    let mut addrs = Vec::with_capacity(addr_count);
    for _ in 0..addr_count {
        addrs.push(cursor.read_array::<20>()?);
    }
    Ok((locktime, threshold, addrs))
}

fn parse_input_ref(cursor: &mut Cursor<'_>) -> Result<PlatformInputRef, String> {
    let tx_id = cursor.read_array::<32>()?;
    let output_index = cursor.read_u32()?;
    cursor.read_array::<32>()?;
    let input_type = cursor.read_u32()?;
    skip_input(cursor, input_type)?;
    Ok(PlatformInputRef {
        tx_id,
        output_index,
    })
}

fn skip_input(cursor: &mut Cursor<'_>, type_id: u32) -> Result<(), String> {
    match type_id {
        TYPE_SECP_TRANSFER_INPUT => {
            cursor.read_u64()?;
            skip_secp_input(cursor)
        }
        TYPE_LOCK_IN => {
            cursor.read_u64()?;
            let inner_type = cursor.read_u32()?;
            skip_input(cursor, inner_type)
        }
        TYPE_SECP_INPUT => skip_secp_input(cursor),
        other => Err(format!("unsupported input type {}", other)),
    }
}

fn skip_secp_input(cursor: &mut Cursor<'_>) -> Result<(), String> {
    let sig_count = cursor.read_u32()? as usize;
    cursor.read_exact(sig_count * 4)?;
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], String> {
        if self.remaining() < len {
            return Err(format!(
                "unexpected end of input at offset {} (need {} more bytes)",
                self.pos, len
            ));
        }
        let start = self.pos;
        self.pos += len;
        Ok(&self.bytes[start..self.pos])
    }

    fn read_u16(&mut self) -> Result<u16, String> {
        let bytes = self.read_exact(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, String> {
        let bytes = self.read_exact(4)?;
        Ok(u32::from_be_bytes(bytes.try_into().unwrap()))
    }

    fn read_u64(&mut self) -> Result<u64, String> {
        let bytes = self.read_exact(8)?;
        Ok(u64::from_be_bytes(bytes.try_into().unwrap()))
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], String> {
        let bytes = self.read_exact(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn read_bytes(&mut self, len: usize) -> Result<Vec<u8>, String> {
        Ok(self.read_exact(len)?.to_vec())
    }
}

fn parse_unsigned_tx(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    match cursor.read_u32()? {
        TYPE_ADD_VALIDATOR_TX => parse_add_validator_tx(cursor),
        TYPE_ADD_DELEGATOR_TX => parse_add_delegator_tx(cursor),
        TYPE_CREATE_SUBNET_TX => parse_create_subnet_tx(cursor),
        TYPE_ADVANCE_TIME_TX => parse_advance_time_tx(cursor),
        TYPE_REWARD_VALIDATOR_TX => parse_reward_validator_tx(cursor),
        TYPE_REMOVE_SUBNET_VALIDATOR_TX => parse_remove_subnet_validator_tx(cursor),
        TYPE_ADD_PERMISSIONLESS_VALIDATOR_TX => parse_add_permissionless_validator_tx(cursor),
        TYPE_ADD_PERMISSIONLESS_DELEGATOR_TX => parse_add_permissionless_delegator_tx(cursor),
        TYPE_TRANSFER_SUBNET_OWNERSHIP_TX => parse_transfer_subnet_ownership_tx(cursor),
        TYPE_BASE_TX => parse_base_tx(cursor),
        other => Err(format!("unsupported platform tx type {}", other)),
    }
}

fn parse_base_tx_fields(cursor: &mut Cursor<'_>) -> Result<Map<String, Value>, String> {
    let network_id = cursor.read_u32()?;
    let blockchain_id = cursor.read_array::<32>()?;

    let outputs_len = cursor.read_u32()? as usize;
    let mut outputs = Vec::with_capacity(outputs_len);
    for _ in 0..outputs_len {
        outputs.push(parse_transferable_output(cursor)?);
    }

    let inputs_len = cursor.read_u32()? as usize;
    let mut inputs = Vec::with_capacity(inputs_len);
    for _ in 0..inputs_len {
        inputs.push(parse_transferable_input(cursor)?);
    }

    let memo_len = cursor.read_u32()? as usize;
    let memo = cursor.read_bytes(memo_len)?;

    let mut map = Map::new();
    map.insert("networkID".to_string(), json!(network_id));
    map.insert(
        "blockchainID".to_string(),
        Value::String(cb58_encode(&blockchain_id)),
    );
    map.insert("outputs".to_string(), Value::Array(outputs));
    map.insert("inputs".to_string(), Value::Array(inputs));
    map.insert(
        "memo".to_string(),
        Value::String(format!("0x{}", hex::encode(memo))),
    );
    Ok(map)
}

fn parse_base_tx(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    Ok(Value::Object(parse_base_tx_fields(cursor)?))
}

fn parse_validator(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    let node_id = cursor.read_array::<20>()?;
    let start = cursor.read_u64()?;
    let end = cursor.read_u64()?;
    let weight = cursor.read_u64()?;
    Ok(json!({
        "nodeID": node_id_string(&node_id),
        "start": start,
        "end": end,
        "weight": weight,
    }))
}

fn parse_owner_interface(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    match cursor.read_u32()? {
        TYPE_OUTPUT_OWNERS => parse_output_owners(cursor).map(Value::Object),
        other => Err(format!("unsupported owner type {}", other)),
    }
}

fn parse_signer_interface(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    match cursor.read_u32()? {
        TYPE_SIGNER_EMPTY => Ok(json!({})),
        TYPE_SIGNER_PROOF_OF_POSSESSION => {
            let public_key = cursor.read_array::<BLS_PUBLIC_KEY_LEN>()?;
            let proof = cursor.read_array::<BLS_SIGNATURE_LEN>()?;
            Ok(json!({
                "publicKey": format!("0x{}", hex::encode(public_key)),
                "proofOfPossession": format!("0x{}", hex::encode(proof)),
            }))
        }
        other => Err(format!("unsupported signer type {}", other)),
    }
}

fn parse_verifiable(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    match cursor.read_u32()? {
        TYPE_SECP_INPUT => parse_secp_input(cursor),
        TYPE_OUTPUT_OWNERS => parse_output_owners(cursor).map(Value::Object),
        TYPE_SIGNER_EMPTY => Ok(json!({})),
        TYPE_SIGNER_PROOF_OF_POSSESSION => {
            let public_key = cursor.read_array::<BLS_PUBLIC_KEY_LEN>()?;
            let proof = cursor.read_array::<BLS_SIGNATURE_LEN>()?;
            Ok(json!({
                "publicKey": format!("0x{}", hex::encode(public_key)),
                "proofOfPossession": format!("0x{}", hex::encode(proof)),
            }))
        }
        other => Err(format!("unsupported verifiable type {}", other)),
    }
}

fn parse_stake_outputs(cursor: &mut Cursor<'_>) -> Result<Vec<Value>, String> {
    let outputs_len = cursor.read_u32()? as usize;
    let mut outputs = Vec::with_capacity(outputs_len);
    for _ in 0..outputs_len {
        outputs.push(parse_transferable_output(cursor)?);
    }
    Ok(outputs)
}

fn parse_add_validator_tx(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    let mut map = parse_base_tx_fields(cursor)?;
    map.insert("validator".to_string(), parse_validator(cursor)?);
    map.insert(
        "stake".to_string(),
        Value::Array(parse_stake_outputs(cursor)?),
    );
    map.insert("rewardsOwner".to_string(), parse_owner_interface(cursor)?);
    map.insert("shares".to_string(), json!(cursor.read_u32()?));
    Ok(Value::Object(map))
}

fn parse_add_delegator_tx(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    let mut map = parse_base_tx_fields(cursor)?;
    map.insert("validator".to_string(), parse_validator(cursor)?);
    map.insert(
        "stake".to_string(),
        Value::Array(parse_stake_outputs(cursor)?),
    );
    map.insert("rewardsOwner".to_string(), parse_owner_interface(cursor)?);
    Ok(Value::Object(map))
}

fn parse_add_permissionless_validator_tx(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    let mut map = parse_base_tx_fields(cursor)?;
    map.insert("validator".to_string(), parse_validator(cursor)?);
    map.insert(
        "subnetID".to_string(),
        Value::String(cb58_encode(&cursor.read_array::<32>()?)),
    );
    map.insert("signer".to_string(), parse_signer_interface(cursor)?);
    map.insert(
        "stake".to_string(),
        Value::Array(parse_stake_outputs(cursor)?),
    );
    map.insert(
        "validationRewardsOwner".to_string(),
        parse_owner_interface(cursor)?,
    );
    map.insert(
        "delegationRewardsOwner".to_string(),
        parse_owner_interface(cursor)?,
    );
    map.insert("shares".to_string(), json!(cursor.read_u32()?));
    Ok(Value::Object(map))
}

fn parse_add_permissionless_delegator_tx(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    let mut map = parse_base_tx_fields(cursor)?;
    map.insert("validator".to_string(), parse_validator(cursor)?);
    map.insert(
        "subnetID".to_string(),
        Value::String(cb58_encode(&cursor.read_array::<32>()?)),
    );
    map.insert(
        "stake".to_string(),
        Value::Array(parse_stake_outputs(cursor)?),
    );
    map.insert("rewardsOwner".to_string(), parse_owner_interface(cursor)?);
    Ok(Value::Object(map))
}

fn parse_create_subnet_tx(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    let mut map = parse_base_tx_fields(cursor)?;
    map.insert("owner".to_string(), parse_owner_interface(cursor)?);
    Ok(Value::Object(map))
}

fn parse_remove_subnet_validator_tx(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    let mut map = parse_base_tx_fields(cursor)?;
    map.insert(
        "nodeID".to_string(),
        Value::String(node_id_string(&cursor.read_array::<20>()?)),
    );
    map.insert(
        "subnetID".to_string(),
        Value::String(cb58_encode(&cursor.read_array::<32>()?)),
    );
    map.insert("subnetAuthorization".to_string(), parse_verifiable(cursor)?);
    Ok(Value::Object(map))
}

fn parse_transfer_subnet_ownership_tx(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    let mut map = parse_base_tx_fields(cursor)?;
    map.insert(
        "subnetID".to_string(),
        Value::String(cb58_encode(&cursor.read_array::<32>()?)),
    );
    map.insert("subnetAuthorization".to_string(), parse_verifiable(cursor)?);
    map.insert("newOwner".to_string(), parse_owner_interface(cursor)?);
    Ok(Value::Object(map))
}

fn parse_advance_time_tx(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    Ok(json!({
        "time": cursor.read_u64()?,
    }))
}

fn parse_reward_validator_tx(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    Ok(json!({
        "txID": cb58_encode(&cursor.read_array::<32>()?),
    }))
}

fn parse_transferable_output(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    let asset_id = cursor.read_array::<32>()?;
    let output_type = cursor.read_u32()?;
    Ok(json!({
        "assetID": cb58_encode(&asset_id),
        "output": parse_output_by_type(cursor, output_type)?,
    }))
}

fn parse_output_by_type(cursor: &mut Cursor<'_>, type_id: u32) -> Result<Value, String> {
    match type_id {
        TYPE_SECP_TRANSFER_OUTPUT => parse_transfer_output(cursor),
        TYPE_LOCK_OUT => {
            let locktime = cursor.read_u64()?;
            let inner_type = cursor.read_u32()?;
            let inner = parse_output_by_type(cursor, inner_type)?;
            Ok(json!({
                "locktime": locktime,
                "output": inner,
            }))
        }
        other => Err(format!("unsupported output type {}", other)),
    }
}

fn parse_transfer_output(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    let amount = cursor.read_u64()?;
    let mut map = parse_output_owners(cursor)?;
    map.insert("amount".to_string(), json!(amount));
    Ok(Value::Object(map))
}

fn parse_output_owners(cursor: &mut Cursor<'_>) -> Result<Map<String, Value>, String> {
    let locktime = cursor.read_u64()?;
    let threshold = cursor.read_u32()?;
    let addr_count = cursor.read_u32()? as usize;
    let mut addrs = Vec::with_capacity(addr_count);
    for _ in 0..addr_count {
        let addr = cursor.read_array::<20>()?;
        addrs.push(Value::String(cb58_encode(&addr)));
    }

    let mut map = Map::new();
    map.insert("locktime".to_string(), json!(locktime));
    map.insert("threshold".to_string(), json!(threshold));
    map.insert("addresses".to_string(), Value::Array(addrs));
    Ok(map)
}

fn parse_transferable_input(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    let tx_id = cursor.read_array::<32>()?;
    let output_index = cursor.read_u32()?;
    let asset_id = cursor.read_array::<32>()?;
    let input_type = cursor.read_u32()?;
    Ok(json!({
        "txID": cb58_encode(&tx_id),
        "outputIndex": output_index,
        "assetID": cb58_encode(&asset_id),
        "input": parse_input_by_type(cursor, input_type)?,
    }))
}

fn parse_input_by_type(cursor: &mut Cursor<'_>, type_id: u32) -> Result<Value, String> {
    match type_id {
        TYPE_SECP_TRANSFER_INPUT => parse_transfer_input(cursor),
        TYPE_LOCK_IN => {
            let locktime = cursor.read_u64()?;
            let inner_type = cursor.read_u32()?;
            let inner = parse_input_by_type(cursor, inner_type)?;
            Ok(json!({
                "locktime": locktime,
                "input": inner,
            }))
        }
        TYPE_SECP_INPUT => parse_secp_input(cursor),
        other => Err(format!("unsupported input type {}", other)),
    }
}

fn parse_transfer_input(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    let amount = cursor.read_u64()?;
    let mut map = match parse_secp_input(cursor)? {
        Value::Object(map) => map,
        _ => unreachable!(),
    };
    map.insert("amount".to_string(), json!(amount));
    Ok(Value::Object(map))
}

fn parse_secp_input(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    let sig_count = cursor.read_u32()? as usize;
    let mut sig_indices = Vec::with_capacity(sig_count);
    for _ in 0..sig_count {
        sig_indices.push(json!(cursor.read_u32()?));
    }
    Ok(json!({
        "signatureIndices": sig_indices,
    }))
}

fn parse_credentials(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    let cred_count = cursor.read_u32()? as usize;
    let mut credentials = Vec::with_capacity(cred_count);
    for _ in 0..cred_count {
        let cred_type = cursor.read_u32()?;
        match cred_type {
            TYPE_SECP_CREDENTIAL => {
                let sig_count = cursor.read_u32()? as usize;
                let mut signatures = Vec::with_capacity(sig_count);
                for _ in 0..sig_count {
                    let sig = cursor.read_array::<SECP256K1_SIGNATURE_LEN>()?;
                    signatures.push(Value::String(format!("0x{}", hex::encode(sig))));
                }
                credentials.push(json!({ "signatures": signatures }));
            }
            other => return Err(format!("unsupported credential type {}", other)),
        }
    }
    Ok(Value::Array(credentials))
}

fn node_id_string(bytes: &[u8; 20]) -> String {
    format!("NodeID-{}", cb58_encode(bytes))
}

fn cb58_encode(bytes: &[u8]) -> String {
    let checksum = Sha256::digest(bytes);
    let mut encoded = Vec::with_capacity(bytes.len() + 4);
    encoded.extend_from_slice(bytes);
    encoded.extend_from_slice(&checksum[checksum.len() - 4..]);
    bs58::encode(encoded).into_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transferable_output_bytes(asset_id: [u8; 32], amount: u64, owner: [u8; 20]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&asset_id);
        bytes.extend_from_slice(&TYPE_SECP_TRANSFER_OUTPUT.to_be_bytes());
        bytes.extend_from_slice(&amount.to_be_bytes());
        bytes.extend_from_slice(&0u64.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&owner);
        bytes
    }

    fn minimal_base_tx_bytes() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        bytes.extend_from_slice(&TYPE_BASE_TX.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes
    }

    fn minimal_signed_base_tx_bytes() -> Vec<u8> {
        let mut bytes = minimal_base_tx_bytes();
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes
    }

    fn minimal_add_validator_tx_bytes() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        bytes.extend_from_slice(&TYPE_ADD_VALIDATOR_TX.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&[0x11u8; 20]);
        bytes.extend_from_slice(&1000u64.to_be_bytes());
        bytes.extend_from_slice(&2000u64.to_be_bytes());
        bytes.extend_from_slice(&3000u64.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&TYPE_OUTPUT_OWNERS.to_be_bytes());
        bytes.extend_from_slice(&0u64.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&12345u32.to_be_bytes());
        bytes
    }

    fn add_validator_with_stake_bytes(owner: [u8; 20], amount: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        bytes.extend_from_slice(&TYPE_ADD_VALIDATOR_TX.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&[0x11u8; 20]);
        bytes.extend_from_slice(&1000u64.to_be_bytes());
        bytes.extend_from_slice(&2000u64.to_be_bytes());
        bytes.extend_from_slice(&amount.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&transferable_output_bytes([0xAB; 32], amount, owner));
        bytes.extend_from_slice(&TYPE_OUTPUT_OWNERS.to_be_bytes());
        bytes.extend_from_slice(&0u64.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&owner);
        bytes.extend_from_slice(&12345u32.to_be_bytes());
        bytes
    }

    #[test]
    fn test_parse_minimal_base_tx_json() {
        let json = parse_platform_tx_json(&minimal_base_tx_bytes()).unwrap();
        assert_eq!(json["unsignedTx"]["networkID"], 1);
        assert_eq!(
            json["unsignedTx"]["blockchainID"],
            "11111111111111111111111111111111LpoYY"
        );
        assert_eq!(json["unsignedTx"]["outputs"], json!([]));
        assert_eq!(json["unsignedTx"]["inputs"], json!([]));
        assert_eq!(json["unsignedTx"]["memo"], "0x");
        assert!(json["credentials"].is_null());
        assert!(json["id"].as_str().unwrap().starts_with('2'));
    }

    #[test]
    fn test_parse_advance_time_tx_json() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        bytes.extend_from_slice(&TYPE_ADVANCE_TIME_TX.to_be_bytes());
        bytes.extend_from_slice(&123456u64.to_be_bytes());

        let json = parse_platform_tx_json(&bytes).unwrap();
        assert_eq!(json["unsignedTx"]["time"], 123456);
        assert!(json["credentials"].is_null());
    }

    #[test]
    fn test_parse_add_validator_tx_json() {
        let json = parse_platform_tx_json(&minimal_add_validator_tx_bytes()).unwrap();
        assert_eq!(json["unsignedTx"]["validator"]["start"], 1000);
        assert_eq!(json["unsignedTx"]["validator"]["end"], 2000);
        assert_eq!(json["unsignedTx"]["validator"]["weight"], 3000);
        assert_eq!(json["unsignedTx"]["stake"], json!([]));
        assert_eq!(json["unsignedTx"]["rewardsOwner"]["threshold"], 0);
        assert_eq!(json["unsignedTx"]["shares"], 12345);
        assert!(json["unsignedTx"]["validator"]["nodeID"]
            .as_str()
            .unwrap()
            .starts_with("NodeID-"));
    }

    #[test]
    fn test_parse_rejects_unsupported_tx_type() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        bytes.extend_from_slice(&99u32.to_be_bytes());
        let err = parse_platform_tx_json(&bytes).unwrap_err();
        assert!(err.contains("unsupported platform tx type"));
    }

    #[test]
    fn test_summarize_platform_tx_extracts_primary_network_stake_outputs() {
        let owner = [0x42u8; 20];
        let tx = add_validator_with_stake_bytes(owner, 99);
        let summary = summarize_platform_tx(&tx).unwrap();
        match summary {
            PlatformTxSummary::Stake(summary) => {
                assert_eq!(summary.kind, PlatformStakerKind::Validator);
                assert_eq!(summary.outputs.len(), 1);
                assert_eq!(summary.outputs[0].asset_id, [0xAB; 32]);
                assert_eq!(summary.outputs[0].amount, 99);
                assert_eq!(summary.outputs[0].addresses, vec![owner]);
                assert_eq!(
                    summary.outputs[0].raw_bytes,
                    transferable_output_bytes([0xAB; 32], 99, owner)
                );
            }
            other => panic!("unexpected summary: {other:?}"),
        }
    }

    #[test]
    fn test_summarize_platform_tx_extracts_reward_validator_reference() {
        let mut tx = Vec::new();
        tx.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        tx.extend_from_slice(&TYPE_REWARD_VALIDATOR_TX.to_be_bytes());
        tx.extend_from_slice(&[0x55; 32]);

        let summary = summarize_platform_tx(&tx).unwrap();
        assert_eq!(
            summary,
            PlatformTxSummary::RewardValidator { tx_id: [0x55; 32] }
        );
    }

    #[test]
    fn test_extract_platform_tx_bytes_from_banff_standard_block() {
        let tx_bytes = minimal_signed_base_tx_bytes();
        let mut block = Vec::new();
        block.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        block.extend_from_slice(&TYPE_BANFF_STANDARD_BLOCK.to_be_bytes());
        block.extend_from_slice(&1_700_000_000u64.to_be_bytes());
        block.extend_from_slice(&[0x11; 32]);
        block.extend_from_slice(&7u64.to_be_bytes());
        block.extend_from_slice(&1u32.to_be_bytes());
        block.extend_from_slice(&tx_bytes);

        let txs = extract_platform_tx_bytes_from_block(&block).unwrap();
        assert_eq!(txs, vec![tx_bytes]);
    }

    #[test]
    fn test_extract_platform_tx_bytes_from_banff_proposal_block() {
        let decision_tx = minimal_signed_base_tx_bytes();
        let proposal_tx = minimal_signed_base_tx_bytes();
        let mut block = Vec::new();
        block.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        block.extend_from_slice(&TYPE_BANFF_PROPOSAL_BLOCK.to_be_bytes());
        block.extend_from_slice(&1_700_000_000u64.to_be_bytes());
        block.extend_from_slice(&1u32.to_be_bytes());
        block.extend_from_slice(&decision_tx);
        block.extend_from_slice(&[0x22; 32]);
        block.extend_from_slice(&8u64.to_be_bytes());
        block.extend_from_slice(&proposal_tx);

        let txs = extract_platform_tx_bytes_from_block(&block).unwrap();
        assert_eq!(txs, vec![decision_tx, proposal_tx]);
    }
}
