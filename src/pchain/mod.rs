use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

const CODEC_VERSION: u16 = 0;

const TYPE_SECP_TRANSFER_INPUT: u32 = 5;
const TYPE_SECP_TRANSFER_OUTPUT: u32 = 7;
const TYPE_SECP_CREDENTIAL: u32 = 9;
const TYPE_SECP_INPUT: u32 = 10;
const TYPE_OUTPUT_OWNERS: u32 = 11;

const TYPE_ADD_VALIDATOR_TX: u32 = 12;
const TYPE_ADD_SUBNET_VALIDATOR_TX: u32 = 13;
const TYPE_ADD_DELEGATOR_TX: u32 = 14;
const TYPE_CREATE_CHAIN_TX: u32 = 15;
const TYPE_CREATE_SUBNET_TX: u32 = 16;
const TYPE_IMPORT_TX: u32 = 17;
const TYPE_EXPORT_TX: u32 = 18;
const TYPE_ADVANCE_TIME_TX: u32 = 19;
const TYPE_REWARD_VALIDATOR_TX: u32 = 20;
const TYPE_LOCK_IN: u32 = 21;
const TYPE_LOCK_OUT: u32 = 22;
const TYPE_REMOVE_SUBNET_VALIDATOR_TX: u32 = 23;
const TYPE_TRANSFORM_SUBNET_TX: u32 = 24;
const TYPE_ADD_PERMISSIONLESS_VALIDATOR_TX: u32 = 25;
const TYPE_ADD_PERMISSIONLESS_DELEGATOR_TX: u32 = 26;
const TYPE_SIGNER_EMPTY: u32 = 27;
const TYPE_SIGNER_PROOF_OF_POSSESSION: u32 = 28;
const TYPE_TRANSFER_SUBNET_OWNERSHIP_TX: u32 = 33;
const TYPE_BASE_TX: u32 = 34;
const TYPE_CONVERT_SUBNET_TO_L1_TX: u32 = 35;
const TYPE_REGISTER_L1_VALIDATOR_TX: u32 = 36;
const TYPE_SET_L1_VALIDATOR_WEIGHT_TX: u32 = 37;
const TYPE_INCREASE_L1_VALIDATOR_BALANCE_TX: u32 = 38;
const TYPE_DISABLE_L1_VALIDATOR_TX: u32 = 39;

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

type StakeOutputDetails = (u64, Vec<[u8; 20]>);
type OwnedOutputDetails = (u64, u64, Option<u64>, Vec<[u8; 20]>);

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
pub struct PlatformPChainOwner {
    pub threshold: u32,
    pub addresses: Vec<[u8; 20]>,
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
    pub import_source_chain: Option<[u8; 32]>,
    pub imported_inputs: Vec<PlatformInputRef>,
    pub export_destination_chain: Option<[u8; 32]>,
    pub exported_outputs: Vec<PlatformOwnedOutput>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformTxSummary {
    Stake(PlatformStakeTxSummary),
    RewardValidator { tx_id: [u8; 32] },
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformL1ValidatorRegistration {
    pub validation_id: [u8; 32],
    pub subnet_id: [u8; 32],
    pub node_id: [u8; 20],
    pub public_key: [u8; BLS_PUBLIC_KEY_LEN],
    pub remaining_balance_owner: PlatformPChainOwner,
    pub deactivation_owner: PlatformPChainOwner,
    pub weight: u64,
    pub balance: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformL1ValidatorTxSummary {
    ConvertSubnetToL1 {
        validators: Vec<PlatformL1ValidatorRegistration>,
    },
    RegisterL1Validator {
        validator: PlatformL1ValidatorRegistration,
    },
    SetL1ValidatorWeight {
        validation_id: [u8; 32],
        nonce: u64,
        weight: u64,
    },
    IncreaseL1ValidatorBalance {
        validation_id: [u8; 32],
        balance: u64,
    },
    DisableL1Validator {
        validation_id: [u8; 32],
    },
    Other,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct DynamicFeeDimensions {
    bandwidth: u64,
    db_read: u64,
    db_write: u64,
    compute: u64,
}

impl DynamicFeeDimensions {
    fn add(self, other: Self) -> Result<Self, String> {
        Ok(Self {
            bandwidth: self
                .bandwidth
                .checked_add(other.bandwidth)
                .ok_or_else(|| "bandwidth overflow".to_string())?,
            db_read: self
                .db_read
                .checked_add(other.db_read)
                .ok_or_else(|| "db_read overflow".to_string())?,
            db_write: self
                .db_write
                .checked_add(other.db_write)
                .ok_or_else(|| "db_write overflow".to_string())?,
            compute: self
                .compute
                .checked_add(other.compute)
                .ok_or_else(|| "compute overflow".to_string())?,
        })
    }

    fn to_gas(self, weights: [u64; 4]) -> Result<u64, String> {
        let gas = (self.bandwidth as u128)
            .checked_mul(weights[0] as u128)
            .and_then(|value| value.checked_add((self.db_read as u128) * (weights[1] as u128)))
            .and_then(|value| value.checked_add((self.db_write as u128) * (weights[2] as u128)))
            .and_then(|value| value.checked_add((self.compute as u128) * (weights[3] as u128)))
            .ok_or_else(|| "dynamic fee gas overflow".to_string())?;
        u64::try_from(gas).map_err(|_| "dynamic fee gas exceeds u64".to_string())
    }
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

pub(crate) fn platform_tx_len(bytes: &[u8]) -> Result<usize, String> {
    parse_platform_tx_prefix(bytes).map(|(_, consumed)| consumed)
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
        TYPE_ADD_SUBNET_VALIDATOR_TX => {
            let (outputs, inputs) = parse_base_tx_ledger(&mut cursor)?;
            skip_validator(&mut cursor)?;
            cursor.read_array::<32>()?;
            let _ = parse_verifiable(&mut cursor)?;
            Ok(PlatformTxLedgerSummary {
                kind: None,
                inputs,
                outputs,
                stake_outputs: Vec::new(),
                reward_validator_tx_id: None,
                import_source_chain: None,
                imported_inputs: Vec::new(),
                export_destination_chain: None,
                exported_outputs: Vec::new(),
            })
        }
        TYPE_CREATE_CHAIN_TX => {
            let (outputs, inputs) = parse_base_tx_ledger(&mut cursor)?;
            cursor.read_array::<32>()?;
            let chain_name_len = cursor.read_u16()? as usize;
            cursor.read_exact(chain_name_len)?;
            cursor.read_array::<32>()?;
            let fx_count = cursor.read_u32()? as usize;
            cursor.read_exact(fx_count.saturating_mul(32))?;
            let genesis_len = cursor.read_u32()? as usize;
            cursor.read_exact(genesis_len)?;
            let _ = parse_verifiable(&mut cursor)?;
            Ok(PlatformTxLedgerSummary {
                kind: None,
                inputs,
                outputs,
                stake_outputs: Vec::new(),
                reward_validator_tx_id: None,
                import_source_chain: None,
                imported_inputs: Vec::new(),
                export_destination_chain: None,
                exported_outputs: Vec::new(),
            })
        }
        TYPE_CREATE_SUBNET_TX => {
            let (outputs, inputs) = parse_base_tx_ledger(&mut cursor)?;
            let _ = parse_owner_interface(&mut cursor)?;
            Ok(PlatformTxLedgerSummary {
                kind: None,
                inputs,
                outputs,
                stake_outputs: Vec::new(),
                reward_validator_tx_id: None,
                import_source_chain: None,
                imported_inputs: Vec::new(),
                export_destination_chain: None,
                exported_outputs: Vec::new(),
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
                import_source_chain: None,
                imported_inputs: Vec::new(),
                export_destination_chain: None,
                exported_outputs: Vec::new(),
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
                import_source_chain: None,
                imported_inputs: Vec::new(),
                export_destination_chain: None,
                exported_outputs: Vec::new(),
            })
        }
        TYPE_IMPORT_TX => {
            let (outputs, inputs) = parse_base_tx_ledger(&mut cursor)?;
            let import_source_chain = cursor.read_array::<32>()?;
            let import_count = cursor.read_u32()? as usize;
            let mut imported_inputs = Vec::with_capacity(import_count);
            for _ in 0..import_count {
                imported_inputs.push(parse_input_ref(&mut cursor)?);
            }
            Ok(PlatformTxLedgerSummary {
                kind: None,
                inputs,
                outputs,
                stake_outputs: Vec::new(),
                reward_validator_tx_id: None,
                import_source_chain: Some(import_source_chain),
                imported_inputs,
                export_destination_chain: None,
                exported_outputs: Vec::new(),
            })
        }
        TYPE_EXPORT_TX => {
            let (outputs, inputs) = parse_base_tx_ledger(&mut cursor)?;
            let export_destination_chain = cursor.read_array::<32>()?;
            let exported_outputs = parse_owned_transferable_outputs(&mut cursor)?;
            Ok(PlatformTxLedgerSummary {
                kind: None,
                inputs,
                outputs,
                stake_outputs: Vec::new(),
                reward_validator_tx_id: None,
                import_source_chain: None,
                imported_inputs: Vec::new(),
                export_destination_chain: Some(export_destination_chain),
                exported_outputs,
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
            import_source_chain: None,
            imported_inputs: Vec::new(),
            export_destination_chain: None,
            exported_outputs: Vec::new(),
        }),
        TYPE_ADVANCE_TIME_TX => Ok(PlatformTxLedgerSummary {
            kind: None,
            inputs: Vec::new(),
            outputs: Vec::new(),
            stake_outputs: Vec::new(),
            reward_validator_tx_id: None,
            import_source_chain: None,
            imported_inputs: Vec::new(),
            export_destination_chain: None,
            exported_outputs: Vec::new(),
        }),
        other => Err(format!("unsupported platform tx type {}", other)),
    }
}

pub fn summarize_platform_l1_validator_tx(
    bytes: &[u8],
) -> Result<PlatformL1ValidatorTxSummary, String> {
    let mut cursor = Cursor::new(bytes);
    let version = cursor.read_u16()?;
    if version != CODEC_VERSION {
        return Err(format!("unsupported codec version {}", version));
    }

    match cursor.read_u32()? {
        TYPE_CONVERT_SUBNET_TO_L1_TX => parse_convert_subnet_to_l1_tx_summary(&mut cursor),
        TYPE_REGISTER_L1_VALIDATOR_TX => parse_register_l1_validator_tx_summary(&mut cursor),
        TYPE_SET_L1_VALIDATOR_WEIGHT_TX => parse_set_l1_validator_weight_tx_summary(&mut cursor),
        TYPE_INCREASE_L1_VALIDATOR_BALANCE_TX => {
            parse_increase_l1_validator_balance_tx_summary(&mut cursor)
        }
        TYPE_DISABLE_L1_VALIDATOR_TX => parse_disable_l1_validator_tx_summary(&mut cursor),
        _ => Ok(PlatformL1ValidatorTxSummary::Other),
    }
}

pub fn platform_tx_type_id(bytes: &[u8]) -> Result<u32, String> {
    let mut cursor = Cursor::new(bytes);
    let version = cursor.read_u16()?;
    if version != CODEC_VERSION {
        return Err(format!("unsupported codec version {}", version));
    }
    cursor.read_u32()
}

pub fn platform_tx_dynamic_fee_gas(bytes: &[u8], weights: [u64; 4]) -> Result<Option<u64>, String> {
    let mut cursor = Cursor::new(bytes);
    let version = cursor.read_u16()?;
    if version != CODEC_VERSION {
        return Err(format!("unsupported codec version {}", version));
    }

    let type_id = cursor.read_u32()?;
    let bandwidth = u64::try_from(bytes.len()).map_err(|_| "tx too large".to_string())?;
    let base_dims = DynamicFeeDimensions {
        bandwidth,
        ..Default::default()
    };

    let dims = match type_id {
        TYPE_BASE_TX => parse_base_tx_dynamic_fee_dimensions(&mut cursor)?,
        TYPE_CREATE_SUBNET_TX => {
            parse_base_tx_dynamic_fee_dimensions(&mut cursor)?.add(DynamicFeeDimensions {
                db_write: 1,
                ..Default::default()
            })?
        }
        TYPE_ADD_SUBNET_VALIDATOR_TX => {
            let mut tx_dims = parse_base_tx_dynamic_fee_dimensions(&mut cursor)?;
            skip_validator(&mut cursor)?;
            cursor.read_array::<32>()?;
            let auth_compute = parse_auth_compute(&mut cursor)?;
            tx_dims = tx_dims.add(DynamicFeeDimensions {
                db_read: 3,
                db_write: 3,
                compute: auth_compute,
                ..Default::default()
            })?;
            tx_dims
        }
        TYPE_CREATE_CHAIN_TX => {
            let mut tx_dims = parse_base_tx_dynamic_fee_dimensions(&mut cursor)?;
            cursor.read_array::<32>()?;
            let chain_name_len = cursor.read_u16()? as usize;
            cursor.read_exact(chain_name_len)?;
            cursor.read_array::<32>()?;
            let fx_count = cursor.read_u32()? as usize;
            cursor.read_exact(fx_count.saturating_mul(32))?;
            let genesis_len = cursor.read_u32()? as usize;
            cursor.read_exact(genesis_len)?;
            let auth_compute = parse_auth_compute(&mut cursor)?;
            tx_dims = tx_dims.add(DynamicFeeDimensions {
                db_read: 3,
                db_write: 1,
                compute: auth_compute,
                ..Default::default()
            })?;
            tx_dims
        }
        TYPE_IMPORT_TX => {
            let mut tx_dims = parse_base_tx_dynamic_fee_dimensions(&mut cursor)?;
            cursor.read_array::<32>()?;
            tx_dims = tx_dims.add(parse_transferable_inputs_dynamic_fee_dimensions(
                &mut cursor,
            )?)?;
            tx_dims
        }
        TYPE_EXPORT_TX => {
            let mut tx_dims = parse_base_tx_dynamic_fee_dimensions(&mut cursor)?;
            cursor.read_array::<32>()?;
            tx_dims = tx_dims.add(parse_transferable_outputs_dynamic_fee_dimensions(
                &mut cursor,
            )?)?;
            tx_dims
        }
        TYPE_REMOVE_SUBNET_VALIDATOR_TX => {
            let mut tx_dims = parse_base_tx_dynamic_fee_dimensions(&mut cursor)?;
            cursor.read_array::<20>()?;
            cursor.read_array::<32>()?;
            let auth_compute = parse_auth_compute(&mut cursor)?;
            tx_dims = tx_dims.add(DynamicFeeDimensions {
                db_read: 1,
                db_write: 3,
                compute: auth_compute,
                ..Default::default()
            })?;
            tx_dims
        }
        TYPE_ADD_PERMISSIONLESS_VALIDATOR_TX => {
            let mut tx_dims = parse_base_tx_dynamic_fee_dimensions(&mut cursor)?;
            skip_validator(&mut cursor)?;
            cursor.read_array::<32>()?;
            let signer_compute = parse_signer_compute(&mut cursor)?;
            tx_dims = tx_dims.add(parse_transferable_outputs_dynamic_fee_dimensions(
                &mut cursor,
            )?)?;
            skip_owner_interface_raw(&mut cursor)?;
            skip_owner_interface_raw(&mut cursor)?;
            cursor.read_u32()?;
            tx_dims = tx_dims.add(DynamicFeeDimensions {
                db_read: 1,
                db_write: 3,
                compute: signer_compute,
                ..Default::default()
            })?;
            tx_dims
        }
        TYPE_ADD_PERMISSIONLESS_DELEGATOR_TX => {
            let mut tx_dims = parse_base_tx_dynamic_fee_dimensions(&mut cursor)?;
            skip_validator(&mut cursor)?;
            cursor.read_array::<32>()?;
            tx_dims = tx_dims.add(parse_transferable_outputs_dynamic_fee_dimensions(
                &mut cursor,
            )?)?;
            skip_owner_interface_raw(&mut cursor)?;
            tx_dims = tx_dims.add(DynamicFeeDimensions {
                db_read: 1,
                db_write: 2,
                ..Default::default()
            })?;
            tx_dims
        }
        TYPE_TRANSFER_SUBNET_OWNERSHIP_TX => {
            let mut tx_dims = parse_base_tx_dynamic_fee_dimensions(&mut cursor)?;
            cursor.read_array::<32>()?;
            let auth_compute = parse_auth_compute(&mut cursor)?;
            skip_owner_interface_raw(&mut cursor)?;
            tx_dims = tx_dims.add(DynamicFeeDimensions {
                db_read: 1,
                db_write: 1,
                compute: auth_compute,
                ..Default::default()
            })?;
            tx_dims
        }
        TYPE_CONVERT_SUBNET_TO_L1_TX => {
            parse_convert_subnet_to_l1_dynamic_fee_dimensions(&mut cursor)?
        }
        TYPE_REGISTER_L1_VALIDATOR_TX => {
            parse_register_l1_validator_dynamic_fee_dimensions(&mut cursor)?
        }
        TYPE_SET_L1_VALIDATOR_WEIGHT_TX => {
            parse_set_l1_validator_weight_dynamic_fee_dimensions(&mut cursor)?
        }
        TYPE_INCREASE_L1_VALIDATOR_BALANCE_TX => {
            parse_increase_l1_validator_balance_dynamic_fee_dimensions(&mut cursor)?
        }
        TYPE_DISABLE_L1_VALIDATOR_TX => {
            parse_disable_l1_validator_dynamic_fee_dimensions(&mut cursor)?
        }
        TYPE_ADVANCE_TIME_TX | TYPE_REWARD_VALIDATOR_TX => return Ok(None),
        TYPE_ADD_VALIDATOR_TX | TYPE_ADD_DELEGATOR_TX | TYPE_TRANSFORM_SUBNET_TX => {
            return Err(format!(
                "unsupported platform tx type {} for dynamic fee accounting",
                type_id
            ))
        }
        other => return Err(format!("unsupported platform tx type {}", other)),
    };

    skip_credentials_raw(&mut cursor)?;
    if cursor.remaining() != 0 {
        return Err(format!("unexpected trailing bytes: {}", cursor.remaining()));
    }
    base_dims.add(dims)?.to_gas(weights).map(Some)
}

fn parse_base_tx_dynamic_fee_dimensions(
    cursor: &mut Cursor<'_>,
) -> Result<DynamicFeeDimensions, String> {
    cursor.read_u32()?;
    cursor.read_array::<32>()?;

    let outputs = parse_transferable_outputs_dynamic_fee_dimensions(cursor)?;
    let inputs = parse_transferable_inputs_dynamic_fee_dimensions(cursor)?;

    let memo_len = cursor.read_u32()? as usize;
    cursor.read_exact(memo_len)?;
    outputs.add(inputs)
}

fn parse_transferable_outputs_dynamic_fee_dimensions(
    cursor: &mut Cursor<'_>,
) -> Result<DynamicFeeDimensions, String> {
    let outputs_len = cursor.read_u32()? as usize;
    let mut dims = DynamicFeeDimensions::default();
    for _ in 0..outputs_len {
        skip_transferable_output(cursor)?;
        dims = dims.add(DynamicFeeDimensions {
            db_write: 1,
            ..Default::default()
        })?;
    }
    Ok(dims)
}

fn parse_convert_subnet_to_l1_dynamic_fee_dimensions(
    cursor: &mut Cursor<'_>,
) -> Result<DynamicFeeDimensions, String> {
    let mut tx_dims = parse_base_tx_dynamic_fee_dimensions(cursor)?;
    cursor.read_array::<32>()?;
    cursor.read_array::<32>()?;
    let address_len = cursor.read_u32()? as usize;
    cursor.read_exact(address_len)?;

    let validator_count = cursor.read_u32()? as usize;
    let validator_count_u64 =
        u64::try_from(validator_count).map_err(|_| "validator count overflow".to_string())?;
    let mut validator_compute = 0u64;
    for _ in 0..validator_count {
        let node_id_len = cursor.read_u32()? as usize;
        cursor.read_exact(node_id_len)?;
        cursor.read_u64()?;
        cursor.read_u64()?;
        cursor.read_exact(BLS_PUBLIC_KEY_LEN)?;
        cursor.read_exact(BLS_SIGNATURE_LEN)?;
        skip_pchain_owner_raw(cursor)?;
        skip_pchain_owner_raw(cursor)?;
        validator_compute = validator_compute
            .checked_add(1_050)
            .ok_or_else(|| "validator compute overflow".to_string())?;
    }

    let auth_compute = parse_auth_compute(cursor)?;
    tx_dims = tx_dims.add(DynamicFeeDimensions {
        db_read: 3,
        db_write: validator_count_u64
            .checked_mul(4)
            .and_then(|value| value.checked_add(2))
            .ok_or_else(|| "validator db_write overflow".to_string())?,
        compute: validator_compute
            .checked_add(auth_compute)
            .ok_or_else(|| "validator compute overflow".to_string())?,
        ..Default::default()
    })?;
    Ok(tx_dims)
}

fn parse_register_l1_validator_dynamic_fee_dimensions(
    cursor: &mut Cursor<'_>,
) -> Result<DynamicFeeDimensions, String> {
    let mut tx_dims = parse_base_tx_dynamic_fee_dimensions(cursor)?;
    cursor.read_u64()?;
    cursor.read_exact(BLS_SIGNATURE_LEN)?;
    let warp_dims = parse_warp_dynamic_fee_dimensions(cursor)?;
    tx_dims = tx_dims.add(warp_dims)?.add(DynamicFeeDimensions {
        db_read: 5,
        db_write: 6,
        compute: 1_050,
        ..Default::default()
    })?;
    Ok(tx_dims)
}

fn parse_set_l1_validator_weight_dynamic_fee_dimensions(
    cursor: &mut Cursor<'_>,
) -> Result<DynamicFeeDimensions, String> {
    let mut tx_dims = parse_base_tx_dynamic_fee_dimensions(cursor)?;
    let warp_dims = parse_warp_dynamic_fee_dimensions(cursor)?;
    tx_dims = tx_dims.add(warp_dims)?.add(DynamicFeeDimensions {
        db_read: 3,
        db_write: 5,
        ..Default::default()
    })?;
    Ok(tx_dims)
}

fn parse_increase_l1_validator_balance_dynamic_fee_dimensions(
    cursor: &mut Cursor<'_>,
) -> Result<DynamicFeeDimensions, String> {
    let mut tx_dims = parse_base_tx_dynamic_fee_dimensions(cursor)?;
    cursor.read_array::<32>()?;
    cursor.read_u64()?;
    tx_dims = tx_dims.add(DynamicFeeDimensions {
        db_read: 1,
        db_write: 5,
        ..Default::default()
    })?;
    Ok(tx_dims)
}

fn parse_disable_l1_validator_dynamic_fee_dimensions(
    cursor: &mut Cursor<'_>,
) -> Result<DynamicFeeDimensions, String> {
    let mut tx_dims = parse_base_tx_dynamic_fee_dimensions(cursor)?;
    cursor.read_array::<32>()?;
    let auth_compute = parse_auth_compute(cursor)?;
    tx_dims = tx_dims.add(DynamicFeeDimensions {
        db_read: 1,
        db_write: 6,
        compute: auth_compute,
        ..Default::default()
    })?;
    Ok(tx_dims)
}

fn parse_warp_dynamic_fee_dimensions(
    cursor: &mut Cursor<'_>,
) -> Result<DynamicFeeDimensions, String> {
    let message = read_len_prefixed_bytes(cursor)?;
    let parsed = parse_warp_message(&message)?;
    let aggregation_compute = parsed
        .num_signers
        .checked_mul(5)
        .ok_or_else(|| "warp compute overflow".to_string())?;
    Ok(DynamicFeeDimensions {
        db_read: 23,
        compute: aggregation_compute
            .checked_add(1_000)
            .ok_or_else(|| "warp compute overflow".to_string())?,
        ..Default::default()
    })
}

fn parse_transferable_inputs_dynamic_fee_dimensions(
    cursor: &mut Cursor<'_>,
) -> Result<DynamicFeeDimensions, String> {
    let inputs_len = cursor.read_u32()? as usize;
    let mut dims = DynamicFeeDimensions::default();
    for _ in 0..inputs_len {
        let input_dims = parse_transferable_input_dynamic_fee_dimensions(cursor)?;
        dims = dims.add(input_dims)?;
    }
    Ok(dims)
}

fn parse_transferable_input_dynamic_fee_dimensions(
    cursor: &mut Cursor<'_>,
) -> Result<DynamicFeeDimensions, String> {
    cursor.read_array::<32>()?;
    cursor.read_u32()?;
    cursor.read_array::<32>()?;
    let input_type = cursor.read_u32()?;
    let signature_count = parse_input_signature_count(cursor, input_type)?;
    let compute = signature_count
        .checked_mul(200)
        .ok_or_else(|| "signature compute overflow".to_string())?;
    Ok(DynamicFeeDimensions {
        db_read: 1,
        db_write: 1,
        compute,
        ..Default::default()
    })
}

fn parse_input_signature_count(cursor: &mut Cursor<'_>, type_id: u32) -> Result<u64, String> {
    match type_id {
        TYPE_SECP_TRANSFER_INPUT => {
            cursor.read_u64()?;
            parse_secp_input_signature_count(cursor)
        }
        TYPE_LOCK_IN => {
            cursor.read_u64()?;
            let inner_type = cursor.read_u32()?;
            parse_input_signature_count(cursor, inner_type)
        }
        TYPE_SECP_INPUT => parse_secp_input_signature_count(cursor),
        other => Err(format!("unsupported input type {}", other)),
    }
}

fn parse_secp_input_signature_count(cursor: &mut Cursor<'_>) -> Result<u64, String> {
    let sig_count = cursor.read_u32()? as usize;
    cursor.read_exact(sig_count.saturating_mul(4))?;
    u64::try_from(sig_count).map_err(|_| "signature count overflow".to_string())
}

fn parse_auth_compute(cursor: &mut Cursor<'_>) -> Result<u64, String> {
    let sig_count = match cursor.read_u32()? {
        TYPE_SECP_INPUT => parse_secp_input_signature_count(cursor)?,
        other => return Err(format!("unsupported auth type {}", other)),
    };
    sig_count
        .checked_mul(200)
        .ok_or_else(|| "auth compute overflow".to_string())
}

fn read_len_prefixed_bytes(cursor: &mut Cursor<'_>) -> Result<Vec<u8>, String> {
    let len = cursor.read_u32()? as usize;
    Ok(cursor.read_exact(len)?.to_vec())
}

fn skip_pchain_owner_raw(cursor: &mut Cursor<'_>) -> Result<(), String> {
    let _ = read_pchain_owner_raw(cursor)?;
    Ok(())
}

fn read_pchain_owner_raw(cursor: &mut Cursor<'_>) -> Result<PlatformPChainOwner, String> {
    let threshold = cursor.read_u32()?;
    let address_count = cursor.read_u32()? as usize;
    let mut addresses = Vec::with_capacity(address_count);
    for _ in 0..address_count {
        addresses.push(cursor.read_array::<20>()?);
    }
    Ok(PlatformPChainOwner {
        threshold,
        addresses,
    })
}

fn append_platform_id(id: [u8; 32], suffix: u32) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(36);
    bytes.extend_from_slice(&id);
    bytes.extend_from_slice(&suffix.to_be_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(&bytes));
    out
}

fn count_set_bits(bytes: &[u8]) -> u64 {
    bytes.iter().map(|byte| u64::from(byte.count_ones())).sum()
}

struct ParsedWarpMessage {
    payload: Vec<u8>,
    num_signers: u64,
}

fn parse_warp_message(bytes: &[u8]) -> Result<ParsedWarpMessage, String> {
    let mut cursor = Cursor::new(bytes);
    let version = cursor.read_u16()?;
    if version != CODEC_VERSION {
        return Err(format!("unsupported warp codec version {}", version));
    }

    cursor.read_u32()?;
    cursor.read_array::<32>()?;
    let payload = read_len_prefixed_bytes(&mut cursor)?;
    match cursor.read_u32()? {
        0 => {
            let signers = read_len_prefixed_bytes(&mut cursor)?;
            cursor.read_exact(BLS_SIGNATURE_LEN)?;
            if cursor.remaining() != 0 {
                return Err(format!(
                    "unexpected trailing warp bytes: {}",
                    cursor.remaining()
                ));
            }
            Ok(ParsedWarpMessage {
                payload,
                num_signers: count_set_bits(&signers),
            })
        }
        other => Err(format!("unsupported warp signature type {}", other)),
    }
}

fn parse_warp_addressed_call_payload(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut cursor = Cursor::new(bytes);
    let version = cursor.read_u16()?;
    if version != CODEC_VERSION {
        return Err(format!(
            "unsupported warp payload codec version {}",
            version
        ));
    }

    match cursor.read_u32()? {
        1 => {
            let _source_address = read_len_prefixed_bytes(&mut cursor)?;
            let payload = read_len_prefixed_bytes(&mut cursor)?;
            if cursor.remaining() != 0 {
                return Err(format!(
                    "unexpected trailing addressed call bytes: {}",
                    cursor.remaining()
                ));
            }
            Ok(payload)
        }
        other => Err(format!("unsupported warp payload type {}", other)),
    }
}

struct ParsedRegisterL1ValidatorMessage {
    validation_id: [u8; 32],
    subnet_id: [u8; 32],
    node_id: [u8; 20],
    public_key: [u8; BLS_PUBLIC_KEY_LEN],
    remaining_balance_owner: PlatformPChainOwner,
    deactivation_owner: PlatformPChainOwner,
    weight: u64,
}

fn parse_register_l1_validator_message(
    bytes: &[u8],
) -> Result<ParsedRegisterL1ValidatorMessage, String> {
    let mut cursor = Cursor::new(bytes);
    let version = cursor.read_u16()?;
    if version != CODEC_VERSION {
        return Err(format!(
            "unsupported warp message codec version {}",
            version
        ));
    }

    match cursor.read_u32()? {
        1 => {
            let subnet_id = cursor.read_array::<32>()?;
            let node_id_len = cursor.read_u32()? as usize;
            let node_id = cursor.read_bytes(node_id_len)?;
            let node_id: [u8; 20] = node_id
                .as_slice()
                .try_into()
                .map_err(|_| "invalid nodeID length".to_string())?;
            let public_key = cursor.read_array::<BLS_PUBLIC_KEY_LEN>()?;
            cursor.read_u64()?;
            let remaining_balance_owner = read_pchain_owner_raw(&mut cursor)?;
            let deactivation_owner = read_pchain_owner_raw(&mut cursor)?;
            let weight = cursor.read_u64()?;
            if cursor.remaining() != 0 {
                return Err(format!(
                    "unexpected trailing register message bytes: {}",
                    cursor.remaining()
                ));
            }
            Ok(ParsedRegisterL1ValidatorMessage {
                validation_id: Sha256::digest(bytes).into(),
                subnet_id,
                node_id,
                public_key,
                remaining_balance_owner,
                deactivation_owner,
                weight,
            })
        }
        other => Err(format!("unsupported warp message type {}", other)),
    }
}

fn parse_l1_validator_weight_message(bytes: &[u8]) -> Result<([u8; 32], u64, u64), String> {
    let mut cursor = Cursor::new(bytes);
    let version = cursor.read_u16()?;
    if version != CODEC_VERSION {
        return Err(format!(
            "unsupported warp message codec version {}",
            version
        ));
    }

    match cursor.read_u32()? {
        3 => {
            let validation_id = cursor.read_array::<32>()?;
            let nonce = cursor.read_u64()?;
            let weight = cursor.read_u64()?;
            if cursor.remaining() != 0 {
                return Err(format!(
                    "unexpected trailing validator weight message bytes: {}",
                    cursor.remaining()
                ));
            }
            Ok((validation_id, nonce, weight))
        }
        other => Err(format!("unsupported warp message type {}", other)),
    }
}

fn parse_convert_subnet_to_l1_tx_summary(
    cursor: &mut Cursor<'_>,
) -> Result<PlatformL1ValidatorTxSummary, String> {
    skip_base_tx_fields(cursor)?;
    let subnet_id = cursor.read_array::<32>()?;
    cursor.read_array::<32>()?;
    let address_len = cursor.read_u32()? as usize;
    cursor.read_exact(address_len)?;
    let validator_count = cursor.read_u32()? as usize;
    let mut validators = Vec::with_capacity(validator_count);
    for index in 0..validator_count {
        let node_id_len = cursor.read_u32()? as usize;
        let node_id = cursor.read_bytes(node_id_len)?;
        let node_id: [u8; 20] = node_id
            .as_slice()
            .try_into()
            .map_err(|_| "invalid nodeID length".to_string())?;
        let weight = cursor.read_u64()?;
        let balance = cursor.read_u64()?;
        let public_key = cursor.read_array::<BLS_PUBLIC_KEY_LEN>()?;
        cursor.read_exact(BLS_SIGNATURE_LEN)?;
        let remaining_balance_owner = read_pchain_owner_raw(cursor)?;
        let deactivation_owner = read_pchain_owner_raw(cursor)?;
        validators.push(PlatformL1ValidatorRegistration {
            validation_id: append_platform_id(subnet_id, index as u32),
            subnet_id,
            node_id,
            public_key,
            remaining_balance_owner,
            deactivation_owner,
            weight,
            balance,
        });
    }
    let _ = parse_auth_compute(cursor)?;
    Ok(PlatformL1ValidatorTxSummary::ConvertSubnetToL1 { validators })
}

fn parse_register_l1_validator_tx_summary(
    cursor: &mut Cursor<'_>,
) -> Result<PlatformL1ValidatorTxSummary, String> {
    skip_base_tx_fields(cursor)?;
    let balance = cursor.read_u64()?;
    cursor.read_exact(BLS_SIGNATURE_LEN)?;
    let warp_message = read_len_prefixed_bytes(cursor)?;
    let addressed_call = parse_warp_message(&warp_message)?;
    let payload = parse_warp_addressed_call_payload(&addressed_call.payload)?;
    let parsed = parse_register_l1_validator_message(&payload)?;
    Ok(PlatformL1ValidatorTxSummary::RegisterL1Validator {
        validator: PlatformL1ValidatorRegistration {
            validation_id: parsed.validation_id,
            subnet_id: parsed.subnet_id,
            node_id: parsed.node_id,
            public_key: parsed.public_key,
            remaining_balance_owner: parsed.remaining_balance_owner,
            deactivation_owner: parsed.deactivation_owner,
            weight: parsed.weight,
            balance,
        },
    })
}

fn parse_set_l1_validator_weight_tx_summary(
    cursor: &mut Cursor<'_>,
) -> Result<PlatformL1ValidatorTxSummary, String> {
    skip_base_tx_fields(cursor)?;
    let warp_message = read_len_prefixed_bytes(cursor)?;
    let addressed_call = parse_warp_message(&warp_message)?;
    let payload = parse_warp_addressed_call_payload(&addressed_call.payload)?;
    let (validation_id, nonce, weight) = parse_l1_validator_weight_message(&payload)?;
    Ok(PlatformL1ValidatorTxSummary::SetL1ValidatorWeight {
        validation_id,
        nonce,
        weight,
    })
}

fn parse_increase_l1_validator_balance_tx_summary(
    cursor: &mut Cursor<'_>,
) -> Result<PlatformL1ValidatorTxSummary, String> {
    skip_base_tx_fields(cursor)?;
    Ok(PlatformL1ValidatorTxSummary::IncreaseL1ValidatorBalance {
        validation_id: cursor.read_array::<32>()?,
        balance: cursor.read_u64()?,
    })
}

fn parse_disable_l1_validator_tx_summary(
    cursor: &mut Cursor<'_>,
) -> Result<PlatformL1ValidatorTxSummary, String> {
    skip_base_tx_fields(cursor)?;
    let validation_id = cursor.read_array::<32>()?;
    let _ = parse_auth_compute(cursor)?;
    Ok(PlatformL1ValidatorTxSummary::DisableL1Validator { validation_id })
}

fn parse_signer_compute(cursor: &mut Cursor<'_>) -> Result<u64, String> {
    match cursor.read_u32()? {
        TYPE_SIGNER_EMPTY => Ok(0),
        TYPE_SIGNER_PROOF_OF_POSSESSION => {
            cursor.read_exact(BLS_PUBLIC_KEY_LEN)?;
            cursor.read_exact(BLS_SIGNATURE_LEN)?;
            Ok(1_050)
        }
        other => Err(format!("unsupported signer type {}", other)),
    }
}

fn skip_transferable_output(cursor: &mut Cursor<'_>) -> Result<(), String> {
    cursor.read_array::<32>()?;
    let output_type = cursor.read_u32()?;
    skip_output(cursor, output_type)
}

fn skip_output(cursor: &mut Cursor<'_>, type_id: u32) -> Result<(), String> {
    match type_id {
        TYPE_SECP_TRANSFER_OUTPUT => {
            cursor.read_u64()?;
            let _ = parse_output_owners_raw(cursor)?;
            Ok(())
        }
        TYPE_LOCK_OUT => {
            cursor.read_u64()?;
            let inner_type = cursor.read_u32()?;
            skip_output(cursor, inner_type)
        }
        other => Err(format!("unsupported output type {}", other)),
    }
}

fn skip_owner_interface_raw(cursor: &mut Cursor<'_>) -> Result<(), String> {
    match cursor.read_u32()? {
        TYPE_OUTPUT_OWNERS => {
            let _ = parse_output_owners_raw(cursor)?;
            Ok(())
        }
        other => Err(format!("unsupported owner type {}", other)),
    }
}

fn skip_credentials_raw(cursor: &mut Cursor<'_>) -> Result<(), String> {
    let cred_count = cursor.read_u32()? as usize;
    for _ in 0..cred_count {
        match cursor.read_u32()? {
            TYPE_SECP_CREDENTIAL => {
                let sig_count = cursor.read_u32()? as usize;
                cursor.read_exact(sig_count.saturating_mul(SECP256K1_SIGNATURE_LEN))?;
            }
            other => return Err(format!("unsupported credential type {}", other)),
        }
    }
    Ok(())
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
        import_source_chain: None,
        imported_inputs: Vec::new(),
        export_destination_chain: None,
        exported_outputs: Vec::new(),
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
        import_source_chain: None,
        imported_inputs: Vec::new(),
        export_destination_chain: None,
        exported_outputs: Vec::new(),
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
        import_source_chain: None,
        imported_inputs: Vec::new(),
        export_destination_chain: None,
        exported_outputs: Vec::new(),
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
) -> Result<Option<StakeOutputDetails>, String> {
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
) -> Result<Option<OwnedOutputDetails>, String> {
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

    fn read_u8(&mut self) -> Result<u8, String> {
        Ok(self.read_exact(1)?[0])
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
        TYPE_ADD_SUBNET_VALIDATOR_TX => parse_add_subnet_validator_tx(cursor),
        TYPE_ADD_DELEGATOR_TX => parse_add_delegator_tx(cursor),
        TYPE_CREATE_CHAIN_TX => parse_create_chain_tx(cursor),
        TYPE_CREATE_SUBNET_TX => parse_create_subnet_tx(cursor),
        TYPE_IMPORT_TX => parse_import_tx(cursor),
        TYPE_EXPORT_TX => parse_export_tx(cursor),
        TYPE_ADVANCE_TIME_TX => parse_advance_time_tx(cursor),
        TYPE_REWARD_VALIDATOR_TX => parse_reward_validator_tx(cursor),
        TYPE_REMOVE_SUBNET_VALIDATOR_TX => parse_remove_subnet_validator_tx(cursor),
        TYPE_ADD_PERMISSIONLESS_VALIDATOR_TX => parse_add_permissionless_validator_tx(cursor),
        TYPE_ADD_PERMISSIONLESS_DELEGATOR_TX => parse_add_permissionless_delegator_tx(cursor),
        TYPE_TRANSFER_SUBNET_OWNERSHIP_TX => parse_transfer_subnet_ownership_tx(cursor),
        TYPE_BASE_TX => parse_base_tx(cursor),
        TYPE_TRANSFORM_SUBNET_TX => parse_transform_subnet_tx(cursor),
        TYPE_CONVERT_SUBNET_TO_L1_TX => parse_convert_subnet_to_l1_tx(cursor),
        TYPE_REGISTER_L1_VALIDATOR_TX => parse_register_l1_validator_tx(cursor),
        TYPE_SET_L1_VALIDATOR_WEIGHT_TX => parse_set_l1_validator_weight_tx(cursor),
        TYPE_INCREASE_L1_VALIDATOR_BALANCE_TX => parse_increase_l1_validator_balance_tx(cursor),
        TYPE_DISABLE_L1_VALIDATOR_TX => parse_disable_l1_validator_tx(cursor),
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

fn parse_pchain_owner(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    let threshold = cursor.read_u32()?;
    let address_count = cursor.read_u32()? as usize;
    let mut addresses = Vec::with_capacity(address_count);
    for _ in 0..address_count {
        addresses.push(Value::String(cb58_encode(&cursor.read_array::<20>()?)));
    }
    Ok(json!({
        "threshold": threshold,
        "addresses": addresses,
    }))
}

fn parse_convert_subnet_to_l1_validator(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    let node_id_len = cursor.read_u32()? as usize;
    let node_id = cursor.read_bytes(node_id_len)?;
    let weight = cursor.read_u64()?;
    let balance = cursor.read_u64()?;
    let public_key = cursor.read_array::<BLS_PUBLIC_KEY_LEN>()?;
    let proof_of_possession = cursor.read_array::<BLS_SIGNATURE_LEN>()?;
    Ok(json!({
        "nodeID": node_id_string(node_id.as_slice().try_into().map_err(|_| "invalid nodeID length".to_string())?),
        "weight": weight,
        "balance": balance,
        "signer": {
            "publicKey": format!("0x{}", hex::encode(public_key)),
            "proofOfPossession": format!("0x{}", hex::encode(proof_of_possession)),
        },
        "remainingBalanceOwner": parse_pchain_owner(cursor)?,
        "deactivationOwner": parse_pchain_owner(cursor)?,
    }))
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

fn parse_add_subnet_validator_tx(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    let mut map = parse_base_tx_fields(cursor)?;
    let mut validator = match parse_validator(cursor)? {
        Value::Object(map) => map,
        _ => unreachable!(),
    };
    validator.insert(
        "subnetID".to_string(),
        Value::String(cb58_encode(&cursor.read_array::<32>()?)),
    );
    map.insert("validator".to_string(), Value::Object(validator));
    map.insert("subnetAuthorization".to_string(), parse_verifiable(cursor)?);
    Ok(Value::Object(map))
}

fn parse_create_chain_tx(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    let mut map = parse_base_tx_fields(cursor)?;
    map.insert(
        "subnetID".to_string(),
        Value::String(cb58_encode(&cursor.read_array::<32>()?)),
    );
    let chain_name_len = cursor.read_u16()? as usize;
    map.insert(
        "chainName".to_string(),
        Value::String(String::from_utf8_lossy(&cursor.read_bytes(chain_name_len)?).into_owned()),
    );
    map.insert(
        "vmID".to_string(),
        Value::String(cb58_encode(&cursor.read_array::<32>()?)),
    );
    let fx_count = cursor.read_u32()? as usize;
    let mut fx_ids = Vec::with_capacity(fx_count);
    for _ in 0..fx_count {
        fx_ids.push(Value::String(cb58_encode(&cursor.read_array::<32>()?)));
    }
    map.insert("fxIDs".to_string(), Value::Array(fx_ids));
    let genesis_len = cursor.read_u32()? as usize;
    map.insert(
        "genesisData".to_string(),
        Value::String(format!(
            "0x{}",
            hex::encode(cursor.read_bytes(genesis_len)?)
        )),
    );
    map.insert("subnetAuthorization".to_string(), parse_verifiable(cursor)?);
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

fn parse_import_tx(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    let mut map = parse_base_tx_fields(cursor)?;
    map.insert(
        "sourceChain".to_string(),
        Value::String(cb58_encode(&cursor.read_array::<32>()?)),
    );
    let input_count = cursor.read_u32()? as usize;
    let mut imported_inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        imported_inputs.push(parse_transferable_input(cursor)?);
    }
    map.insert("importedInputs".to_string(), Value::Array(imported_inputs));
    Ok(Value::Object(map))
}

fn parse_export_tx(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    let mut map = parse_base_tx_fields(cursor)?;
    map.insert(
        "destinationChain".to_string(),
        Value::String(cb58_encode(&cursor.read_array::<32>()?)),
    );
    let output_count = cursor.read_u32()? as usize;
    let mut exported_outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        exported_outputs.push(parse_transferable_output(cursor)?);
    }
    map.insert(
        "exportedOutputs".to_string(),
        Value::Array(exported_outputs),
    );
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

fn parse_transform_subnet_tx(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    let mut map = parse_base_tx_fields(cursor)?;
    map.insert(
        "subnetID".to_string(),
        Value::String(cb58_encode(&cursor.read_array::<32>()?)),
    );
    map.insert(
        "assetID".to_string(),
        Value::String(cb58_encode(&cursor.read_array::<32>()?)),
    );
    map.insert("initialSupply".to_string(), json!(cursor.read_u64()?));
    map.insert("maximumSupply".to_string(), json!(cursor.read_u64()?));
    map.insert("minConsumptionRate".to_string(), json!(cursor.read_u64()?));
    map.insert("maxConsumptionRate".to_string(), json!(cursor.read_u64()?));
    map.insert("minValidatorStake".to_string(), json!(cursor.read_u64()?));
    map.insert("maxValidatorStake".to_string(), json!(cursor.read_u64()?));
    map.insert("minStakeDuration".to_string(), json!(cursor.read_u32()?));
    map.insert("maxStakeDuration".to_string(), json!(cursor.read_u32()?));
    map.insert("minDelegationFee".to_string(), json!(cursor.read_u32()?));
    map.insert("minDelegatorStake".to_string(), json!(cursor.read_u64()?));
    map.insert(
        "maxValidatorWeightFactor".to_string(),
        json!(cursor.read_u8()?),
    );
    map.insert("uptimeRequirement".to_string(), json!(cursor.read_u32()?));
    map.insert("subnetAuthorization".to_string(), parse_verifiable(cursor)?);
    Ok(Value::Object(map))
}

fn parse_convert_subnet_to_l1_tx(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    let mut map = parse_base_tx_fields(cursor)?;
    map.insert(
        "subnetID".to_string(),
        Value::String(cb58_encode(&cursor.read_array::<32>()?)),
    );
    map.insert(
        "chainID".to_string(),
        Value::String(cb58_encode(&cursor.read_array::<32>()?)),
    );
    let address_len = cursor.read_u32()? as usize;
    map.insert(
        "address".to_string(),
        Value::String(format!(
            "0x{}",
            hex::encode(cursor.read_bytes(address_len)?)
        )),
    );
    let validator_count = cursor.read_u32()? as usize;
    let mut validators = Vec::with_capacity(validator_count);
    for _ in 0..validator_count {
        validators.push(parse_convert_subnet_to_l1_validator(cursor)?);
    }
    map.insert("validators".to_string(), Value::Array(validators));
    map.insert("subnetAuthorization".to_string(), parse_verifiable(cursor)?);
    Ok(Value::Object(map))
}

fn parse_register_l1_validator_tx(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    let mut map = parse_base_tx_fields(cursor)?;
    map.insert("balance".to_string(), json!(cursor.read_u64()?));
    map.insert(
        "proofOfPossession".to_string(),
        Value::String(format!(
            "0x{}",
            hex::encode(cursor.read_array::<BLS_SIGNATURE_LEN>()?)
        )),
    );
    let message_len = cursor.read_u32()? as usize;
    map.insert(
        "message".to_string(),
        Value::String(format!(
            "0x{}",
            hex::encode(cursor.read_bytes(message_len)?)
        )),
    );
    Ok(Value::Object(map))
}

fn parse_set_l1_validator_weight_tx(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    let mut map = parse_base_tx_fields(cursor)?;
    let message_len = cursor.read_u32()? as usize;
    map.insert(
        "message".to_string(),
        Value::String(format!(
            "0x{}",
            hex::encode(cursor.read_bytes(message_len)?)
        )),
    );
    Ok(Value::Object(map))
}

fn parse_increase_l1_validator_balance_tx(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    let mut map = parse_base_tx_fields(cursor)?;
    map.insert(
        "validationID".to_string(),
        Value::String(cb58_encode(&cursor.read_array::<32>()?)),
    );
    map.insert("balance".to_string(), json!(cursor.read_u64()?));
    Ok(Value::Object(map))
}

fn parse_disable_l1_validator_tx(cursor: &mut Cursor<'_>) -> Result<Value, String> {
    let mut map = parse_base_tx_fields(cursor)?;
    map.insert(
        "validationID".to_string(),
        Value::String(cb58_encode(&cursor.read_array::<32>()?)),
    );
    map.insert(
        "disableAuthorization".to_string(),
        parse_verifiable(cursor)?,
    );
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

    type ImportInputFixture = ([u8; 32], u32, [u8; 32], u64, Vec<u32>);

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

    fn transferable_input_bytes(
        tx_id: [u8; 32],
        output_index: u32,
        asset_id: [u8; 32],
        amount: u64,
        sig_indices: &[u32],
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&tx_id);
        bytes.extend_from_slice(&output_index.to_be_bytes());
        bytes.extend_from_slice(&asset_id);
        bytes.extend_from_slice(&TYPE_SECP_TRANSFER_INPUT.to_be_bytes());
        bytes.extend_from_slice(&amount.to_be_bytes());
        bytes.extend_from_slice(&(sig_indices.len() as u32).to_be_bytes());
        for sig_index in sig_indices {
            bytes.extend_from_slice(&sig_index.to_be_bytes());
        }
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

    fn pchain_owner_bytes(owner: [u8; 20]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&owner);
        bytes
    }

    fn auth_bytes(sig_indices: &[u32]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&TYPE_SECP_INPUT.to_be_bytes());
        bytes.extend_from_slice(&(sig_indices.len() as u32).to_be_bytes());
        for sig_index in sig_indices {
            bytes.extend_from_slice(&sig_index.to_be_bytes());
        }
        bytes
    }

    fn output_owner_interface_bytes(owners: &[[u8; 20]], locktime: u64, threshold: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&TYPE_OUTPUT_OWNERS.to_be_bytes());
        bytes.extend_from_slice(&locktime.to_be_bytes());
        bytes.extend_from_slice(&threshold.to_be_bytes());
        bytes.extend_from_slice(&(owners.len() as u32).to_be_bytes());
        for owner in owners {
            bytes.extend_from_slice(owner);
        }
        bytes
    }

    fn create_subnet_tx_bytes(owners: &[[u8; 20]], locktime: u64, threshold: u32) -> Vec<u8> {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        tx_bytes.extend_from_slice(&TYPE_CREATE_SUBNET_TX.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&[0u8; 32]);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&output_owner_interface_bytes(owners, locktime, threshold));
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes
    }

    fn create_chain_tx_bytes(
        subnet_id: [u8; 32],
        chain_name: &str,
        vm_id: [u8; 32],
        fx_ids: &[[u8; 32]],
        genesis_data: &[u8],
        sig_indices: &[u32],
    ) -> Vec<u8> {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        tx_bytes.extend_from_slice(&TYPE_CREATE_CHAIN_TX.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&[0u8; 32]);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&subnet_id);
        tx_bytes.extend_from_slice(&(chain_name.len() as u16).to_be_bytes());
        tx_bytes.extend_from_slice(chain_name.as_bytes());
        tx_bytes.extend_from_slice(&vm_id);
        tx_bytes.extend_from_slice(&(fx_ids.len() as u32).to_be_bytes());
        for fx_id in fx_ids {
            tx_bytes.extend_from_slice(fx_id);
        }
        tx_bytes.extend_from_slice(&(genesis_data.len() as u32).to_be_bytes());
        tx_bytes.extend_from_slice(genesis_data);
        tx_bytes.extend_from_slice(&auth_bytes(sig_indices));
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes
    }

    fn import_tx_bytes(source_chain: [u8; 32], imported_inputs: &[ImportInputFixture]) -> Vec<u8> {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        tx_bytes.extend_from_slice(&TYPE_IMPORT_TX.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&[0u8; 32]);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&source_chain);
        tx_bytes.extend_from_slice(&(imported_inputs.len() as u32).to_be_bytes());
        for (tx_id, output_index, asset_id, amount, sig_indices) in imported_inputs {
            tx_bytes.extend_from_slice(&transferable_input_bytes(
                *tx_id,
                *output_index,
                *asset_id,
                *amount,
                sig_indices,
            ));
        }
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes
    }

    fn export_tx_bytes(
        destination_chain: [u8; 32],
        exported_outputs: &[([u8; 32], u64, [u8; 20])],
    ) -> Vec<u8> {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        tx_bytes.extend_from_slice(&TYPE_EXPORT_TX.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&[0u8; 32]);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&destination_chain);
        tx_bytes.extend_from_slice(&(exported_outputs.len() as u32).to_be_bytes());
        for (asset_id, amount, owner) in exported_outputs {
            tx_bytes.extend_from_slice(&transferable_output_bytes(*asset_id, *amount, *owner));
        }
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes
    }

    fn base_tx_fields_with_io(outputs: &[Vec<u8>], inputs: &[Vec<u8>], memo: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.extend_from_slice(&(outputs.len() as u32).to_be_bytes());
        for output in outputs {
            bytes.extend_from_slice(output);
        }
        bytes.extend_from_slice(&(inputs.len() as u32).to_be_bytes());
        for input in inputs {
            bytes.extend_from_slice(input);
        }
        bytes.extend_from_slice(&(memo.len() as u32).to_be_bytes());
        bytes.extend_from_slice(memo);
        bytes
    }

    fn add_subnet_validator_tx_bytes(
        node_id: [u8; 20],
        subnet_id: [u8; 32],
        sig_indices: &[u32],
    ) -> Vec<u8> {
        add_subnet_validator_tx_with_base_io_bytes(node_id, subnet_id, sig_indices, &[], &[])
    }

    fn add_subnet_validator_tx_with_base_io_bytes(
        node_id: [u8; 20],
        subnet_id: [u8; 32],
        sig_indices: &[u32],
        outputs: &[Vec<u8>],
        inputs: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        tx_bytes.extend_from_slice(&TYPE_ADD_SUBNET_VALIDATOR_TX.to_be_bytes());
        tx_bytes.extend_from_slice(&base_tx_fields_with_io(outputs, inputs, &[]));
        tx_bytes.extend_from_slice(&node_id);
        tx_bytes.extend_from_slice(&100u64.to_be_bytes());
        tx_bytes.extend_from_slice(&200u64.to_be_bytes());
        tx_bytes.extend_from_slice(&300u64.to_be_bytes());
        tx_bytes.extend_from_slice(&subnet_id);
        tx_bytes.extend_from_slice(&auth_bytes(sig_indices));
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes
    }

    fn create_chain_tx_with_base_io_bytes(
        outputs: &[Vec<u8>],
        inputs: &[Vec<u8>],
        subnet_id: [u8; 32],
        sig_indices: &[u32],
    ) -> Vec<u8> {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        tx_bytes.extend_from_slice(&TYPE_CREATE_CHAIN_TX.to_be_bytes());
        tx_bytes.extend_from_slice(&base_tx_fields_with_io(outputs, inputs, b"memo"));
        tx_bytes.extend_from_slice(&subnet_id);
        tx_bytes.extend_from_slice(&(3u16).to_be_bytes());
        tx_bytes.extend_from_slice(b"evm");
        tx_bytes.extend_from_slice(&[0x88; 32]);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&(2u32).to_be_bytes());
        tx_bytes.extend_from_slice(&[0xAA, 0xBB]);
        tx_bytes.extend_from_slice(&auth_bytes(sig_indices));
        tx_bytes
    }

    fn import_tx_with_base_io_bytes(
        outputs: &[Vec<u8>],
        inputs: &[Vec<u8>],
        source_chain: [u8; 32],
        imported_inputs: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        tx_bytes.extend_from_slice(&TYPE_IMPORT_TX.to_be_bytes());
        tx_bytes.extend_from_slice(&base_tx_fields_with_io(outputs, inputs, b"memo"));
        tx_bytes.extend_from_slice(&source_chain);
        tx_bytes.extend_from_slice(&(imported_inputs.len() as u32).to_be_bytes());
        for input in imported_inputs {
            tx_bytes.extend_from_slice(input);
        }
        tx_bytes
    }

    fn export_tx_with_base_io_bytes(
        outputs: &[Vec<u8>],
        inputs: &[Vec<u8>],
        destination_chain: [u8; 32],
        exported_outputs: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        tx_bytes.extend_from_slice(&TYPE_EXPORT_TX.to_be_bytes());
        tx_bytes.extend_from_slice(&base_tx_fields_with_io(outputs, inputs, b"memo"));
        tx_bytes.extend_from_slice(&destination_chain);
        tx_bytes.extend_from_slice(&(exported_outputs.len() as u32).to_be_bytes());
        for output in exported_outputs {
            tx_bytes.extend_from_slice(output);
        }
        tx_bytes
    }

    fn transfer_subnet_ownership_tx_bytes(
        subnet_id: [u8; 32],
        owners: &[[u8; 20]],
        locktime: u64,
        threshold: u32,
        sig_indices: &[u32],
    ) -> Vec<u8> {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        tx_bytes.extend_from_slice(&TYPE_TRANSFER_SUBNET_OWNERSHIP_TX.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&[0u8; 32]);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&subnet_id);
        tx_bytes.extend_from_slice(&auth_bytes(sig_indices));
        tx_bytes.extend_from_slice(&output_owner_interface_bytes(owners, locktime, threshold));
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes
    }

    fn signer_pop_bytes(
        public_key: [u8; BLS_PUBLIC_KEY_LEN],
        proof: [u8; BLS_SIGNATURE_LEN],
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&TYPE_SIGNER_PROOF_OF_POSSESSION.to_be_bytes());
        bytes.extend_from_slice(&public_key);
        bytes.extend_from_slice(&proof);
        bytes
    }

    fn remove_subnet_validator_tx_bytes(
        node_id: [u8; 20],
        subnet_id: [u8; 32],
        sig_indices: &[u32],
    ) -> Vec<u8> {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        tx_bytes.extend_from_slice(&TYPE_REMOVE_SUBNET_VALIDATOR_TX.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&[0u8; 32]);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&node_id);
        tx_bytes.extend_from_slice(&subnet_id);
        tx_bytes.extend_from_slice(&auth_bytes(sig_indices));
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes
    }

    fn add_permissionless_validator_tx_bytes(
        node_id: [u8; 20],
        subnet_id: [u8; 32],
        stake_owner: [u8; 20],
        validation_owner: [u8; 20],
        delegation_owner: [u8; 20],
        amount: u64,
        shares: u32,
    ) -> Vec<u8> {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        tx_bytes.extend_from_slice(&TYPE_ADD_PERMISSIONLESS_VALIDATOR_TX.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&[0u8; 32]);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&node_id);
        tx_bytes.extend_from_slice(&1000u64.to_be_bytes());
        tx_bytes.extend_from_slice(&2000u64.to_be_bytes());
        tx_bytes.extend_from_slice(&amount.to_be_bytes());
        tx_bytes.extend_from_slice(&subnet_id);
        tx_bytes.extend_from_slice(&signer_pop_bytes(
            [0x66; BLS_PUBLIC_KEY_LEN],
            [0x77; BLS_SIGNATURE_LEN],
        ));
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&transferable_output_bytes([0xAB; 32], amount, stake_owner));
        tx_bytes.extend_from_slice(&output_owner_interface_bytes(&[validation_owner], 10, 1));
        tx_bytes.extend_from_slice(&output_owner_interface_bytes(&[delegation_owner], 20, 1));
        tx_bytes.extend_from_slice(&shares.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes
    }

    fn add_permissionless_delegator_tx_bytes(
        node_id: [u8; 20],
        subnet_id: [u8; 32],
        stake_owner: [u8; 20],
        reward_owner: [u8; 20],
        amount: u64,
    ) -> Vec<u8> {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        tx_bytes.extend_from_slice(&TYPE_ADD_PERMISSIONLESS_DELEGATOR_TX.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&[0u8; 32]);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&node_id);
        tx_bytes.extend_from_slice(&3000u64.to_be_bytes());
        tx_bytes.extend_from_slice(&4000u64.to_be_bytes());
        tx_bytes.extend_from_slice(&amount.to_be_bytes());
        tx_bytes.extend_from_slice(&subnet_id);
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&transferable_output_bytes([0xAC; 32], amount, stake_owner));
        tx_bytes.extend_from_slice(&output_owner_interface_bytes(&[reward_owner], 30, 1));
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes
    }

    fn signer_bitset(signers: usize) -> Vec<u8> {
        if signers == 0 {
            return Vec::new();
        }
        let mut bytes = vec![0u8; signers.div_ceil(8)];
        for signer in 0..signers {
            let byte_index = signer / 8;
            let bit_index = signer % 8;
            bytes[byte_index] |= 1u8 << bit_index;
        }
        bytes
    }

    fn warp_message_bytes(payload: &[u8], signer_count: usize) -> Vec<u8> {
        let signers = signer_bitset(signer_count);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&[0xAA; 32]);
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&(signers.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&signers);
        bytes.extend_from_slice(&[0xBB; BLS_SIGNATURE_LEN]);
        bytes
    }

    fn addressed_call_bytes(payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&20u32.to_be_bytes());
        bytes.extend_from_slice(&[0xCC; 20]);
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    fn register_l1_validator_message_payload(
        subnet_id: [u8; 32],
        node_id: [u8; 20],
        owner: [u8; 20],
        weight: u64,
        expiry: u64,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&subnet_id);
        bytes.extend_from_slice(&20u32.to_be_bytes());
        bytes.extend_from_slice(&node_id);
        bytes.extend_from_slice(&[0x11; BLS_PUBLIC_KEY_LEN]);
        bytes.extend_from_slice(&expiry.to_be_bytes());
        bytes.extend_from_slice(&pchain_owner_bytes(owner));
        bytes.extend_from_slice(&pchain_owner_bytes(owner));
        bytes.extend_from_slice(&weight.to_be_bytes());
        bytes
    }

    fn l1_validator_weight_message_payload(
        validation_id: [u8; 32],
        nonce: u64,
        weight: u64,
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        bytes.extend_from_slice(&3u32.to_be_bytes());
        bytes.extend_from_slice(&validation_id);
        bytes.extend_from_slice(&nonce.to_be_bytes());
        bytes.extend_from_slice(&weight.to_be_bytes());
        bytes
    }

    fn convert_subnet_to_l1_tx_bytes(
        subnet_id: [u8; 32],
        validators: &[([u8; 20], u64, u64, [u8; 20])],
    ) -> Vec<u8> {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        tx_bytes.extend_from_slice(&TYPE_CONVERT_SUBNET_TO_L1_TX.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&[0u8; 32]);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&subnet_id);
        tx_bytes.extend_from_slice(&[0x44; 32]);
        tx_bytes.extend_from_slice(&3u32.to_be_bytes());
        tx_bytes.extend_from_slice(b"mgr");
        tx_bytes.extend_from_slice(&(validators.len() as u32).to_be_bytes());
        for (node_id, weight, balance, owner) in validators {
            tx_bytes.extend_from_slice(&20u32.to_be_bytes());
            tx_bytes.extend_from_slice(node_id);
            tx_bytes.extend_from_slice(&weight.to_be_bytes());
            tx_bytes.extend_from_slice(&balance.to_be_bytes());
            tx_bytes.extend_from_slice(&[0x22; BLS_PUBLIC_KEY_LEN]);
            tx_bytes.extend_from_slice(&[0x33; BLS_SIGNATURE_LEN]);
            tx_bytes.extend_from_slice(&pchain_owner_bytes(*owner));
            tx_bytes.extend_from_slice(&pchain_owner_bytes(*owner));
        }
        tx_bytes.extend_from_slice(&auth_bytes(&[]));
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes
    }

    fn transform_subnet_tx_bytes(subnet_id: [u8; 32], asset_id: [u8; 32]) -> Vec<u8> {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        tx_bytes.extend_from_slice(&TYPE_TRANSFORM_SUBNET_TX.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&[0u8; 32]);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&subnet_id);
        tx_bytes.extend_from_slice(&asset_id);
        tx_bytes.extend_from_slice(&1_000u64.to_be_bytes());
        tx_bytes.extend_from_slice(&10_000u64.to_be_bytes());
        tx_bytes.extend_from_slice(&1u64.to_be_bytes());
        tx_bytes.extend_from_slice(&100_000u64.to_be_bytes());
        tx_bytes.extend_from_slice(&100u64.to_be_bytes());
        tx_bytes.extend_from_slice(&1_000u64.to_be_bytes());
        tx_bytes.extend_from_slice(&86_400u32.to_be_bytes());
        tx_bytes.extend_from_slice(&(86_400u32 * 30).to_be_bytes());
        tx_bytes.extend_from_slice(&1_000u32.to_be_bytes());
        tx_bytes.extend_from_slice(&25u64.to_be_bytes());
        tx_bytes.push(5u8);
        tx_bytes.extend_from_slice(&80_000u32.to_be_bytes());
        tx_bytes.extend_from_slice(&auth_bytes(&[]));
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes
    }

    fn register_l1_validator_tx_bytes(
        subnet_id: [u8; 32],
        node_id: [u8; 20],
        owner: [u8; 20],
        weight: u64,
        balance: u64,
        expiry: u64,
        signer_count: usize,
    ) -> (Vec<u8>, [u8; 32]) {
        let payload =
            register_l1_validator_message_payload(subnet_id, node_id, owner, weight, expiry);
        let mut validation_id = [0u8; 32];
        validation_id.copy_from_slice(&Sha256::digest(&payload));
        let addressed_call = addressed_call_bytes(&payload);
        let warp_message = warp_message_bytes(&addressed_call, signer_count);

        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        tx_bytes.extend_from_slice(&TYPE_REGISTER_L1_VALIDATOR_TX.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&[0u8; 32]);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&balance.to_be_bytes());
        tx_bytes.extend_from_slice(&[0x55; BLS_SIGNATURE_LEN]);
        tx_bytes.extend_from_slice(&(warp_message.len() as u32).to_be_bytes());
        tx_bytes.extend_from_slice(&warp_message);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        (tx_bytes, validation_id)
    }

    fn set_l1_validator_weight_tx_bytes(
        validation_id: [u8; 32],
        nonce: u64,
        weight: u64,
        signer_count: usize,
    ) -> Vec<u8> {
        let payload = l1_validator_weight_message_payload(validation_id, nonce, weight);
        let addressed_call = addressed_call_bytes(&payload);
        let warp_message = warp_message_bytes(&addressed_call, signer_count);

        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        tx_bytes.extend_from_slice(&TYPE_SET_L1_VALIDATOR_WEIGHT_TX.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&[0u8; 32]);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&(warp_message.len() as u32).to_be_bytes());
        tx_bytes.extend_from_slice(&warp_message);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes
    }

    fn increase_l1_validator_balance_tx_bytes(validation_id: [u8; 32], balance: u64) -> Vec<u8> {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        tx_bytes.extend_from_slice(&TYPE_INCREASE_L1_VALIDATOR_BALANCE_TX.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&[0u8; 32]);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&validation_id);
        tx_bytes.extend_from_slice(&balance.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes
    }

    fn disable_l1_validator_tx_bytes(validation_id: [u8; 32]) -> Vec<u8> {
        let mut tx_bytes = Vec::new();
        tx_bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        tx_bytes.extend_from_slice(&TYPE_DISABLE_L1_VALIDATOR_TX.to_be_bytes());
        tx_bytes.extend_from_slice(&1u32.to_be_bytes());
        tx_bytes.extend_from_slice(&[0u8; 32]);
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes.extend_from_slice(&validation_id);
        tx_bytes.extend_from_slice(&auth_bytes(&[]));
        tx_bytes.extend_from_slice(&0u32.to_be_bytes());
        tx_bytes
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
    fn test_parse_add_subnet_validator_tx_json() {
        let node_id = [0x30; 20];
        let subnet_id = [0x31; 32];
        let tx = add_subnet_validator_tx_bytes(node_id, subnet_id, &[6, 8]);

        let json = parse_platform_tx_json(&tx).unwrap();
        assert_eq!(
            json["unsignedTx"]["validator"]["nodeID"],
            format!("NodeID-{}", cb58_encode(&node_id))
        );
        assert_eq!(json["unsignedTx"]["validator"]["start"], 100);
        assert_eq!(json["unsignedTx"]["validator"]["end"], 200);
        assert_eq!(json["unsignedTx"]["validator"]["weight"], 300);
        assert_eq!(
            json["unsignedTx"]["validator"]["subnetID"],
            cb58_encode(&subnet_id)
        );
        assert_eq!(
            json["unsignedTx"]["subnetAuthorization"],
            json!({ "signatureIndices": [6, 8] })
        );
        assert_eq!(json["credentials"], json!([]));
    }

    #[test]
    fn test_parse_create_chain_tx_json() {
        let subnet_id = [0x31; 32];
        let vm_id = [0x32; 32];
        let fx_a = [0x33; 32];
        let fx_b = [0x34; 32];
        let tx = create_chain_tx_bytes(
            subnet_id,
            "Contracts",
            vm_id,
            &[fx_a, fx_b],
            &[0xDE, 0xAD, 0xBE, 0xEF],
            &[2, 4],
        );

        let json = parse_platform_tx_json(&tx).unwrap();
        assert_eq!(json["unsignedTx"]["subnetID"], cb58_encode(&subnet_id));
        assert_eq!(json["unsignedTx"]["chainName"], "Contracts");
        assert_eq!(json["unsignedTx"]["vmID"], cb58_encode(&vm_id));
        assert_eq!(
            json["unsignedTx"]["fxIDs"],
            json!([cb58_encode(&fx_a), cb58_encode(&fx_b)])
        );
        assert_eq!(json["unsignedTx"]["genesisData"], "0xdeadbeef");
        assert_eq!(
            json["unsignedTx"]["subnetAuthorization"],
            json!({ "signatureIndices": [2, 4] })
        );
        assert_eq!(json["credentials"], json!([]));
    }

    #[test]
    fn test_parse_import_tx_json() {
        let source_chain = [0x35; 32];
        let imported_tx_id = [0x36; 32];
        let asset_id = [0x37; 32];
        let tx = import_tx_bytes(
            source_chain,
            &[(imported_tx_id, 7, asset_id, 99, vec![1, 5])],
        );

        let json = parse_platform_tx_json(&tx).unwrap();
        assert_eq!(
            json["unsignedTx"]["sourceChain"],
            cb58_encode(&source_chain)
        );
        assert_eq!(
            json["unsignedTx"]["importedInputs"][0]["txID"],
            cb58_encode(&imported_tx_id)
        );
        assert_eq!(json["unsignedTx"]["importedInputs"][0]["outputIndex"], 7);
        assert_eq!(
            json["unsignedTx"]["importedInputs"][0]["assetID"],
            cb58_encode(&asset_id)
        );
        assert_eq!(
            json["unsignedTx"]["importedInputs"][0]["input"]["amount"],
            99
        );
        assert_eq!(
            json["unsignedTx"]["importedInputs"][0]["input"]["signatureIndices"],
            json!([1, 5])
        );
        assert_eq!(json["credentials"], json!([]));
    }

    #[test]
    fn test_parse_export_tx_json() {
        let destination_chain = [0x38; 32];
        let asset_id = [0x39; 32];
        let owner = [0x3A; 20];
        let tx = export_tx_bytes(destination_chain, &[(asset_id, 123, owner)]);

        let json = parse_platform_tx_json(&tx).unwrap();
        assert_eq!(
            json["unsignedTx"]["destinationChain"],
            cb58_encode(&destination_chain)
        );
        assert_eq!(
            json["unsignedTx"]["exportedOutputs"][0]["assetID"],
            cb58_encode(&asset_id)
        );
        assert_eq!(
            json["unsignedTx"]["exportedOutputs"][0]["output"]["amount"],
            123
        );
        assert_eq!(
            json["unsignedTx"]["exportedOutputs"][0]["output"]["addresses"],
            json!([cb58_encode(&owner)])
        );
        assert_eq!(json["credentials"], json!([]));
    }

    #[test]
    fn test_summarize_platform_tx_ledger_tracks_base_io_for_admin_txs() {
        let base_output = transferable_output_bytes([0x91; 32], 5, [0x11; 20]);
        let base_input = transferable_input_bytes([0x92; 32], 7, [0x93; 32], 9, &[1]);

        let add_subnet_tx = add_subnet_validator_tx_with_base_io_bytes(
            [0x41; 20],
            [0x42; 32],
            &[0],
            std::slice::from_ref(&base_output),
            std::slice::from_ref(&base_input),
        );
        let add_subnet_ledger = summarize_platform_tx_ledger(&add_subnet_tx).unwrap();
        assert_eq!(add_subnet_ledger.outputs.len(), 1);
        assert_eq!(add_subnet_ledger.inputs.len(), 1);
        assert_eq!(add_subnet_ledger.outputs[0].amount, 5);
        assert_eq!(add_subnet_ledger.inputs[0].tx_id, [0x92; 32]);
        assert_eq!(add_subnet_ledger.inputs[0].output_index, 7);

        let create_chain_tx = create_chain_tx_with_base_io_bytes(
            std::slice::from_ref(&base_output),
            std::slice::from_ref(&base_input),
            [0x43; 32],
            &[2],
        );
        let create_chain_ledger = summarize_platform_tx_ledger(&create_chain_tx).unwrap();
        assert_eq!(create_chain_ledger.outputs.len(), 1);
        assert_eq!(create_chain_ledger.inputs.len(), 1);

        let imported_input = transferable_input_bytes([0x94; 32], 3, [0x95; 32], 11, &[4]);
        let import_tx = import_tx_with_base_io_bytes(
            std::slice::from_ref(&base_output),
            std::slice::from_ref(&base_input),
            [0x44; 32],
            std::slice::from_ref(&imported_input),
        );
        let import_ledger = summarize_platform_tx_ledger(&import_tx).unwrap();
        assert_eq!(import_ledger.outputs.len(), 1);
        assert_eq!(import_ledger.inputs.len(), 1);
        assert_eq!(import_ledger.inputs[0].tx_id, [0x92; 32]);
        assert_eq!(import_ledger.import_source_chain, Some([0x44; 32]));
        assert_eq!(import_ledger.imported_inputs.len(), 1);
        assert_eq!(import_ledger.imported_inputs[0].tx_id, [0x94; 32]);
        assert_eq!(import_ledger.imported_inputs[0].output_index, 3);
        assert!(import_ledger.export_destination_chain.is_none());
        assert!(import_ledger.exported_outputs.is_empty());

        let exported_output = transferable_output_bytes([0x96; 32], 13, [0x12; 20]);
        let export_tx = export_tx_with_base_io_bytes(
            std::slice::from_ref(&base_output),
            std::slice::from_ref(&base_input),
            [0x45; 32],
            std::slice::from_ref(&exported_output),
        );
        let export_ledger = summarize_platform_tx_ledger(&export_tx).unwrap();
        assert_eq!(export_ledger.outputs.len(), 1);
        assert_eq!(export_ledger.inputs.len(), 1);
        assert_eq!(export_ledger.outputs[0].amount, 5);
        assert!(export_ledger.import_source_chain.is_none());
        assert!(export_ledger.imported_inputs.is_empty());
        assert_eq!(export_ledger.export_destination_chain, Some([0x45; 32]));
        assert_eq!(export_ledger.exported_outputs.len(), 1);
        assert_eq!(export_ledger.exported_outputs[0].asset_id, [0x96; 32]);
        assert_eq!(export_ledger.exported_outputs[0].amount, 13);
    }

    #[test]
    fn test_platform_tx_dynamic_fee_gas_supports_add_subnet_validator_tx() {
        let tx = add_subnet_validator_tx_bytes([0x46; 20], [0x47; 32], &[1, 2]);
        let gas = platform_tx_dynamic_fee_gas(&tx, [1, 1, 1, 1]).unwrap();
        assert!(matches!(gas, Some(value) if value > 0));
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

    #[test]
    fn test_parse_convert_subnet_to_l1_tx_json_and_summary() {
        let subnet_id = [0x41; 32];
        let node_id = [0x42; 20];
        let owner = [0x43; 20];
        let tx = convert_subnet_to_l1_tx_bytes(subnet_id, &[(node_id, 10, 20, owner)]);

        let json = parse_platform_tx_json(&tx).unwrap();
        assert_eq!(json["unsignedTx"]["subnetID"], cb58_encode(&subnet_id));
        assert_eq!(json["unsignedTx"]["chainID"], cb58_encode(&[0x44; 32]));
        assert_eq!(json["unsignedTx"]["address"], "0x6d6772");
        assert_eq!(
            json["unsignedTx"]["validators"][0]["nodeID"],
            format!("NodeID-{}", cb58_encode(&node_id))
        );
        assert_eq!(json["unsignedTx"]["validators"][0]["weight"], 10);
        assert_eq!(json["unsignedTx"]["validators"][0]["balance"], 20);
        assert_eq!(
            json["unsignedTx"]["validators"][0]["remainingBalanceOwner"]["addresses"],
            json!([cb58_encode(&owner)])
        );
        assert_eq!(
            json["unsignedTx"]["subnetAuthorization"],
            json!({ "signatureIndices": [] })
        );
        assert_eq!(json["credentials"], json!([]));

        let summary = summarize_platform_l1_validator_tx(&tx).unwrap();
        assert_eq!(
            summary,
            PlatformL1ValidatorTxSummary::ConvertSubnetToL1 {
                validators: vec![PlatformL1ValidatorRegistration {
                    validation_id: append_platform_id(subnet_id, 0),
                    subnet_id,
                    node_id,
                    public_key: [0x22; BLS_PUBLIC_KEY_LEN],
                    remaining_balance_owner: PlatformPChainOwner {
                        threshold: 1,
                        addresses: vec![owner],
                    },
                    deactivation_owner: PlatformPChainOwner {
                        threshold: 1,
                        addresses: vec![owner],
                    },
                    weight: 10,
                    balance: 20,
                }],
            }
        );
    }

    #[test]
    fn test_parse_transform_subnet_tx_json() {
        let subnet_id = [0x46; 32];
        let asset_id = [0x47; 32];
        let tx = transform_subnet_tx_bytes(subnet_id, asset_id);

        let json = parse_platform_tx_json(&tx).unwrap();
        assert_eq!(json["unsignedTx"]["subnetID"], cb58_encode(&subnet_id));
        assert_eq!(json["unsignedTx"]["assetID"], cb58_encode(&asset_id));
        assert_eq!(json["unsignedTx"]["initialSupply"], 1_000);
        assert_eq!(json["unsignedTx"]["maximumSupply"], 10_000);
        assert_eq!(json["unsignedTx"]["minConsumptionRate"], 1);
        assert_eq!(json["unsignedTx"]["maxConsumptionRate"], 100_000);
        assert_eq!(json["unsignedTx"]["minValidatorStake"], 100);
        assert_eq!(json["unsignedTx"]["maxValidatorStake"], 1_000);
        assert_eq!(json["unsignedTx"]["minStakeDuration"], 86_400);
        assert_eq!(json["unsignedTx"]["maxStakeDuration"], 86_400 * 30);
        assert_eq!(json["unsignedTx"]["minDelegationFee"], 1_000);
        assert_eq!(json["unsignedTx"]["minDelegatorStake"], 25);
        assert_eq!(json["unsignedTx"]["maxValidatorWeightFactor"], 5);
        assert_eq!(json["unsignedTx"]["uptimeRequirement"], 80_000);
        assert_eq!(
            json["unsignedTx"]["subnetAuthorization"],
            json!({ "signatureIndices": [] })
        );
        assert_eq!(json["credentials"], json!([]));
    }

    #[test]
    fn test_parse_create_subnet_tx_json() {
        let owner_a = [0x48; 20];
        let owner_b = [0x49; 20];
        let tx = create_subnet_tx_bytes(&[owner_a, owner_b], 55, 2);

        let json = parse_platform_tx_json(&tx).unwrap();
        assert_eq!(json["unsignedTx"]["networkID"], 1);
        assert_eq!(
            json["unsignedTx"]["blockchainID"],
            "11111111111111111111111111111111LpoYY"
        );
        assert_eq!(json["unsignedTx"]["owner"]["locktime"], 55);
        assert_eq!(json["unsignedTx"]["owner"]["threshold"], 2);
        assert_eq!(
            json["unsignedTx"]["owner"]["addresses"],
            json!([cb58_encode(&owner_a), cb58_encode(&owner_b)])
        );
        assert_eq!(json["credentials"], json!([]));
    }

    #[test]
    fn test_parse_transfer_subnet_ownership_tx_json() {
        let subnet_id = [0x4A; 32];
        let owner_a = [0x4B; 20];
        let owner_b = [0x4C; 20];
        let tx = transfer_subnet_ownership_tx_bytes(subnet_id, &[owner_a, owner_b], 77, 2, &[3, 7]);

        let json = parse_platform_tx_json(&tx).unwrap();
        assert_eq!(json["unsignedTx"]["subnetID"], cb58_encode(&subnet_id));
        assert_eq!(
            json["unsignedTx"]["subnetAuthorization"],
            json!({ "signatureIndices": [3, 7] })
        );
        assert_eq!(json["unsignedTx"]["newOwner"]["locktime"], 77);
        assert_eq!(json["unsignedTx"]["newOwner"]["threshold"], 2);
        assert_eq!(
            json["unsignedTx"]["newOwner"]["addresses"],
            json!([cb58_encode(&owner_a), cb58_encode(&owner_b)])
        );
        assert_eq!(json["credentials"], json!([]));
    }

    #[test]
    fn test_parse_remove_subnet_validator_tx_json() {
        let node_id = [0x4D; 20];
        let subnet_id = [0x4E; 32];
        let tx = remove_subnet_validator_tx_bytes(node_id, subnet_id, &[1, 9]);

        let json = parse_platform_tx_json(&tx).unwrap();
        assert_eq!(
            json["unsignedTx"]["nodeID"],
            format!("NodeID-{}", cb58_encode(&node_id))
        );
        assert_eq!(json["unsignedTx"]["subnetID"], cb58_encode(&subnet_id));
        assert_eq!(
            json["unsignedTx"]["subnetAuthorization"],
            json!({ "signatureIndices": [1, 9] })
        );
        assert_eq!(json["credentials"], json!([]));
    }

    #[test]
    fn test_parse_add_permissionless_validator_tx_json() {
        let node_id = [0x4F; 20];
        let subnet_id = [0x50; 32];
        let stake_owner = [0x51; 20];
        let validation_owner = [0x52; 20];
        let delegation_owner = [0x53; 20];
        let tx = add_permissionless_validator_tx_bytes(
            node_id,
            subnet_id,
            stake_owner,
            validation_owner,
            delegation_owner,
            500,
            12_345,
        );

        let json = parse_platform_tx_json(&tx).unwrap();
        assert_eq!(
            json["unsignedTx"]["validator"]["nodeID"],
            format!("NodeID-{}", cb58_encode(&node_id))
        );
        assert_eq!(json["unsignedTx"]["validator"]["start"], 1000);
        assert_eq!(json["unsignedTx"]["validator"]["end"], 2000);
        assert_eq!(json["unsignedTx"]["validator"]["weight"], 500);
        assert_eq!(json["unsignedTx"]["subnetID"], cb58_encode(&subnet_id));
        assert_eq!(
            json["unsignedTx"]["signer"]["publicKey"],
            Value::String(format!("0x{}", "66".repeat(BLS_PUBLIC_KEY_LEN)))
        );
        assert_eq!(
            json["unsignedTx"]["signer"]["proofOfPossession"],
            Value::String(format!("0x{}", "77".repeat(BLS_SIGNATURE_LEN)))
        );
        assert_eq!(
            json["unsignedTx"]["stake"][0]["assetID"],
            cb58_encode(&[0xAB; 32])
        );
        assert_eq!(
            json["unsignedTx"]["validationRewardsOwner"]["addresses"],
            json!([cb58_encode(&validation_owner)])
        );
        assert_eq!(
            json["unsignedTx"]["delegationRewardsOwner"]["addresses"],
            json!([cb58_encode(&delegation_owner)])
        );
        assert_eq!(json["unsignedTx"]["shares"], 12_345);
        assert_eq!(json["credentials"], json!([]));
    }

    #[test]
    fn test_parse_add_permissionless_delegator_tx_json() {
        let node_id = [0x54; 20];
        let subnet_id = [0x55; 32];
        let stake_owner = [0x56; 20];
        let reward_owner = [0x57; 20];
        let tx = add_permissionless_delegator_tx_bytes(
            node_id,
            subnet_id,
            stake_owner,
            reward_owner,
            700,
        );

        let json = parse_platform_tx_json(&tx).unwrap();
        assert_eq!(
            json["unsignedTx"]["validator"]["nodeID"],
            format!("NodeID-{}", cb58_encode(&node_id))
        );
        assert_eq!(json["unsignedTx"]["validator"]["start"], 3000);
        assert_eq!(json["unsignedTx"]["validator"]["end"], 4000);
        assert_eq!(json["unsignedTx"]["validator"]["weight"], 700);
        assert_eq!(json["unsignedTx"]["subnetID"], cb58_encode(&subnet_id));
        assert_eq!(
            json["unsignedTx"]["stake"][0]["assetID"],
            cb58_encode(&[0xAC; 32])
        );
        assert_eq!(
            json["unsignedTx"]["rewardsOwner"]["addresses"],
            json!([cb58_encode(&reward_owner)])
        );
        assert_eq!(json["credentials"], json!([]));
    }

    #[test]
    fn test_parse_register_and_set_weight_l1_validator_txs() {
        let subnet_id = [0x51; 32];
        let node_id = [0x52; 20];
        let owner = [0x53; 20];
        let (register_tx, validation_id) =
            register_l1_validator_tx_bytes(subnet_id, node_id, owner, 77, 33, 999, 2);

        let register_json = parse_platform_tx_json(&register_tx).unwrap();
        assert_eq!(register_json["unsignedTx"]["balance"], 33);
        assert_eq!(
            register_json["unsignedTx"]["proofOfPossession"],
            Value::String(format!("0x{}", "55".repeat(BLS_SIGNATURE_LEN)))
        );
        assert!(register_json["unsignedTx"]["message"]
            .as_str()
            .unwrap()
            .starts_with("0x"));
        assert_eq!(register_json["credentials"], json!([]));

        let register_summary = summarize_platform_l1_validator_tx(&register_tx).unwrap();
        assert_eq!(
            register_summary,
            PlatformL1ValidatorTxSummary::RegisterL1Validator {
                validator: PlatformL1ValidatorRegistration {
                    validation_id,
                    subnet_id,
                    node_id,
                    public_key: [0x11; BLS_PUBLIC_KEY_LEN],
                    remaining_balance_owner: PlatformPChainOwner {
                        threshold: 1,
                        addresses: vec![owner],
                    },
                    deactivation_owner: PlatformPChainOwner {
                        threshold: 1,
                        addresses: vec![owner],
                    },
                    weight: 77,
                    balance: 33,
                },
            }
        );

        let set_weight_tx = set_l1_validator_weight_tx_bytes(validation_id, 5, 88, 1);
        let set_weight_json = parse_platform_tx_json(&set_weight_tx).unwrap();
        assert!(set_weight_json["unsignedTx"]["message"]
            .as_str()
            .unwrap()
            .starts_with("0x"));
        assert_eq!(set_weight_json["credentials"], json!([]));

        let set_weight_summary = summarize_platform_l1_validator_tx(&set_weight_tx).unwrap();
        assert_eq!(
            set_weight_summary,
            PlatformL1ValidatorTxSummary::SetL1ValidatorWeight {
                validation_id,
                nonce: 5,
                weight: 88,
            }
        );
    }

    #[test]
    fn test_parse_increase_and_disable_l1_validator_txs() {
        let validation_id = [0x61; 32];

        let increase_tx = increase_l1_validator_balance_tx_bytes(validation_id, 44);
        let increase_json = parse_platform_tx_json(&increase_tx).unwrap();
        assert_eq!(
            increase_json["unsignedTx"]["validationID"],
            cb58_encode(&validation_id)
        );
        assert_eq!(increase_json["unsignedTx"]["balance"], 44);
        assert_eq!(increase_json["credentials"], json!([]));

        let increase_summary = summarize_platform_l1_validator_tx(&increase_tx).unwrap();
        assert_eq!(
            increase_summary,
            PlatformL1ValidatorTxSummary::IncreaseL1ValidatorBalance {
                validation_id,
                balance: 44,
            }
        );

        let disable_tx = disable_l1_validator_tx_bytes(validation_id);
        let disable_json = parse_platform_tx_json(&disable_tx).unwrap();
        assert_eq!(
            disable_json["unsignedTx"]["validationID"],
            cb58_encode(&validation_id)
        );
        assert_eq!(
            disable_json["unsignedTx"]["disableAuthorization"],
            json!({ "signatureIndices": [] })
        );
        assert_eq!(disable_json["credentials"], json!([]));

        let disable_summary = summarize_platform_l1_validator_tx(&disable_tx).unwrap();
        assert_eq!(
            disable_summary,
            PlatformL1ValidatorTxSummary::DisableL1Validator { validation_id }
        );
    }
}
