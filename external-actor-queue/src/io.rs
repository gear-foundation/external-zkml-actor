use codec::{Decode, Encode};
use gstd::prelude::*;

use gstd::ActorId;
use halo2_proofs_wasm::plonk::{Advice, Column, Fixed, Selector, TableColumn};
use zkml_wasm::gadgets::gadget::GadgetConfig;
use zkml_wasm::gadgets::gadget::GadgetType;

#[derive(codec::Encode, codec::Decode)]
pub struct GadgetConfigCodec {
    pub used_gadgets: BTreeSet<GadgetType>,
    pub columns: Vec<Column<Advice>>,
    pub fixed_columns: Vec<Column<Fixed>>,
    pub selectors: Vec<(GadgetType, Vec<Selector>)>,
    pub tables: Vec<(GadgetType, Vec<TableColumn>)>,
    pub maps: Vec<(GadgetType, Vec<Vec<(i64, i64)>>)>,
    pub scale_factor: u64,
    pub shift_min_val: i64, // MUST be divisible by 2 * scale_factor
    pub num_rows: u64,
    pub num_cols: u64,
    pub k: u64,
    pub eta: u64,
    pub min_val: i64,
    pub max_val: i64,
    pub div_outp_min_val: i64,
    pub use_selectors: bool,
    pub commit_before: Vec<Vec<i64>>,
    pub commit_after: Vec<Vec<i64>>,
    pub num_bits_per_elem: i64,
}

impl From<GadgetConfigCodec> for GadgetConfig {
    fn from(config: GadgetConfigCodec) -> GadgetConfig {
        GadgetConfig {
            used_gadgets: config.used_gadgets,
            columns: config.columns,
            fixed_columns: config.fixed_columns,
            selectors: config.selectors.into_iter().collect(),
            tables: config.tables.into_iter().collect(),
            maps: config
                .maps
                .into_iter()
                .map(|(k, v)| (k, v.into_iter().map(|v| v.into_iter().collect()).collect()))
                .collect(),
            scale_factor: config.scale_factor,
            shift_min_val: config.shift_min_val,
            num_rows: config.num_rows,
            num_cols: config.num_cols,
            k: config.k,
            eta: config.eta,
            min_val: config.min_val,
            max_val: config.max_val,
            div_outp_min_val: config.div_outp_min_val,
            use_selectors: config.use_selectors,
            commit_before: config.commit_before,
            commit_after: config.commit_after,
            num_bits_per_elem: config.num_bits_per_elem,
        }
    }
}

impl From<GadgetConfig> for GadgetConfigCodec {
    fn from(config: GadgetConfig) -> GadgetConfigCodec {
        GadgetConfigCodec {
            used_gadgets: config.used_gadgets,
            columns: config.columns,
            fixed_columns: config.fixed_columns,
            selectors: config.selectors.into_iter().collect(),
            tables: config.tables.into_iter().collect(),
            maps: config
                .maps
                .into_iter()
                .map(|(k, v)| (k, v.into_iter().map(|v| v.into_iter().collect()).collect()))
                .collect(),
            scale_factor: config.scale_factor,
            shift_min_val: config.shift_min_val,
            num_rows: config.num_rows,
            num_cols: config.num_cols,
            k: config.k,
            eta: config.eta,
            min_val: config.min_val,
            max_val: config.max_val,
            div_outp_min_val: config.div_outp_min_val,
            use_selectors: config.use_selectors,
            commit_before: config.commit_before,
            commit_after: config.commit_after,
            num_bits_per_elem: config.num_bits_per_elem,
        }
    }
}

#[derive(Encode, Decode, Debug, TypeInfo)]
pub struct KzgParamsNoVec {
    pub k: u32,
    pub n: u64,
    pub g2_data: [u8; 128],
    pub s_g2_data: [u8; 128],
}

#[derive(Encode, Decode, Debug, TypeInfo)]
pub enum Incoming {
    Initializing(InitializingMessage),
    Prover(ProverMessage),
    Client(ClientMessage),
}

#[derive(Encode, Decode, Debug, TypeInfo)]
pub enum InitializingMessage {
    LoadKZG {
        g_data: Vec<Vec<u8>>,
        g_lagrange_data: Vec<Vec<u8>>,
    },
    FillVkeyMap,
    Finalize {
        kzg_params: KzgParamsNoVec,
        gadget_config_data: Vec<u8>,
    },
}

#[derive(Encode, Decode, Debug, TypeInfo)]
pub enum ProverMessage {
    SubmitProof {
        client: ActorId,
        proof_data: Vec<u8>,
        pub_vals_data: Vec<u8>,
    },
}

#[derive(Encode, Decode, Debug, TypeInfo)]
pub enum ClientMessage {
    SubmitInput { input: Vec<u8> },
    VerifierKey { vkey_data: Vec<u8> },
    Verify,
}
