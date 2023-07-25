#![feature(offset_of)]

use codec::{Decode, Encode};
use external_actor_queue::{events::Event as ExtActorEvent, io::KzgParamsNoVec};
use gclient::{DispatchStatus, EventListener, EventProcessor, GearApi, Result, WSAddress};
use gear_core::ids::{MessageId, ProgramId};
use halo2_proofs::{
    arithmetic::Field,
    circuit,
    halo2curves::{
        bn256::{Bn256, Fr, G1Affine},
        ff::PrimeField,
        group::{Curve, Group},
        pairing::Engine,
        serde::SerdeObject,
    },
    plonk::{keygen_vk, verify_proof, Advice, Column, Fixed, Selector, TableColumn, VerifyingKey},
    poly::{
        commitment::{Params, ParamsProver},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::VerifierSHPLONK,
            strategy::SingleStrategy,
        },
    },
    transcript::{Blake2bRead, Challenge255, TranscriptRead, TranscriptReadBuffer},
    SerdeFormat,
};
use itertools::Itertools;
use std::{
    collections::BTreeSet,
    fs::File,
    io::{BufReader, Read},
};
use zkml::{
    gadgets::gadget::{GadgetConfig, GadgetType},
    utils::loader::ModelMsgpack,
};

const WASM_PATH: &str =
    "./external-actor-queue/target/wasm32-unknown-unknown/release/external_actor_queue.opt.wasm";

#[derive(codec::Encode)]
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
            eta: config.eta as u64, // WARNING
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

#[tokio::main]
async fn main() {
    let api = GearApi::dev().await.unwrap();
    let mut listener = api.subscribe().await.unwrap();
    assert!(listener.blocks_running().await.unwrap());

    let (message_id, program_id, _) = api
        .upload_program_bytes_by_path(
            WASM_PATH,
            gclient::now_micros().to_le_bytes(),
            &vec![],
            api.block_gas_limit().unwrap(),
            0,
        )
        .await
        .unwrap();

    assert!(listener
        .message_processed(message_id)
        .await
        .unwrap()
        .succeed());

    initializator(program_id).await;

    futures::future::join(client(program_id), prover(program_id)).await;
}

#[derive(Debug, Clone)]
pub struct ParamsKZGLayout<E: Engine> {
    k: u32,
    n: u64,
    g: Vec<E::G1Affine>,
    g_lagrange: Vec<E::G1Affine>,
    g2: E::G2Affine,
    s_g2: E::G2Affine,
}

fn get_kzg_data() -> (Vec<Vec<u8>>, Vec<Vec<u8>>, KzgParamsNoVec) {
    let mut params = zkml::utils::proving_kzg::get_kzg_params("./params_kzg", 15);

    unsafe {
        let params: ParamsKZGLayout<Bn256> = std::mem::transmute(params);

        let g2_data: [u8; 128] = std::mem::transmute(params.g2);
        let s_g2_data: [u8; 128] = std::mem::transmute(params.s_g2);

        let g: Vec<Vec<u8>> = params.g.into_iter().map(|g| g.to_raw_bytes()).collect();
        let g_lagrange: Vec<Vec<u8>> = params
            .g_lagrange
            .into_iter()
            .map(|g_lagrange| g_lagrange.to_raw_bytes())
            .collect();

        (
            g,
            g_lagrange,
            KzgParamsNoVec {
                k: params.k,
                n: params.n,
                g2_data: g2_data,
                s_g2_data: s_g2_data,
            },
        )
    }
}

async fn send_message_and_wait_for_success<E: Encode>(
    api: &GearApi,
    listener: &mut EventListener,
    pid: ProgramId,
    payload: E,
) -> MessageId {
    let (message_id, _) = api
        .send_message(pid, payload, api.block_gas_limit().unwrap(), 0)
        .await
        .unwrap();
    assert!(listener
        .message_processed(message_id)
        .await
        .unwrap()
        .succeed());

    message_id
}

async fn initializator(program_id: ProgramId) {
    let api = GearApi::init_with(WSAddress::dev(), "//Bob").await.unwrap();
    let mut listener = api.subscribe().await.unwrap();
    assert!(listener.blocks_running().await.unwrap());

    println!("Init::FillVkeyMap sending...");
    let payload = external_actor_queue::io::Incoming::Initializing(
        external_actor_queue::io::InitializingMessage::FillVkeyMap,
    );
    let _ = send_message_and_wait_for_success(&api, &mut listener, program_id, payload).await;
    println!("Init::FillVkeyMap sent");

    let (g_data, g_lagrange_data, kzg_params) = get_kzg_data();
    for (i, (g_data, g_lagrange_data)) in itertools::izip!(
        g_data.chunks(g_data.len() / 128),
        g_lagrange_data.chunks(g_lagrange_data.len() / 128),
    )
    .enumerate()
    {
        println!("Init::LoadKZG sending... {i}");
        let payload = external_actor_queue::io::Incoming::Initializing(
            external_actor_queue::io::InitializingMessage::LoadKZG {
                g_data: g_data.to_vec(),
                g_lagrange_data: g_lagrange_data.to_vec(),
            },
        );
        let _ = send_message_and_wait_for_success(&api, &mut listener, program_id, payload).await;
        println!("Init::LoadKZG sent");
    }

    let model =
        zkml::utils::loader::load_model_msgpack("./model/model.msgpack", "./model/inp.msgpack");
    let circuit = zkml::model::ModelCircuit::<Fr>::generate_from_msgpack(model, true);
    let gadget_config_data = unsafe {
        GadgetConfigCodec::from(zkml::model::GADGET_CONFIG.lock().unwrap().clone()).encode()
    };

    println!("Init::Finalize sending...");
    let payload = external_actor_queue::io::Incoming::Initializing(
        external_actor_queue::io::InitializingMessage::Finalize {
            kzg_params,
            gadget_config_data,
        },
    );
    let _ = send_message_and_wait_for_success(&api, &mut listener, program_id, payload).await;
    println!("Init::Finalize sent");
}

async fn client(program_id: ProgramId) {
    let api = GearApi::init_with(WSAddress::dev(), "//Bob").await.unwrap();
    let mut listener = api.subscribe().await.unwrap();
    assert!(listener.blocks_running().await.unwrap());

    println!("Client::SubmitInput sending...");
    let input = {
        let input_file = File::open("./model/inp.msgpack").unwrap();
        let mut reader = BufReader::new(input_file);
        let mut input = vec![];
        reader.read_to_end(&mut input);
        input
    };

    let payload = external_actor_queue::io::Incoming::Client(
        external_actor_queue::io::ClientMessage::SubmitInput {
            input: input.clone(),
        },
    );
    let new_payload_message_id =
        send_message_and_wait_for_success(&api, &mut listener, program_id, payload).await;
    println!("Client::SubmitInput sent");

    println!("Client::VerifierKey sending...");
    let model = zkml::utils::loader::load_model_msgpack_and_bytes("./model/model.msgpack", input);
    let circuit = zkml::model::ModelCircuit::<Fr>::generate_from_msgpack(model, true);
    let params_kzg = zkml::utils::proving_kzg::get_kzg_params("./params_kzg", 15);
    let vkey = keygen_vk(&params_kzg, &circuit).unwrap();
    let vkey_data = vkey.to_bytes(SerdeFormat::RawBytes);

    let payload = external_actor_queue::io::Incoming::Client(
        external_actor_queue::io::ClientMessage::VerifierKey { vkey_data },
    );
    let _ = send_message_and_wait_for_success(&api, &mut listener, program_id, payload).await;
    println!("Client::VerifierKey sent");

    for i in 0..34 {
        println!("Client::Verify {i} sending...");
        let payload = external_actor_queue::io::Incoming::Client(
            external_actor_queue::io::ClientMessage::Verify,
        );
        let _ = send_message_and_wait_for_success(&api, &mut listener, program_id, payload).await;
        println!("Client::Verify {i} sent");
    }

    loop {
        let mut msg = api.get_mailbox_messages(1).await.unwrap();
        if msg.len() == 1 {
            let msg = msg.pop().unwrap().0;
            api.claim_value(msg.id()).await.unwrap();
            let event = ExtActorEvent::decode(&mut msg.payload()).unwrap();

            match event {
                ExtActorEvent::ProofValidated { validity } => {
                    panic!("Validated {}", validity);
                }
                _ => {
                    println!("WHAT?");
                }
            }
        }
    }
}

async fn prover(program_id: ProgramId) {
    let api = GearApi::init_with(WSAddress::dev(), "//Alice")
        .await
        .unwrap();
    let mut listener = api.subscribe().await.unwrap();
    assert!(listener.blocks_running().await.unwrap());

    loop {
        let mut msg = api.get_mailbox_messages(1).await.unwrap();
        if msg.len() == 1 {
            let msg = msg.pop().unwrap().0;
            api.claim_value(msg.id()).await.unwrap();
            let event = ExtActorEvent::decode(&mut msg.payload()).unwrap();

            match event {
                ExtActorEvent::NewPayload { client } => {
                    let input: Vec<([u8; 32], Vec<u8>)> = api.read_state(program_id).await.unwrap();
                    let input = input
                        .into_iter()
                        .find(|inp| inp.0 == client)
                        .expect("Record about provided input in state")
                        .1;

                    let model = zkml::utils::loader::load_model_msgpack_and_bytes(
                        "./model/model.msgpack",
                        input,
                    );
                    let circuit =
                        zkml::model::ModelCircuit::<Fr>::generate_from_msgpack(model, true);
                    // Writes ./proof and ./public_vals
                    zkml::utils::proving_kzg::time_circuit_kzg(circuit);

                    let proof_data = std::fs::read("./proof").unwrap();
                    let pub_vals_data = std::fs::read("./public_vals").unwrap();

                    let payload = external_actor_queue::io::Incoming::Prover(
                        external_actor_queue::io::ProverMessage::SubmitProof {
                            client,
                            proof_data,
                            pub_vals_data,
                        },
                    );

                    println!("Prover::SubmitProof sending...");
                    let _ =
                        send_message_and_wait_for_success(&api, &mut listener, program_id, payload)
                            .await;
                    println!("Prover::SubmitProof sent");
                }
                ExtActorEvent::InvalidProof { client } => {
                    panic!("Invalid proof");
                }
                _ => {}
            }
        }
    }
}
