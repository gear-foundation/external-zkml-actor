#![feature(offset_of)]

use codec::{Decode, Encode};
use external_actor_queue::events::Event as ExtActorEvent;
use external_actor_queue::io::KzgParamsNoVec;
use external_actor_queue::queue::Message as ExtQueueMessage;
use gclient::EventListener;
use gclient::{DispatchStatus, EventProcessor, GearApi, Result, WSAddress};
use gear_core::ids::MessageId;
use gear_core::ids::ProgramId;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::halo2curves::ff::PrimeField;
use halo2_proofs::halo2curves::group::Curve;
use halo2_proofs::halo2curves::group::Group;
use halo2_proofs::halo2curves::pairing::Engine;
use halo2_proofs::halo2curves::serde::SerdeObject;
use halo2_proofs::poly::commitment::{Params, ParamsProver};
use halo2_proofs::transcript::TranscriptRead;
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{verify_proof, VerifyingKey},
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::VerifierSHPLONK,
        strategy::SingleStrategy,
    },
    transcript::{Blake2bRead, Challenge255, TranscriptReadBuffer},
    SerdeFormat,
};
use itertools::Itertools;
use zkml::gadgets::gadget::GadgetConfig;

use std::io::Read;
use std::{collections::BTreeSet, fs::File, io::BufReader};
use zkml::utils::loader::ModelMsgpack;

use halo2_proofs::plonk::{Advice, Column, Fixed, Selector, TableColumn};
use zkml::gadgets::gadget::GadgetType;

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

    // Upload and init program.
    let init = external_actor_queue::io::Initialization {
        actor_code_hash: [0; 32],
        actor_state_hash: [0; 32],
    };
    let (message_id, program_id, _) = api
        .upload_program_bytes_by_path(
            WASM_PATH,
            gclient::now_micros().to_le_bytes(),
            &init.encode(),
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

    futures::future::join(sender(program_id), external_actor(program_id)).await;
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

impl<E: Engine> ParamsKZGLayout<E> {
    const fn g_data_offset() -> isize {
        std::mem::offset_of!(Self, g) as isize + 8
    }

    const fn g_lagrange_data_offset() -> isize {
        std::mem::offset_of!(Self, g_lagrange) as isize + 8
    }
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

async fn sender(program_id: ProgramId) {
    let api = GearApi::init_with(WSAddress::dev(), "//Bob").await.unwrap();
    let mut listener = api.subscribe().await.unwrap();
    assert!(listener.blocks_running().await.unwrap());

    // Send request to actor.
    println!("Incoming::New sending...");
    let model =
        zkml::utils::loader::load_model_msgpack("./model/model.msgpack", "./model/inp.msgpack");
    let model_data = rmp_serde::to_vec(&model).unwrap();
    let payload = external_actor_queue::io::Incoming::New(model_data);
    let new_payload_message_id =
        send_message_and_wait_for_success(&api, &mut listener, program_id, payload).await;
    println!("Incoming::New sent");

    let (g_data, g_lagrange_data, kzg_params) = get_kzg_data();
    for (i, (g_data, g_lagrange_data)) in itertools::izip!(
        g_data.chunks(g_data.len() / 128),
        g_lagrange_data.chunks(g_lagrange_data.len() / 128),
    )
    .enumerate()
    .skip(127)
    {
        println!("Incoming::LoadKZG sending... {i}");
        let payload = external_actor_queue::io::Incoming::LoadKzg {
            g_data: g_data.to_vec(),
            g_lagrange_data: g_lagrange_data.to_vec(),
        };
        let _ = send_message_and_wait_for_success(&api, &mut listener, program_id, payload).await;
        println!("Incoming::LoadKZG sent");
    }

    println!("Incoming::FillVkeyMap sending...");
    let payload = external_actor_queue::io::Incoming::FillVkeyMap;
    let _ = send_message_and_wait_for_success(&api, &mut listener, program_id, payload).await;
    println!("Incoming::FillVkeyMap sent");

    println!("Incoming::FillDataForVerify sending...");
    let outcome = std::fs::read("./public_vals").unwrap();
    let verifier_key = std::fs::read("./vkey").unwrap();
    let payload = external_actor_queue::io::Incoming::FillDataForVerify {
        verifier_key,
        outcome,
        kzg_params,
    };
    let _ = send_message_and_wait_for_success(&api, &mut listener, program_id, payload).await;
    println!("Incoming::FillDataForVerify sent");

    println!("Incoming::GenerateMSMStage1 sending...");
    let payload = external_actor_queue::io::Incoming::GenerateMSMStage1 {
        message_id: new_payload_message_id.encode(),
    };
    let _ = send_message_and_wait_for_success(&api, &mut listener, program_id, payload).await;
    println!("Incoming::GenerateMSMStage1 sent");

    println!("Incoming::GenerateMSMStage2 sending...");
    let payload = external_actor_queue::io::Incoming::GenerateMSMStage2;
    let _ = send_message_and_wait_for_success(&api, &mut listener, program_id, payload).await;
    println!("Incoming::GenerateMSMStage2 sent");

    for i in 0..8 {
        println!("Incoming::EvaluateMSM {} sending...", i);
        let payload = external_actor_queue::io::Incoming::EvaluateMSM;
        let _ = send_message_and_wait_for_success(&api, &mut listener, program_id, payload).await;
        println!("Incoming::EvaluateMSM sent");
    }

    println!("Incoming::Verify sending...");
    let payload = external_actor_queue::io::Incoming::Verify;
    let _ = send_message_and_wait_for_success(&api, &mut listener, program_id, payload).await;
    println!("Incoming::Verify sent");

    panic!("DONE");
}

async fn external_actor(program_id: ProgramId) {
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
            let event = ExtActorEvent::decode(&mut msg.payload_bytes()).unwrap();

            match event {
                ExtActorEvent::NewPayload { index, size } => {
                    let queue: Vec<ExtQueueMessage> = api.read_state(program_id).await.unwrap();
                    let msg = &queue[index as usize];
                    let model: ModelMsgpack = rmp_serde::from_slice(&msg.payload).unwrap();
                    let circuit =
                        zkml::model::ModelCircuit::<Fr>::generate_from_msgpack(model, true);

                    // It's weird behaviour but this command fills GadgetConfig.
                    zkml::utils::proving_kzg::verify_circuit_kzg(
                        circuit,
                        "./vkey",
                        "./proof",
                        "./public_vals",
                    );

                    let gadget_config = unsafe {
                        GadgetConfigCodec::from(zkml::model::GADGET_CONFIG.lock().unwrap().clone())
                            .encode()
                    };

                    let proof = std::fs::read("./proof").unwrap();

                    let payload = external_actor_queue::io::Incoming::Proof {
                        index,
                        proof,
                        gadget_config,
                    };

                    println!("Incoming::Proof sending...");
                    let _ =
                        send_message_and_wait_for_success(&api, &mut listener, program_id, payload)
                            .await;
                    println!("Incoming::Proof sent");
                }
                ExtActorEvent::InvalidProof { index } => {
                    panic!("Invalid proof");
                }
            }
        }
    }
}
