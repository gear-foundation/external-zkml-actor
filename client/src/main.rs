#![feature(offset_of)]

use codec::{Decode, Encode};
use external_ml_actor_contract::{self as contract, io::KzgParamsNoVec};
use gclient::{DispatchStatus, EventListener, EventProcessor, GearApi, Result, WSAddress};
use gear_core::ids::{MessageId, ProgramId};
use halo2_proofs_client::{
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
use zkml_client::{
    gadgets::gadget::{GadgetConfig, GadgetType},
    utils::loader::ModelMsgpack,
};

// usage:
// ./gear-external-ml-actor init SURI <PROGRAM_ID(optional)>
// ./gear-external-ml-actor client SURI INPUT_FILE_PATH <PROGRAM_ID(optional)>
// ./gear-external-ml-actor clean_verify SURI <PROGRAM_ID(optional)>
// ./gear-external-ml-actor actor SURI <PROGRAM_ID(optional)>

#[tokio::main]
async fn main() {
    let op = std::env::args()
        .nth(1)
        .expect("Expected at least 2 arguments");
    let suri = std::env::args()
        .nth(2)
        .expect("Expected at least 2 arguments");

    let prog_id_idx = match &*op {
        "init" => 3,
        "client" => 4,
        "clean_verify" => 3,
        "actor" => 3,
        _ => {
            panic!(
                "Expected one of the following as 1st argument: init, client, actor, clean_verify"
            );
        }
    };

    let prog_id = std::env::args().nth(prog_id_idx);

    let program_id = ProgramId::from(
        &hex::decode(prog_id.unwrap_or(
            "cb7ab504102545b32135627834265c739f3609909ac41010d6027072c977e4a5".to_string(),
        ))
        .unwrap()[..],
    );

    let address = WSAddress::new("wss://testnet.vara.rs", Some(443));

    match &*op {
        "init" => {
            initializator(program_id, address, &suri).await;
        }
        "client" => {
            let inp_path = std::env::args()
                .nth(3)
                .expect("Expected at least 3 arguments");

            let api = GearApi::init_with(address, &suri).await.unwrap();
            client(program_id, api, &inp_path).await;
        }
        "clean_verify" => {
            let api = GearApi::init_with(address, &suri).await.unwrap();
            clean_verify(program_id, api).await;
        }
        "actor" => {
            let api = GearApi::init_with(address, &suri).await.unwrap();
            prover(program_id, api).await;
        }
        _ => {
            panic!(
                "Expected one of the following as 1st argument: init, client, actor, clean_verify"
            );
        }
    }
}

// verifier : 29k - 23.5k (5.5k spent)
// prover: 8.8k - 8.8k (<100 spent)

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
    let mut params = zkml_client::utils::proving_kzg::get_kzg_params("./params_kzg", 15);

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
    loop {
        let gas = match api
            .calculate_handle_gas(None, pid, payload.encode(), 0, true)
            .await
        {
            Ok(limit) => limit.min_limit,
            Err(_) => api.block_gas_limit().unwrap(),
        };

        match api.send_message_bytes(pid, payload.encode(), gas, 0).await {
            Ok((message_id, _)) => {
                if listener
                    .message_processed(message_id)
                    .await
                    .unwrap()
                    .failed()
                {
                    println!("ERROR: MSG NOT PROCESSED");

                    continue;
                }

                return message_id;
            }
            Err(e) => {
                println!("ERROR: {e}");
                return MessageId::default();
            }
        }
    }
}

async fn initializator(program_id: ProgramId, endpoint: WSAddress, suri: &str) {
    let api = GearApi::init_with(endpoint, suri).await.unwrap();
    let mut listener = api.subscribe().await.unwrap();
    assert!(listener.blocks_running().await.unwrap());

    println!("Init::FillVkeyMap sending...");
    let payload =
        contract::io::Incoming::Initializing(contract::io::InitializingMessage::FillVkeyMap);
    let _ = send_message_and_wait_for_success(&api, &mut listener, program_id, payload).await;
    println!("Init::FillVkeyMap sent");

    let (g_data, g_lagrange_data, kzg_params) = get_kzg_data();

    let load_per_iter = g_data.len() / 128;
    let mut already_loaded = load_per_iter * 0;

    for (i, (g_data, g_lagrange_data)) in itertools::izip!(
        g_data.chunks(load_per_iter),
        g_lagrange_data.chunks(load_per_iter),
    )
    .enumerate()
    .skip(already_loaded / load_per_iter)
    {
        println!("Init::LoadKZG sending... {i}");
        let payload =
            contract::io::Incoming::Initializing(contract::io::InitializingMessage::LoadKZG {
                g_data: g_data.to_vec(),
                g_lagrange_data: g_lagrange_data.to_vec(),
                load_offset: already_loaded as u32,
            });
        let _ = send_message_and_wait_for_success(&api, &mut listener, program_id, payload).await;

        already_loaded += load_per_iter;
        println!("Init::LoadKZG sent");
    }

    let model = zkml_client::utils::loader::load_model_msgpack(
        "./model/model.msgpack",
        "./model/inp.msgpack",
    );
    let circuit = zkml_client::model::ModelCircuit::<Fr>::generate_from_msgpack(model, true);
    let gadget_config_data = unsafe {
        GadgetConfigCodec::from(zkml_client::model::GADGET_CONFIG.lock().unwrap().clone()).encode()
    };

    println!("Init::Finalize sending...");
    let payload =
        contract::io::Incoming::Initializing(contract::io::InitializingMessage::Finalize {
            kzg_params,
            gadget_config_data,
        });
    let _ = send_message_and_wait_for_success(&api, &mut listener, program_id, payload).await;
    println!("Init::Finalize sent");
}

async fn client(program_id: ProgramId, api: GearApi, input_file_path: &str) {
    let mut listener = api.subscribe().await.unwrap();
    assert!(listener.blocks_running().await.unwrap());

    println!("Client::SubmitInput sending...");
    let input = {
        let input_file = File::open(input_file_path).unwrap();
        let mut reader = BufReader::new(input_file);
        let mut input = vec![];
        reader.read_to_end(&mut input);
        input
    };

    let payload = contract::io::Incoming::Client(contract::io::ClientMessage::SubmitInput {
        input: input.clone(),
    });
    let new_payload_message_id =
        send_message_and_wait_for_success(&api, &mut listener, program_id, payload).await;
    println!("Client::SubmitInput sent");

    loop {
        let mut msg = api.get_mailbox_messages(1).await.unwrap();
        if msg.len() == 1 {
            let msg = msg.pop().unwrap().0;
            api.claim_value(msg.id()).await;
            let event = contract::io::Event::decode(&mut msg.payload_bytes()).unwrap();

            match event {
                contract::io::Event::NewProof => {
                    break;
                }
                _ => {
                    println!("Unexpected event");
                }
            }
        }
    }

    println!("Client::CloneVkeyData sending...");
    let payload = contract::io::Incoming::Client(contract::io::ClientMessage::CloneVkeyData);
    let _ = send_message_and_wait_for_success(&api, &mut listener, program_id, payload).await;
    println!("Client::CloneVkeyData sent");

    println!("Client::VerifierKey sending...");
    let model =
        zkml_client::utils::loader::load_model_msgpack_and_bytes("./model/model.msgpack", input);
    let circuit = zkml_client::model::ModelCircuit::<Fr>::generate_from_msgpack(model, true);
    let params_kzg = zkml_client::utils::proving_kzg::get_kzg_params("./params_kzg", 15);
    let vkey = keygen_vk(&params_kzg, &circuit).unwrap();
    let vkey_data = vkey.to_bytes(SerdeFormat::RawBytes);

    let payload =
        contract::io::Incoming::Client(contract::io::ClientMessage::VerifierKey { vkey_data });
    let _ = send_message_and_wait_for_success(&api, &mut listener, program_id, payload).await;
    println!("Client::VerifierKey sent");

    for i in 0..34 {
        println!("Client::Verify {i} sending...");
        let payload = contract::io::Incoming::Client(contract::io::ClientMessage::Verify);
        let _ = send_message_and_wait_for_success(&api, &mut listener, program_id, payload).await;
        println!("Client::Verify {i} sent");
    }

    loop {
        let mut msg = api.get_mailbox_messages(1).await.unwrap();
        if msg.len() == 1 {
            let msg = msg.pop().unwrap().0;
            api.claim_value(msg.id()).await.unwrap();
            let event = contract::io::Event::decode(&mut msg.payload_bytes()).unwrap();

            match event {
                contract::io::Event::ProofValidated { validity } => {
                    println!("Validated {}", validity);
                    break;
                }
                _ => {
                    println!("Unexpected event");
                }
            }
        }
    }
}

async fn clean_verify(program_id: ProgramId, api: GearApi) {
    let mut listener = api.subscribe().await.unwrap();
    assert!(listener.blocks_running().await.unwrap());

    println!("Client::PurgeVerification sending...");
    let payload = contract::io::Incoming::Client(contract::io::ClientMessage::PurgeVerification);
    let _ = send_message_and_wait_for_success(&api, &mut listener, program_id, payload).await;
    println!("Client::PurgeVerification sent");
}

async fn prover(program_id: ProgramId, api: GearApi) {
    let mut listener = api.subscribe().await.unwrap();
    assert!(listener.blocks_running().await.unwrap());

    loop {
        let mut msg = api.get_mailbox_messages(1).await.unwrap();
        if msg.len() == 1 {
            let msg = msg.pop().unwrap().0;
            api.claim_value(msg.id()).await.unwrap();
            let event = contract::io::Event::decode(&mut msg.payload_bytes()).unwrap();

            match event {
                contract::io::Event::NewPayload { client } => {
                    let input: Vec<([u8; 32], Vec<u8>)> = api.read_state(program_id).await.unwrap();
                    let input = input
                        .into_iter()
                        .find(|inp| inp.0 == client)
                        .expect("Record about provided input in state")
                        .1;

                    let model = zkml_client::utils::loader::load_model_msgpack_and_bytes(
                        "./model/model.msgpack",
                        input,
                    );
                    let circuit =
                        zkml_client::model::ModelCircuit::<Fr>::generate_from_msgpack(model, true);
                    // Writes ./proof and ./public_vals
                    zkml_client::utils::proving_kzg::time_circuit_kzg(circuit);

                    let proof_data = std::fs::read("./proof").unwrap();
                    let pub_vals_data = std::fs::read("./public_vals").unwrap();

                    let pub_vals: Vec<_> = pub_vals_data
                        .clone()
                        .chunks(32)
                        .map(|inp| Fr::from_bytes(inp.try_into().unwrap()).unwrap())
                        .collect();

                    println!("Got result: {:?}", pub_vals);

                    let payload =
                        contract::io::Incoming::Prover(contract::io::ProverMessage::SubmitProof {
                            client,
                            proof_data,
                            pub_vals_data,
                        });

                    println!("Prover::SubmitProof sending...");
                    let _ =
                        send_message_and_wait_for_success(&api, &mut listener, program_id, payload)
                            .await;
                    println!("Prover::SubmitProof sent");

                    break;
                }
                _ => {
                    println!("Unexpected event");
                }
            }
        }
    }
}

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
