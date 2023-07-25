#![no_std]
#![feature(offset_of)]

#[cfg(feature = "std")]
mod code {
    include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));
}

#[cfg(feature = "std")]
pub use code::WASM_BINARY_OPT as WASM_BINARY;

extern crate gstd;
extern crate halo2_proofs_wasm;
extern crate hashbrown;
extern crate zkml_wasm;

pub mod events;
pub mod io;

use gstd::{prelude::*, ActorId, MessageId};
use halo2_proofs_wasm::{
    halo2curves_wasm::{
        bn256::{Bn256, Fr, G1Affine},
        group::Group,
        pairing::{MillerLoopResult, MultiMillerLoop},
        serde::SerdeObject,
    },
    plonk::{verify_proof_stage_1, VerifyingKey},
    poly::{
        commitment::{Params, Verifier},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            msm::{DualMSM, DualMSMData},
            multiopen::shplonk::{
                verifier::VerifierIntermediateState, IntermediateSetsData, VerifierSHPLONK,
            },
            strategy::SingleStrategy,
        },
    },
    transcript::{Blake2bRead, Challenge255, TranscriptReadBuffer},
    SerdeFormat,
};
use hashbrown::{hash_map::Entry, HashMap};
use io::{
    ClientMessage, GadgetConfigCodec, Incoming, InitializingMessage, KzgParamsNoVec, ProverMessage,
};
use zkml_wasm::gadgets::gadget::GadgetConfig;

use crate::events::Event;

static mut VERIFICATOR_STATE: Option<VerificatorState> = Some(VerificatorState::Initializing {
    kzg_g_data: vec![],
    kzg_g_lagrange_data: vec![],
    vkey_map: None,
});
static mut VERIFICATION_STAGES: Option<HashMap<ActorId, VerificationStage>> = None;
static mut PROOF_DATA: Option<HashMap<ActorId, Vec<u8>>> = None;

enum VerificatorState {
    Initializing {
        kzg_g_data: Vec<G1Affine>,
        kzg_g_lagrange_data: Vec<G1Affine>,
        vkey_map: Option<HashMap<i64, i64>>,
    },
    Initialized {
        params_kzg: ParamsKZG<Bn256>,
        gadget_config: GadgetConfig,
        vkey_map: HashMap<i64, i64>,
    },
}

enum VerificationStage {
    Input {
        input_data: Vec<u8>,
    },
    Proof {
        proof_data: Vec<u8>,
        pub_vals: Vec<Fr>,
    },
    VerifierKey {
        proof_data: Vec<u8>,
        pub_vals: Vec<Fr>,
        verifier_key: VerifyingKey<G1Affine>,
    },
    GenerateMSM1 {
        transcript: Blake2bRead<&'static [u8], G1Affine, Challenge255<G1Affine>>,
        intermediate_sets: IntermediateSetsData<Fr>,
    },
    GenerateMSM2 {
        transcript: Blake2bRead<&'static [u8], G1Affine, Challenge255<G1Affine>>,
        intermediate_sets: IntermediateSetsData<Fr>,
        intermediate_state: VerifierIntermediateState<Bn256>,
    },
    GenerateMSM3 {
        msm_data: DualMSMData<Bn256>,
        evaluation_steps: usize,
    },
    EvaluateMSM {
        msm_data: DualMSMData<Bn256>,
    },
    PreVerify {
        mml_result: <Bn256 as MultiMillerLoop>::Result,
    },
    Verify {
        result: bool,
    },
}

#[no_mangle]
unsafe extern "C" fn init() {
    VERIFICATION_STAGES = Some(HashMap::new());
    PROOF_DATA = Some(HashMap::new());
}

#[no_mangle]
unsafe extern "C" fn handle() {
    let msg: Incoming = gstd::msg::load().expect("Unable to parse incoming");

    match msg {
        Incoming::Initializing(msg) => handle_initialization(msg),
        Incoming::Prover(msg) => handle_prover_message(msg),
        Incoming::Client(msg) => handle_client_message(msg),
    }
}

unsafe fn handle_initialization(msg: InitializingMessage) {
    VERIFICATOR_STATE = Some(match VERIFICATOR_STATE.take().unwrap() {
        VerificatorState::Initializing {
            mut kzg_g_data,
            mut kzg_g_lagrange_data,
            mut vkey_map,
        } => match msg {
            InitializingMessage::LoadKZG {
                g_data,
                g_lagrange_data,
            } => {
                let mut g = g_data
                    .into_iter()
                    .map(|g| G1Affine::from_raw_bytes(&g).expect("Failed to decode G1Affine"))
                    .collect();
                let mut g_lagrange = g_lagrange_data
                    .into_iter()
                    .map(|g_lagrange| {
                        G1Affine::from_raw_bytes(&g_lagrange).expect("Failed to decode G1Affine")
                    })
                    .collect();

                kzg_g_data.append(&mut g);
                kzg_g_lagrange_data.append(&mut g_lagrange);

                VerificatorState::Initializing {
                    kzg_g_data,
                    kzg_g_lagrange_data,
                    vkey_map,
                }
            }
            InitializingMessage::FillVkeyMap => {
                if vkey_map.is_none() {
                    vkey_map = Some(zkml_wasm::gadgets::bias_div_round_relu6::get_vkey_map());
                } else {
                    panic!("Verifier key map is already loaded");
                }

                VerificatorState::Initializing {
                    kzg_g_data,
                    kzg_g_lagrange_data,
                    vkey_map,
                }
            }
            InitializingMessage::Finalize {
                kzg_params,
                gadget_config_data,
            } => {
                // if kzg_g_data.len() != kzg_params.n as usize
                //     || kzg_g_lagrange_data.len() != kzg_params.n as usize
                // {
                //     panic!("KZG Params are not fully loaded");
                // }

                if vkey_map.is_none() {
                    panic!("Fill verifier key map first");
                }

                let params_kzg = ParamsKZG {
                    k: kzg_params.k,
                    n: kzg_params.n,
                    g: kzg_g_data,
                    g_lagrange: kzg_g_lagrange_data,
                    g2: gstd::mem::transmute(kzg_params.g2_data),
                    s_g2: gstd::mem::transmute(kzg_params.s_g2_data),
                };

                let gadget_config = GadgetConfigCodec::decode(&mut &*gadget_config_data)
                    .unwrap()
                    .into();

                VerificatorState::Initialized {
                    params_kzg,
                    gadget_config,
                    vkey_map: vkey_map.take().unwrap(),
                }
            }
        },
        _ => {
            panic!("Invalid operation")
        }
    });
}

unsafe fn handle_prover_message(msg: ProverMessage) {
    // TODO: Assert prover.

    match msg {
        ProverMessage::SubmitProof {
            proof_data,
            pub_vals_data,
            client,
        } => {
            let client: ActorId = client.into();

            let stage = VERIFICATION_STAGES
                .as_mut()
                .unwrap()
                .get_mut(&client)
                .expect("Invalid client");

            match stage {
                VerificationStage::Input { .. } => {
                    let pub_vals: Vec<_> = pub_vals_data
                        .chunks(32)
                        .map(|chunk| {
                            Fr::from_bytes(chunk.try_into().expect("conversion failed")).unwrap()
                        })
                        .collect();

                    *stage = VerificationStage::Proof {
                        proof_data,
                        pub_vals,
                    };
                }
                _ => {
                    panic!("Invalid verification stage");
                }
            }
        }
    }
}

unsafe fn handle_client_message(msg: ClientMessage) {
    let client = gstd::msg::source();

    let (params_kzg, gadget_config, vkey_map) = match VERIFICATOR_STATE.as_ref() {
        Some(VerificatorState::Initialized {
            params_kzg,
            gadget_config,
            vkey_map,
        }) => (params_kzg, gadget_config, vkey_map),
        _ => panic!("Verificator uninitialized"),
    };

    match msg {
        ClientMessage::SubmitInput { input } => {
            match VERIFICATION_STAGES.as_mut().unwrap().entry(client) {
                Entry::Occupied(_) => {
                    // Actually, that's not yet implemented.
                    panic!("Clean previous proving session first");
                }
                Entry::Vacant(entry) => {
                    entry.insert(VerificationStage::Input { input_data: input });

                    events::send(events::Event::NewPayload {
                        client: client.into(),
                    });
                }
            }
        }
        ClientMessage::VerifierKey { vkey_data } => {
            match VERIFICATION_STAGES.as_mut().unwrap().entry(client) {
                Entry::Occupied(stage) => stage.replace_entry_with(|_, stage| match stage {
                    VerificationStage::Proof {
                        proof_data,
                        pub_vals,
                    } => {
                        zkml_wasm::gadgets::bias_div_round_relu6::VKEY_MAP = Some(vkey_map.clone());
                        zkml_wasm::model::GADGET_CONFIG = Some(gadget_config.clone());

                        let verifier_key: VerifyingKey<G1Affine> =
                            VerifyingKey::read::<_, zkml_wasm::model::ModelCircuit<Fr>>(
                                &mut &vkey_data[..],
                                SerdeFormat::RawBytes,
                                (),
                            )
                            .expect("Invalid verifier key");

                        Some(VerificationStage::VerifierKey {
                            proof_data,
                            pub_vals,
                            verifier_key,
                        })
                    }
                    _ => {
                        panic!()
                    }
                }),
                Entry::Vacant(_) => {
                    panic!("Invalid client");
                }
            };
        }
        ClientMessage::Verify => {
            match VERIFICATION_STAGES.as_mut().unwrap().entry(client) {
                Entry::Occupied(stage) => stage.replace_entry_with(|_, stage| match stage {
                    VerificationStage::VerifierKey {
                        proof_data,
                        pub_vals,
                        verifier_key,
                    } => {
                        PROOF_DATA.as_mut().unwrap().insert(client, proof_data);
                        let proof_data = PROOF_DATA.as_ref().unwrap().get(&client).unwrap();

                        let mut transcript: Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>> =
                            Blake2bRead::<_, _, Challenge255<_>>::init(&proof_data[..]);

                        let intermediate_sets =
                            verify_proof_stage_1::<
                                Challenge255<G1Affine>,
                                Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
                            >(
                                &params_kzg, &verifier_key, &[&[&pub_vals]], &mut transcript
                            )
                            .expect("Failed to pre-verify");

                        Some(VerificationStage::GenerateMSM1 {
                            transcript,
                            intermediate_sets,
                        })
                    }
                    VerificationStage::GenerateMSM1 {
                        mut transcript,
                        intermediate_sets,
                    } => {
                        let msm = DualMSM::new(params_kzg);
                        let verifier = VerifierSHPLONK::new(params_kzg);

                        let intermediate_state = verifier
                            .pre_verify_proof_from_intermediate_sets(
                                &mut transcript,
                                intermediate_sets.get_sets(),
                                msm,
                            )
                            .expect("Error opening proof");

                        Some(VerificationStage::GenerateMSM2 {
                            transcript,
                            intermediate_sets,
                            intermediate_state,
                        })
                    }
                    VerificationStage::GenerateMSM2 {
                        mut transcript,
                        intermediate_sets,
                        intermediate_state,
                    } => {
                        let msm = DualMSM::new(params_kzg);
                        let verifier = VerifierSHPLONK::new(params_kzg);
                        let intermediate_sets = intermediate_sets.get_sets();

                        let guard = verifier
                            .verify_proof_from_intermediate_sets(
                                &mut transcript,
                                intermediate_sets,
                                msm,
                                intermediate_state,
                            )
                            .expect("Error opening proof");

                        let msm = guard.msm_accumulator;
                        let msm_data = DualMSMData::new(msm);

                        PROOF_DATA
                            .as_mut()
                            .unwrap()
                            .remove(&client)
                            .expect("Invalid stage order detected");

                        Some(VerificationStage::GenerateMSM3 {
                            msm_data,
                            evaluation_steps: 0,
                        })
                    }
                    // 29 steps currently.
                    VerificationStage::GenerateMSM3 {
                        mut msm_data,
                        evaluation_steps,
                    } => {
                        if msm_data.eval_staged(params_kzg) {
                            Some(VerificationStage::EvaluateMSM { msm_data })
                        } else {
                            Some(VerificationStage::GenerateMSM3 {
                                msm_data,
                                evaluation_steps: evaluation_steps + 1,
                            })
                        }
                    }
                    VerificationStage::EvaluateMSM { msm_data } => {
                        let mml_result = msm_data.check_stage_1(params_kzg);

                        Some(VerificationStage::PreVerify { mml_result })
                    }
                    VerificationStage::PreVerify { mml_result } => {
                        let result = bool::from(mml_result.final_exponentiation().is_identity());

                        gstd::msg::send(client, Event::ProofValidated { validity: result }, 0)
                            .unwrap();

                        Some(VerificationStage::Verify { result })
                    }
                    VerificationStage::Verify { result } => panic!("Proof already verified"),
                    _ => {
                        panic!("Invalid verification stage")
                    }
                }),
                Entry::Vacant(_) => {
                    panic!("Invalid client");
                }
            };
        }
    }
}

#[no_mangle]
extern "C" fn state() {
    let provided_inputs: Vec<([u8; 32], _)> = unsafe {
        VERIFICATION_STAGES
            .as_ref()
            .unwrap()
            .iter()
            .filter_map(|(k, v)| {
                if let VerificationStage::Input { ref input_data } = v {
                    Some((k.clone().into(), input_data.clone()))
                } else {
                    None
                }
            })
            .collect()
    };

    gstd::msg::reply(provided_inputs, 0).expect("Failed to share state");
}
