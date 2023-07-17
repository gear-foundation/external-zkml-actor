#![no_std]
#![feature(offset_of)]

#[cfg(feature = "std")]
mod code {
    include!(concat!(env!("OUT_DIR"), "/wasm_binary.rs"));
}

#[cfg(feature = "std")]
pub use code::WASM_BINARY_OPT as WASM_BINARY;

extern crate gstd;
extern crate halo2_proofs;
extern crate halo2curves;
extern crate hashbrown;
extern crate zkml;

pub mod events;
pub mod io;
pub mod queue;
#[cfg(test)]
mod tests;

use gstd::{prelude::*, MessageId};

use halo2curves::serde::SerdeObject;
use hashbrown::HashMap;

use io::{GadgetConfigCodec, Incoming, KzgParamsNoVec};
use queue::{NewMessage, Queue};

use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{verify_proof, VerifyingKey},
    poly::{
        commitment::Params,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::VerifierSHPLONK,
            strategy::SingleStrategy,
        },
    },
    transcript::{Blake2bRead, Challenge255, TranscriptReadBuffer},
    SerdeFormat,
};

pub type ProofData = Vec<u8>;

static mut ACTOR_CODE_HASH: [u8; 32] = [0u8; 32];
static mut ACTOR_STATE_HASH: [u8; 32] = [0u8; 32];
static mut WAKERS: Option<HashMap<u64, MessageId>> = None;
static mut PROOFS: Option<HashMap<MessageId, ProofData>> = None;

static mut KZG_G_DATA: Option<Vec<G1Affine>> = None;
static mut KZG_G_LAGRANGE_DATA: Option<Vec<G1Affine>> = None;

struct DataForVerify {
    params_kzg: ParamsKZG<Bn256>,
    vkey: VerifyingKey<G1Affine>,
    pub_vals: Vec<Fr>,
}

static mut DATA_FOR_VERIFY: Option<DataForVerify> = None;

#[no_mangle]
unsafe extern "C" fn init() {
    let init: io::Initialization = gstd::msg::load().expect("failed to read init payload");

    WAKERS = Some(Default::default());
    PROOFS = Some(Default::default());
    queue::QUEUE = Some(Default::default());

    KZG_G_DATA = Some(Default::default());
    KZG_G_LAGRANGE_DATA = Some(Default::default());

    ACTOR_CODE_HASH = init.actor_code_hash;
    ACTOR_STATE_HASH = init.actor_state_hash;
}

fn push_waker(index: u64) {
    let wakers = unsafe {
        WAKERS
            .as_mut()
            .expect("WAKERS should have been initialized!")
    };
    wakers.insert(index, gstd::msg::id());
}

fn pop_waker(index: u64) -> Option<MessageId> {
    let wakers = unsafe {
        WAKERS
            .as_mut()
            .expect("WAKERS should have been initialized!")
    };
    wakers.remove(&index)
}

fn pop_proof(handler: MessageId) -> Option<ProofData> {
    let proofs = unsafe {
        PROOFS
            .as_mut()
            .expect("PROOFS should have been initialized!")
    };
    proofs.remove(&handler)
}

fn push_proof(handler: MessageId, data: ProofData) {
    unsafe {
        PROOFS
            .as_mut()
            .expect("PROOFS should have been initialized!")
            .insert(handler, data);
    }
}

#[no_mangle]
unsafe extern "C" fn handle() {
    let msg: Incoming = gstd::msg::load().expect("Unable to parse incoming");

    match msg {
        Incoming::New(payload) => {
            if unsafe { !PROOFS.as_ref().unwrap().contains_key(&gstd::msg::id()) } {
                let size = payload.len();
                let new_index = Queue::push(NewMessage {
                    payload: payload,
                    sender: gstd::msg::source(),
                    value: gstd::msg::value(),
                });

                push_waker(new_index);

                events::send(events::Event::NewPayload {
                    index: new_index,
                    size: size as _,
                });

                gcore::exec::wait();
            }
        }
        Incoming::Proof {
            index,
            proof,
            gadget_config,
        } => {
            if let Some(wake_id) = pop_waker(index) {
                gcore::exec::wake(wake_id.into()).expect("Failed to wake");

                unsafe {
                    zkml::model::GADGET_CONFIG = Some(
                        GadgetConfigCodec::decode(&mut &*gadget_config)
                            .unwrap()
                            .into(),
                    );
                }

                push_proof(wake_id, proof);
            }
        }
        Incoming::LoadKzg {
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

            KZG_G_DATA.as_mut().unwrap().append(&mut g);
            KZG_G_LAGRANGE_DATA
                .as_mut()
                .unwrap()
                .append(&mut g_lagrange);
        }
        Incoming::FillVkeyMap => zkml::gadgets::bias_div_round_relu6::fill_vkey_map(),
        Incoming::FillDataForVerify {
            verifier_key,
            outcome,
            kzg_params,
        } => {
            let params_kzg = unsafe {
                let g = KZG_G_DATA.take().unwrap();
                let g_lagrange = KZG_G_LAGRANGE_DATA.take().unwrap();

                ParamsKZG {
                    k: kzg_params.k,
                    n: kzg_params.n,
                    g,
                    g_lagrange,
                    g2: gstd::mem::transmute(kzg_params.g2_data),
                    s_g2: gstd::mem::transmute(kzg_params.s_g2_data),
                }
            };

            let vkey: VerifyingKey<G1Affine> =
                VerifyingKey::read::<_, zkml::model::ModelCircuit<Fr>>(
                    &mut &verifier_key[..],
                    SerdeFormat::RawBytes,
                    (),
                )
                .expect("Invalid verifying key");

            let pub_vals: Vec<_> = outcome
                .chunks(32)
                .map(|chunk| Fr::from_bytes(chunk.try_into().expect("conversion failed")).unwrap())
                .collect();

            unsafe {
                DATA_FOR_VERIFY = Some(DataForVerify {
                    params_kzg,
                    vkey,
                    pub_vals,
                });
            }
        }
        Incoming::PreVerify { message_id } => {
            let proof = pop_proof(MessageId::decode(&mut &message_id[..]).unwrap())
                .expect("Failed to pop proof");

            let params_kzg = unsafe { &DATA_FOR_VERIFY.as_ref().unwrap().params_kzg };
            let vkey = unsafe { &DATA_FOR_VERIFY.as_ref().unwrap().vkey };
            let pub_vals = unsafe { &DATA_FOR_VERIFY.as_ref().unwrap().pub_vals };

            let strategy: SingleStrategy<'_, Bn256> = SingleStrategy::new(&params_kzg);

            let mut transcript: Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>> =
                Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

            let valid = verify_proof::<
                KZGCommitmentScheme<Bn256>,
                VerifierSHPLONK<'_, Bn256>,
                Challenge255<G1Affine>,
                Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
                halo2_proofs::poly::kzg::strategy::SingleStrategy<'_, Bn256>,
            >(
                &params_kzg,
                &vkey,
                strategy,
                &[&[&pub_vals]],
                &mut transcript,
            )
            .is_ok();

            gstd::debug!("VALID: {valid}");
        }
        Incoming::Verify => {
            //
        }
    }
}

#[no_mangle]
extern "C" fn state() {
    gstd::msg::reply(unsafe { Queue::queue().clone() }, 0).expect("Failed to share state");
}
