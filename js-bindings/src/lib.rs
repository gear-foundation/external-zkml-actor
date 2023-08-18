mod utils;

use wasm_bindgen::prelude::*;

use halo2_proofs_client::{
    halo2curves::bn256::{Bn256, Fr, G1Affine},
    plonk::{keygen_vk, VerifyingKey},
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
    SerdeFormat,
};

use zkml_client::{
    model::ModelCircuit,
    utils::loader::{ModelMsgpack, TensorMsgpack},
};

pub fn load_model(mut model: ModelMsgpack, input: &[u8]) -> ModelMsgpack {
    let inp: Vec<TensorMsgpack> = rmp_serde::from_slice(input).unwrap();
    for tensor in inp {
        model.tensors.push(tensor);
    }

    if model.use_selectors.is_none() {
        model.use_selectors = Some(true)
    };
    if model.commit_before.is_none() {
        model.commit_before = Some(vec![])
    };
    if model.commit_after.is_none() {
        model.commit_after = Some(vec![])
    };
    if model.bits_per_elem.is_none() {
        model.bits_per_elem = Some(model.k)
    };
    if model.num_random.is_none() {
        model.num_random = Some(20001)
    };

    model
}

#[wasm_bindgen]
pub fn get_vkey_data(inputs: &[u8]) -> Vec<u8> {
    let params_kzg_data = include_bytes!("../../params_kzg/15.params");
    let model_data = include_bytes!("../../model/model.msgpack");

    let params_kzg = ParamsKZG::<Bn256>::read(&mut &params_kzg_data[..]).unwrap();

    let model: ModelMsgpack = rmp_serde::from_slice(&model_data[..]).unwrap();
    let model = load_model(model, inputs);

    let circuit = ModelCircuit::<Fr>::generate_from_msgpack(model, true);
    let vkey: VerifyingKey<G1Affine> = keygen_vk::<_, _, _>(&params_kzg, &circuit).unwrap();
    let vkey_data = vkey.to_bytes(SerdeFormat::RawBytes);

    vkey_data
}
