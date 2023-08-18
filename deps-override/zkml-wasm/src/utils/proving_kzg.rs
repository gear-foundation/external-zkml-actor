use gstd::prelude::*;

use halo2_proofs_wasm::{
  halo2curves_wasm::bn256::{Bn256, Fr, G1Affine},
  plonk::VerifyingKey,
  poly::{
    commitment::Params,
    kzg::{
      commitment::{KZGCommitmentScheme, ParamsKZG},
      //multiopen::VerifierSHPLONK,
      strategy::SingleStrategy,
    },
  },
  transcript::{Blake2bRead, Challenge255, TranscriptReadBuffer},
  SerdeFormat,
};

//use crate::model::ModelCircuit;

pub fn get_kzg_params(params_dir: &str, degree: u32) -> ParamsKZG<Bn256> {
  //let rng = rand::thread_rng();
  //let path = format!("{}/{}.params", params_dir, degree);
  //let params_path = Path::new(&path);
  // if File::open(&params_path).is_err() {
  //   let params = ParamsKZG::<Bn256>::setup(degree, rng);
  //   let mut buf = Vec::new();

  //   params.write(&mut buf).expect("Failed to write params");
  //   let mut file = File::create(&params_path).expect("Failed to create params file");
  //   file
  //     .write_all(&buf[..])
  //     .expect("Failed to write params to file");
  // }

  //let mut params_fs = File::open(&params_path).expect("couldn't load params");
  //let params = ParamsKZG::<Bn256>::read(&mut params_fs).expect("Failed to read params");
  //params
  todo!()
}

pub fn verify_kzg(
  params: &ParamsKZG<Bn256>,
  vk: &VerifyingKey<G1Affine>,
  strategy: SingleStrategy<Bn256>,
  public_vals: &Vec<Fr>,
  mut transcript: Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
) {
  // assert!(
  //   verify_proof::<
  //     KZGCommitmentScheme<Bn256>,
  //     VerifierSHPLONK<'_, Bn256>,
  //     Challenge255<G1Affine>,
  //     Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
  //     halo2_proofs_wasm::poly::kzg::strategy::SingleStrategy<'_, Bn256>,
  //   >(&params, &vk, strategy, &[&[&public_vals]], &mut transcript)
  //   .is_ok(),
  //   "proof did not verify"
  // );
}

// Standalone verification
pub fn verify_circuit_kzg(
  //circuit: ModelCircuit<Fr>,
  circuit_degree: u32,
  vkey_fname: &str,
  proof_fname: &str,
  public_vals_fname: &str,
) {
  //let degree = circuit.k as u32;
  let params = get_kzg_params("./params_kzg", circuit_degree);

  let vk = todo!(); // VerifyingKey::read::<BufReader<File>, ModelCircuit<Fr>>(
                    //  &mut BufReader::new(File::open(vkey_fname).unwrap()),
                    //  SerdeFormat::RawBytes,
                    //  (),
                    //)
                    //.unwrap();

  let proof: Vec<u8> = todo!(); // gstd::fs::read(proof_fname).unwrap();

  let public_vals_u8 = vec![]; //STD gstd::fs::read(&public_vals_fname).unwrap();
  let public_vals: Vec<Fr> = public_vals_u8
    .chunks(32)
    .map(|chunk| Fr::from_bytes(chunk.try_into().expect("conversion failed")).unwrap())
    .collect();

  let strategy = SingleStrategy::new(&params);
  let transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

  verify_kzg(&params, &vk, strategy, &public_vals, transcript);
}
