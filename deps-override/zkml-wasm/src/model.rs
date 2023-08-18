use gstd::prelude::*;

use halo2_proofs_wasm::{
  circuit::{Layouter, SimpleFloorPlanner, Value},
  halo2curves_wasm::ff::{FromUniformBytes, PrimeField},
  plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance},
};

use gstd::collections::BTreeMap;

use lazy_static::lazy_static;
use ndarray::{Array, IxDyn};
use num_bigint::BigUint;

use crate::{
  commitments::{
    commit::Commit,
    packer::PackerChip,
    poseidon_commit::{PoseidonCommitChip, L, RATE, WIDTH},
  },
  gadgets::{
    add_pairs::AddPairsChip,
    adder::AdderChip,
    bias_div_round_relu6::BiasDivRoundRelu6Chip,
    dot_prod::DotProductChip,
    gadget::{Gadget, GadgetConfig, GadgetType},
    input_lookup::InputLookupChip,
    max::MaxChip,
    mul_pairs::MulPairsChip,
    nonlinear::{exp::ExpGadgetChip, pow::PowGadgetChip, relu::ReluChip, tanh::TanhGadgetChip},
    nonlinear::{logistic::LogisticGadgetChip, rsqrt::RsqrtGadgetChip, sqrt::SqrtGadgetChip},
    sqrt_big::SqrtBigChip,
    square::SquareGadgetChip,
    squared_diff::SquaredDiffGadgetChip,
    sub_pairs::SubPairsChip,
    update::UpdateGadgetChip,
    var_div::VarDivRoundChip,
    var_div_big::VarDivRoundBigChip,
    var_div_big3::VarDivRoundBig3Chip,
  },
  layers::DAGLayerConfig,
};

pub static mut GADGET_CONFIG: Option<GadgetConfig> = None;

#[derive(Clone, Debug, Default)]
pub struct ModelCircuit<F: PrimeField> {
  pub used_gadgets: gstd::rc::Rc<BTreeSet<GadgetType>>,
  pub dag_config: DAGLayerConfig,

  pub tensors: BTreeMap<i64, Array<F, IxDyn>>,
  pub commit_before: Vec<Vec<i64>>,
  pub commit_after: Vec<Vec<i64>>,
  pub k: usize,
  pub bits_per_elem: usize,
  pub inp_idxes: Vec<i64>,
  pub num_random: i64,
}

#[derive(Clone, Debug)]
pub struct ModelConfig<F: PrimeField + Ord + FromUniformBytes<64>> {
  pub gadget_config: gstd::rc::Rc<GadgetConfig>,
  pub public_col: Column<Instance>,
  pub hasher: Option<PoseidonCommitChip<F, WIDTH, RATE, L>>,
  pub _marker: gstd::marker::PhantomData<F>,
}

impl<F: PrimeField + Ord + FromUniformBytes<64>> ModelCircuit<F> {
  fn configure_internal(meta: &mut ConstraintSystem<F>, gadget_config: Vec<u8>) -> ModelConfig<F> {
    //let mut gadget_config = GadgetConfig::decode(&mut &*gadget_config).unwrap();

    let mut gadget_config = unsafe { GADGET_CONFIG.take().unwrap() };

    let columns = (0..gadget_config.num_cols)
      .map(|_| meta.advice_column())
      .collect::<Vec<_>>();
    for col in columns.iter() {
      meta.enable_equality(*col);
    }
    gadget_config.columns = columns;

    let public_col = meta.instance_column();
    meta.enable_equality(public_col);

    gadget_config.fixed_columns = vec![meta.fixed_column()];
    meta.enable_equality(gadget_config.fixed_columns[0]);

    // The input lookup is always loaded
    gadget_config = InputLookupChip::<F>::configure(meta, gadget_config);

    let used_gadgets = gadget_config.used_gadgets.clone();

    for gadget_type in used_gadgets.iter() {
      gadget_config = match gadget_type {
        GadgetType::AddPairs => AddPairsChip::<F>::configure(meta, gadget_config),
        GadgetType::Adder => AdderChip::<F>::configure(meta, gadget_config),
        GadgetType::BiasDivRoundRelu6 => BiasDivRoundRelu6Chip::<F>::configure(meta, gadget_config),
        GadgetType::BiasDivFloorRelu6 => panic!(),
        GadgetType::DotProduct => DotProductChip::<F>::configure(meta, gadget_config),
        //GadgetType::Exp => ExpGadgetChip::<F>::configure(meta, gadget_config),
        // GadgetType::Logistic => LogisticGadgetChip::<F>::configure(meta, gadget_config),
        GadgetType::Max => MaxChip::<F>::configure(meta, gadget_config),
        GadgetType::MulPairs => MulPairsChip::<F>::configure(meta, gadget_config),
        GadgetType::Pow => PowGadgetChip::<F>::configure(meta, gadget_config),
        GadgetType::Relu => ReluChip::<F>::configure(meta, gadget_config),
        // GadgetType::Rsqrt => RsqrtGadgetChip::<F>::configure(meta, gadget_config),
        // GadgetType::Sqrt => SqrtGadgetChip::<F>::configure(meta, gadget_config),
        // GadgetType::SqrtBig => SqrtBigChip::<F>::configure(meta, gadget_config),
        GadgetType::Square => SquareGadgetChip::<F>::configure(meta, gadget_config),
        GadgetType::SquaredDiff => SquaredDiffGadgetChip::<F>::configure(meta, gadget_config),
        GadgetType::SubPairs => SubPairsChip::<F>::configure(meta, gadget_config),
        // GadgetType::Tanh => TanhGadgetChip::<F>::configure(meta, gadget_config),
        GadgetType::VarDivRound => VarDivRoundChip::<F>::configure(meta, gadget_config),
        GadgetType::VarDivRoundBig => VarDivRoundBigChip::<F>::configure(meta, gadget_config),
        GadgetType::VarDivRoundBig3 => VarDivRoundBig3Chip::<F>::configure(meta, gadget_config),
        GadgetType::InputLookup => gadget_config, // This is always loaded
        GadgetType::Update => UpdateGadgetChip::<F>::configure(meta, gadget_config),
        GadgetType::Packer => panic!(),
        _ => panic!(),
      };
    }

    let hasher =
      if gadget_config.commit_before.len() + gadget_config.commit_after.len() > 0 as usize {
        let packer_config =
          PackerChip::<F>::construct(gadget_config.num_bits_per_elem as usize, &gadget_config);
        gadget_config = PackerChip::<F>::configure(meta, packer_config, gadget_config);

        // TODO
        let input = gadget_config.columns[0..L].try_into().unwrap();
        let state = gadget_config.columns[L..L + WIDTH].try_into().unwrap();
        let partial_sbox = gadget_config.columns[L + WIDTH].into();
        Some(PoseidonCommitChip::<F, WIDTH, RATE, L>::configure(
          meta,
          input,
          state,
          partial_sbox,
        ))
      } else {
        None
      };

    ModelConfig {
      gadget_config: gadget_config.into(),
      public_col,
      hasher,
      _marker: gstd::marker::PhantomData,
    }
  }
}

impl<F: PrimeField + Ord + FromUniformBytes<64>> Circuit<F> for ModelCircuit<F> {
  type Config = ModelConfig<F>;
  type FloorPlanner = SimpleFloorPlanner;
  type Params = ();

  fn without_witnesses(&self) -> Self {
    todo!()
  }

  fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
    Self::configure_internal(meta, vec![])
  }

  fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
    unimplemented!()
  }
}
