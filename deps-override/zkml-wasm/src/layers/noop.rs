use gstd::{collections::BTreeMap, rc::Rc};

use halo2_proofs_wasm::{circuit::Layouter, halo2curves_wasm::ff::PrimeField, plonk::Error};

use crate::gadgets::gadget::GadgetConfig;

use super::layer::{AssignedTensor, CellRc, GadgetConsumer, Layer, LayerConfig};

pub struct NoopChip {}

impl<F: PrimeField> Layer<F> for NoopChip {
  fn forward(
    &self,
    _layouter: impl Layouter<F>,
    tensors: &Vec<AssignedTensor<F>>,
    _constants: &BTreeMap<i64, CellRc<F>>,
    _gadget_config: Rc<GadgetConfig>,
    layer_config: &LayerConfig,
  ) -> Result<Vec<AssignedTensor<F>>, Error> {
    let ret_idx = layer_config.layer_params[0] as usize;
    Ok(vec![tensors[ret_idx].clone()])
  }
}

impl GadgetConsumer for NoopChip {
  fn used_gadgets(&self, _layer_params: Vec<i64>) -> Vec<crate::gadgets::gadget::GadgetType> {
    vec![]
  }
}
