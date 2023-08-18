use gstd::{prelude::*, rc::Rc};

use halo2_proofs_wasm::{circuit::Layouter, halo2curves_wasm::ff::PrimeField, plonk::Error};

use crate::{gadgets::gadget::GadgetConfig, layers::CellRc};

pub trait Commit<F: PrimeField> {
  fn commit(
    &self,
    layouter: impl Layouter<F>,
    gadget_config: Rc<GadgetConfig>,
    constants: &BTreeMap<i64, CellRc<F>>,
    values: &Vec<CellRc<F>>,
    blinding: CellRc<F>,
  ) -> Result<Vec<CellRc<F>>, Error>;
}
