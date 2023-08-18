use gstd::prelude::*;
use gstd::rc::Rc;
use halo2_proofs_wasm::circuit::AssignedCell;
use ndarray::{Array, IxDyn};

#[derive(Clone, Debug, Default)]
pub struct DAGLayerConfig {
  pub ops: Vec<LayerConfig>,
  pub inp_idxes: Vec<Vec<usize>>,
  pub out_idxes: Vec<Vec<usize>>,
  pub final_out_idxes: Vec<usize>,
}

#[derive(Clone, Copy, Debug, Default, Hash, Eq, PartialEq)]
pub enum LayerType {
  Add,
  AvgPool2D,
  BatchMatMul,
  Broadcast,
  Concatenation,
  Conv2D,
  DivVar,
  DivFixed,
  FullyConnected,
  Logistic,
  MaskNegInf,
  MaxPool2D,
  Mean,
  Mul,
  #[default]
  Noop,
  Pack,
  Pad,
  Pow,
  Permute,
  Reshape,
  ResizeNN,
  Rotate,
  Rsqrt,
  Slice,
  Softmax,
  Split,
  Sqrt,
  Square,
  SquaredDifference,
  Sub,
  Tanh,
  Transpose,
  Update,
}

#[derive(Clone, Debug, Default)]
pub struct LayerConfig {
  pub layer_type: LayerType,
  pub layer_params: Vec<i64>, // This is turned into layer specific configurations at runtime
  pub inp_shapes: Vec<Vec<usize>>,
  pub out_shapes: Vec<Vec<usize>>,
  pub mask: Vec<i64>,
}

pub type CellRc<F> = Rc<AssignedCell<F, F>>;
pub type AssignedTensor<F> = Array<CellRc<F>, IxDyn>;
