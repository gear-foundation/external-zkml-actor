use gstd::prelude::*;
//use gstd::{fs::File, io::BufReader};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TensorMsgpack {
  pub idx: i64,
  pub shape: Vec<i64>,
  pub data: Vec<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LayerMsgpack {
  pub layer_type: String,
  pub params: Vec<i64>,
  pub inp_idxes: Vec<i64>,
  pub inp_shapes: Vec<Vec<i64>>,
  pub out_idxes: Vec<i64>,
  pub out_shapes: Vec<Vec<i64>>,
  pub mask: Vec<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModelMsgpack {
  pub global_sf: i64,
  pub k: i64,
  pub num_cols: i64,
  pub inp_idxes: Vec<i64>,
  pub out_idxes: Vec<i64>,
  pub tensors: Vec<TensorMsgpack>,
  pub layers: Vec<LayerMsgpack>,
  pub use_selectors: Option<bool>,
  pub commit_before: Option<Vec<Vec<i64>>>,
  pub commit_after: Option<Vec<Vec<i64>>>,
  pub bits_per_elem: Option<i64>, // Specifically for packing for the commitments
  pub num_random: Option<i64>,
}
