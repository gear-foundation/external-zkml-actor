use gstd::fmt::Debug;

use super::commitment::{KZGCommitmentScheme, ParamsKZG};
use crate::{
    arithmetic::{best_multiexp, parallelize, CurveAffine},
    poly::commitment::MSM,
};
use group::{Curve, Group};
use halo2curves_wasm::pairing::{Engine, MillerLoopResult, MultiMillerLoop};

/// A multiscalar multiplication in the polynomial commitment scheme
#[derive(Clone, Default, Debug)]
pub struct MSMKZG<E: Engine> {
    pub(crate) scalars: Vec<E::Scalar>,
    pub(crate) bases: Vec<E::G1>,
    already_evaluated: usize,
    eval_cache: Option<E::G1>,
}

impl<E: Engine> MSMKZG<E> {
    /// Create an empty MSM instance
    pub fn new() -> Self {
        MSMKZG {
            scalars: vec![],
            bases: vec![],
            already_evaluated: 0,
            eval_cache: Default::default(),
        }
    }

    /// Prepares all scalars in the MSM to linear combination
    pub fn combine_with_base(&mut self, base: E::Scalar) {
        use ff::Field;
        let mut acc = E::Scalar::ONE;
        if !self.scalars.is_empty() {
            for scalar in self.scalars.iter_mut().rev() {
                *scalar *= &acc;
                acc *= base;
            }
        }
    }

    /// Returns evaluated amount.
    fn eval_part(&mut self, amount: usize) -> usize {
        use group::prime::PrimeCurveAffine;

        let amount_to_eval = amount.min(self.scalars.len() - self.already_evaluated);
        let mut bases = vec![E::G1Affine::identity(); amount_to_eval];
        E::G1::batch_normalize(
            &self.bases[self.already_evaluated..self.already_evaluated + amount_to_eval],
            &mut bases,
        );

        let res = best_multiexp(
            &self.scalars[self.already_evaluated..self.already_evaluated + amount_to_eval],
            &bases,
        );

        if let Some(eval_cache) = self.eval_cache.as_mut() {
            *eval_cache = *eval_cache + res;
        } else {
            self.eval_cache = Some(res);
        }

        self.already_evaluated += amount_to_eval;
        amount_to_eval
    }
}

impl<E: Engine + Debug> MSM<E::G1Affine> for MSMKZG<E> {
    fn append_term(&mut self, scalar: E::Scalar, point: E::G1) {
        self.scalars.push(scalar);
        self.bases.push(point);
    }

    fn add_msm(&mut self, other: &Self) {
        self.scalars.extend(other.scalars().iter());
        self.bases.extend(other.bases().iter());
    }

    fn scale(&mut self, factor: E::Scalar) {
        if !self.scalars.is_empty() {
            parallelize(&mut self.scalars, |scalars, _| {
                for other_scalar in scalars {
                    *other_scalar *= &factor;
                }
            })
        }
    }

    fn check(&self) -> bool {
        bool::from(self.eval().is_identity())
    }

    fn eval(&self) -> E::G1 {
        use group::prime::PrimeCurveAffine;

        let mut bases = vec![E::G1Affine::identity(); self.scalars.len()];
        E::G1::batch_normalize(&self.bases, &mut bases);
        let res = best_multiexp(&self.scalars, &bases);

        res
    }

    fn bases(&self) -> Vec<E::G1> {
        self.bases.clone()
    }

    fn scalars(&self) -> Vec<E::Scalar> {
        self.scalars.clone()
    }
}

/// A projective point collector
#[derive(Debug, Clone)]
pub(crate) struct PreMSM<E: Engine> {
    projectives_msms: Vec<MSMKZG<E>>,
}

impl<E: Engine + Debug> PreMSM<E> {
    pub(crate) fn new() -> Self {
        PreMSM {
            projectives_msms: vec![],
        }
    }

    pub(crate) fn normalize(self) -> MSMKZG<E> {
        use group::prime::PrimeCurveAffine;

        let (scalars, bases) = self
            .projectives_msms
            .into_iter()
            .map(|msm| (msm.scalars, msm.bases))
            .unzip::<_, _, Vec<_>, Vec<_>>();

        MSMKZG {
            scalars: scalars.into_iter().flatten().collect(),
            bases: bases.into_iter().flatten().collect(),
            already_evaluated: 0,
            eval_cache: Default::default(),
        }
    }

    pub(crate) fn add_msm(&mut self, other: MSMKZG<E>) {
        self.projectives_msms.push(other);
    }
}

impl<'params, E: MultiMillerLoop + Debug> From<&'params ParamsKZG<E>> for DualMSM<'params, E> {
    fn from(params: &'params ParamsKZG<E>) -> Self {
        DualMSM::new(params)
    }
}

/// Two channel MSM accumulator
#[derive(Debug, Clone)]
pub struct DualMSM<'a, E: Engine> {
    pub(crate) params: &'a ParamsKZG<E>,
    pub(crate) left: MSMKZG<E>,
    pub(crate) right: MSMKZG<E>,
}

#[derive(Debug, Clone)]
pub struct DualMSMData<E: Engine> {
    pub(crate) left: MSMKZG<E>,
    pub(crate) right: MSMKZG<E>,
    left_eval: Option<E::G1>,
    right_eval: Option<E::G1>,
}

impl<E: Engine + MultiMillerLoop + Debug> DualMSMData<E> {
    pub fn new(msm: DualMSM<'_, E>) -> Self {
        Self {
            left: msm.left,
            right: msm.right,
            left_eval: None,
            right_eval: None,
        }
    }

    pub fn eval_staged(&mut self, params: &ParamsKZG<E>) -> bool {
        const MAX_BUDGET: usize = 2;
        // 56 overall
        let mut budget = MAX_BUDGET;
        budget -= self.left.eval_part(budget);
        budget -= self.right.eval_part(budget);

        if budget == MAX_BUDGET {
            self.left_eval = self.left.eval_cache.clone();
            self.right_eval = self.right.eval_cache.clone();
            true
        } else {
            false
        }
    }

    pub fn check_stage_1(self, params: &ParamsKZG<E>) -> <E as MultiMillerLoop>::Result {
        let s_g2_prepared = E::G2Prepared::from(params.s_g2);
        let n_g2_prepared = E::G2Prepared::from(-params.g2);

        let (term_1, term_2) = (
            (&self.left_eval.unwrap().into(), &s_g2_prepared),
            (&self.right_eval.unwrap().into(), &n_g2_prepared),
        );
        let terms = &[term_1, term_2];

        E::multi_miller_loop(&terms[..])
    }

    pub fn check(self, params: &ParamsKZG<E>) -> bool {
        let s_g2_prepared = E::G2Prepared::from(params.s_g2);
        let n_g2_prepared = E::G2Prepared::from(-params.g2);
        let (term_1, term_2) = (
            (&self.left_eval.unwrap().into(), &s_g2_prepared),
            (&self.right_eval.unwrap().into(), &n_g2_prepared),
        );
        let terms = &[term_1, term_2];
        let mml = E::multi_miller_loop(&terms[..]);
        let final_exp = mml.final_exponentiation();
        bool::from(final_exp.is_identity())
    }
}

impl<'a, E: MultiMillerLoop + Debug> DualMSM<'a, E> {
    /// Create a new two channel MSM accumulator instance
    pub fn new(params: &'a ParamsKZG<E>) -> Self {
        Self {
            params,
            left: MSMKZG::new(),
            right: MSMKZG::new(),
        }
    }

    /// Scale all scalars in the MSM by some scaling factor
    pub fn scale(&mut self, e: E::Scalar) {
        self.left.scale(e);
        self.right.scale(e);
    }

    /// Add another multiexp into this one
    pub fn add_msm(&mut self, other: Self) {
        self.left.add_msm(&other.left);
        self.right.add_msm(&other.right);
    }

    /// Performs final pairing check with given verifier params and two channel linear combination
    pub fn check(self) -> bool {
        let s_g2_prepared = E::G2Prepared::from(self.params.s_g2);
        let n_g2_prepared = E::G2Prepared::from(-self.params.g2);

        let left = self.left.eval();
        let right = self.right.eval();

        let (term_1, term_2) = (
            (&left.into(), &s_g2_prepared),
            (&right.into(), &n_g2_prepared),
        );
        let terms = &[term_1, term_2];

        bool::from(
            E::multi_miller_loop(&terms[..])
                .final_exponentiation()
                .is_identity(),
        )
    }
}
use gstd::prelude::*;
