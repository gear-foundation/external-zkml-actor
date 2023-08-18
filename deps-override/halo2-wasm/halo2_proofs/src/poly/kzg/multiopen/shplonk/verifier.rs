use crate::io::Read;
use gstd::fmt::Debug;

use super::ChallengeY;
use super::{construct_intermediate_sets, ChallengeU, ChallengeV};
use crate::arithmetic::{
    eval_polynomial, evaluate_vanishing_polynomial, lagrange_interpolate, powers, CurveAffine,
};
use crate::helpers::SerdeCurveAffine;
use crate::os_rng::OsRng;
use crate::poly::commitment::Verifier;
use crate::poly::commitment::MSM;
use crate::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use crate::poly::kzg::msm::DualMSM;
use crate::poly::kzg::msm::{PreMSM, MSMKZG};
use crate::poly::kzg::multiopen::shplonk::IntermediateSets;
use crate::poly::kzg::strategy::{AccumulatorStrategy, GuardKZG, SingleStrategy};
use crate::poly::query::Query;
use crate::poly::query::{CommitmentReference, VerifierQuery};
use crate::poly::strategy::VerificationStrategy;
use crate::poly::{
    commitment::{Params, ParamsVerifier},
    Error,
};
use crate::transcript::{EncodedChallenge, TranscriptRead};
use ff::{Field, PrimeField};
use group::Group;
use gstd::ops::MulAssign;
use halo2curves_wasm::pairing::{Engine, MillerLoopResult, MultiMillerLoop};

/// Concrete KZG multiopen verifier with SHPLONK variant
#[derive(Debug)]
pub struct VerifierSHPLONK<'params, E: Engine> {
    params: &'params ParamsKZG<E>,
}

impl<'params, E> Verifier<'params, KZGCommitmentScheme<E>> for VerifierSHPLONK<'params, E>
where
    E: MultiMillerLoop + Debug,
    E::Scalar: PrimeField + Ord,
    E::G1Affine: SerdeCurveAffine,
    E::G2Affine: SerdeCurveAffine,
{
    type Guard = GuardKZG<'params, E>;
    type MSMAccumulator = DualMSM<'params, E>;

    const QUERY_INSTANCE: bool = false;

    fn new(params: &'params ParamsKZG<E>) -> Self {
        Self { params }
    }

    /// Verify a multi-opening proof
    fn verify_proof<
        'com,
        Ch: EncodedChallenge<E::G1Affine>,
        T: TranscriptRead<E::G1Affine, Ch>,
        I,
    >(
        &self,
        transcript: &mut T,
        queries: I,
        mut msm_accumulator: DualMSM<'params, E>,
    ) -> Result<Self::Guard, Error>
    where
        I: IntoIterator<Item = VerifierQuery<'com, E::G1Affine, MSMKZG<E>>> + Clone,
    {
        let intermediate_sets = construct_intermediate_sets(queries);
        let (rotation_sets, super_point_set) = (
            intermediate_sets.rotation_sets,
            intermediate_sets.super_point_set,
        );

        let y: ChallengeY<_> = transcript.squeeze_challenge_scalar();
        let v: ChallengeV<_> = transcript.squeeze_challenge_scalar();

        let h1 = transcript.read_point().map_err(|_| Error::SamplingError)?;
        let u: ChallengeU<_> = transcript.squeeze_challenge_scalar();
        let h2 = transcript.read_point().map_err(|_| Error::SamplingError)?;

        let (mut z_0_diff_inverse, mut z_0) = (E::Scalar::ZERO, E::Scalar::ZERO);
        let (mut outer_msm, mut r_outer_acc) = (PreMSM::<E>::new(), E::Scalar::ZERO);

        for (i, (rotation_set, power_of_v)) in rotation_sets.iter().zip(powers(*v)).enumerate() {
            let diffs: Vec<E::Scalar> = super_point_set
                .iter()
                .filter(|point| !rotation_set.points.contains(point))
                .copied()
                .collect();
            let mut z_diff_i = evaluate_vanishing_polynomial(&diffs[..], *u);

            // normalize coefficients by the coefficient of the first commitment
            if i == 0 {
                z_0 = evaluate_vanishing_polynomial(&rotation_set.points[..], *u);
                z_0_diff_inverse = z_diff_i.invert().unwrap();
                z_diff_i = E::Scalar::ONE;
            } else {
                z_diff_i.mul_assign(z_0_diff_inverse);
            }

            let (mut inner_msm, r_inner_acc) = rotation_set
                .commitments
                .iter()
                .zip(powers(*y))
                .map(|(commitment_data, power_of_y)| {
                    // calculate low degree equivalent
                    let r_x = lagrange_interpolate(
                        &rotation_set.points[..],
                        &commitment_data.evals()[..],
                    );
                    let r_eval = power_of_y * eval_polynomial(&r_x[..], *u);
                    let msm = match commitment_data.get() {
                        CommitmentReference::Commitment(c) => {
                            let mut msm = MSMKZG::<E>::new();
                            msm.append_term(power_of_y, (*c).into());
                            msm
                        }
                        CommitmentReference::MSM(msm) => {
                            let mut msm = msm.clone();
                            msm.scale(power_of_y);
                            msm
                        }
                    };
                    (msm, r_eval)
                })
                .reduce(|(mut msm_acc, r_eval_acc), (msm, r_eval)| {
                    msm_acc.add_msm(&msm);
                    (msm_acc, r_eval_acc + r_eval)
                })
                .unwrap();

            inner_msm.scale(power_of_v * z_diff_i);
            outer_msm.add_msm(inner_msm);
            r_outer_acc += power_of_v * r_inner_acc * z_diff_i;
        }

        let mut outer_msm = outer_msm.normalize();
        let g1: E::G1 = self.params.g[0].into();
        outer_msm.append_term(-r_outer_acc, g1);
        outer_msm.append_term(-z_0, h1.into());
        outer_msm.append_term(*u, h2.into());

        msm_accumulator.left.append_term(E::Scalar::ONE, h2.into());

        msm_accumulator.right.add_msm(&outer_msm);

        Ok(Self::Guard::new(msm_accumulator))
    }
}
use gstd::prelude::*;

#[derive(Debug, Clone)]
pub struct VerifierIntermediateState<E: Engine> {
    z_0_diff_inverse: E::Scalar,
    z_0: E::Scalar,
    outer_msm: PreMSM<E>,
    r_outer_acc: E::Scalar,

    y: ChallengeY<E::G1Affine>,
    v: ChallengeV<E::G1Affine>,
    u: ChallengeU<E::G1Affine>,

    h1: E::G1Affine,
    h2: E::G1Affine,
}

impl<'params, E> VerifierSHPLONK<'params, E>
where
    E: MultiMillerLoop + Debug,
    E::Scalar: PrimeField + Ord,
    E::G1Affine: SerdeCurveAffine,
    E::G2Affine: SerdeCurveAffine,
{
    pub fn pre_verify_proof_from_intermediate_sets<
        Ch: EncodedChallenge<E::G1Affine>,
        T: TranscriptRead<E::G1Affine, Ch>,
    >(
        &self,
        transcript: &mut T,
        intermediate_sets: IntermediateSets<E::Scalar, VerifierQuery<E::G1Affine, MSMKZG<E>>>,
        mut msm_accumulator: DualMSM<'params, E>,
    ) -> Result<VerifierIntermediateState<E>, Error> {
        let (rotation_sets, super_point_set) = (
            intermediate_sets.rotation_sets,
            intermediate_sets.super_point_set,
        );

        let y: ChallengeY<_> = transcript.squeeze_challenge_scalar();
        let v: ChallengeV<_> = transcript.squeeze_challenge_scalar();

        let h1 = transcript.read_point().map_err(|_| Error::SamplingError)?;
        let u: ChallengeU<_> = transcript.squeeze_challenge_scalar();
        let h2 = transcript.read_point().map_err(|_| Error::SamplingError)?;

        let (mut z_0_diff_inverse, mut z_0) = (E::Scalar::ZERO, E::Scalar::ZERO);
        let (mut outer_msm, mut r_outer_acc) = (PreMSM::<E>::new(), E::Scalar::ZERO);

        for (i, (rotation_set, power_of_v)) in
            rotation_sets.iter().zip(powers(*v)).enumerate().take(2)
        {
            let diffs: Vec<E::Scalar> = super_point_set
                .iter()
                .filter(|point| !rotation_set.points.contains(point))
                .copied()
                .collect();
            let mut z_diff_i = evaluate_vanishing_polynomial(&diffs[..], *u);

            // normalize coefficients by the coefficient of the first commitment
            if i == 0 {
                z_0 = evaluate_vanishing_polynomial(&rotation_set.points[..], *u);
                z_0_diff_inverse = z_diff_i.invert().unwrap();
                z_diff_i = E::Scalar::ONE;
            } else {
                z_diff_i.mul_assign(z_0_diff_inverse);
            }

            let (mut inner_msm, r_inner_acc) = rotation_set
                .commitments
                .iter()
                .zip(powers(*y))
                .map(|(commitment_data, power_of_y)| {
                    // calculate low degree equivalent
                    let r_x = lagrange_interpolate(
                        &rotation_set.points[..],
                        &commitment_data.evals()[..],
                    );
                    let r_eval = power_of_y * eval_polynomial(&r_x[..], *u);
                    let msm = match commitment_data.get() {
                        CommitmentReference::Commitment(c) => {
                            let mut msm = MSMKZG::<E>::new();
                            msm.append_term(power_of_y, (*c).into());
                            msm
                        }
                        CommitmentReference::MSM(msm) => {
                            let mut msm = msm.clone();
                            msm.scale(power_of_y);
                            msm
                        }
                    };
                    (msm, r_eval)
                })
                .reduce(|(mut msm_acc, r_eval_acc), (msm, r_eval)| {
                    msm_acc.add_msm(&msm);
                    (msm_acc, r_eval_acc + r_eval)
                })
                .unwrap();

            inner_msm.scale(power_of_v * z_diff_i);
            outer_msm.add_msm(inner_msm);
            r_outer_acc += power_of_v * r_inner_acc * z_diff_i;
        }

        Ok(VerifierIntermediateState {
            z_0_diff_inverse,
            z_0,
            outer_msm,
            r_outer_acc,

            y,
            v,
            u,

            h1,
            h2,
        })
    }

    pub fn verify_proof_from_intermediate_sets<
        Ch: EncodedChallenge<E::G1Affine>,
        T: TranscriptRead<E::G1Affine, Ch>,
    >(
        &self,
        transcript: &mut T,
        intermediate_sets: IntermediateSets<E::Scalar, VerifierQuery<E::G1Affine, MSMKZG<E>>>,
        mut msm_accumulator: DualMSM<'params, E>,
        int_state: VerifierIntermediateState<E>,
    ) -> Result<GuardKZG<'params, E>, Error> {
        let (rotation_sets, super_point_set) = (
            intermediate_sets.rotation_sets,
            intermediate_sets.super_point_set,
        );

        // let y: ChallengeY<_> = transcript.squeeze_challenge_scalar();
        // let v: ChallengeV<_> = transcript.squeeze_challenge_scalar();

        // let h1 = transcript.read_point().map_err(|_| Error::SamplingError)?;
        // let u: ChallengeU<_> = transcript.squeeze_challenge_scalar();
        // let h2 = transcript.read_point().map_err(|_| Error::SamplingError)?;

        let y = int_state.y;
        let v = int_state.v;
        let u = int_state.u;

        let h1 = int_state.h1;
        let h2 = int_state.h2;

        let (mut z_0_diff_inverse, mut z_0) = (int_state.z_0_diff_inverse, int_state.z_0);
        let (mut outer_msm, mut r_outer_acc) = (int_state.outer_msm, int_state.r_outer_acc);

        for (i, (rotation_set, power_of_v)) in
            rotation_sets.iter().zip(powers(*v)).enumerate().skip(2)
        {
            let diffs: Vec<E::Scalar> = super_point_set
                .iter()
                .filter(|point| !rotation_set.points.contains(point))
                .copied()
                .collect();
            let mut z_diff_i = evaluate_vanishing_polynomial(&diffs[..], *u);

            // normalize coefficients by the coefficient of the first commitment
            if i == 0 {
                z_0 = evaluate_vanishing_polynomial(&rotation_set.points[..], *u);
                z_0_diff_inverse = z_diff_i.invert().unwrap();
                z_diff_i = E::Scalar::ONE;
            } else {
                z_diff_i.mul_assign(z_0_diff_inverse);
            }

            let (mut inner_msm, r_inner_acc) = rotation_set
                .commitments
                .iter()
                .zip(powers(*y))
                .map(|(commitment_data, power_of_y)| {
                    // calculate low degree equivalent
                    let r_x = lagrange_interpolate(
                        &rotation_set.points[..],
                        &commitment_data.evals()[..],
                    );
                    let r_eval = power_of_y * eval_polynomial(&r_x[..], *u);
                    let msm = match commitment_data.get() {
                        CommitmentReference::Commitment(c) => {
                            let mut msm = MSMKZG::<E>::new();
                            msm.append_term(power_of_y, (*c).into());
                            msm
                        }
                        CommitmentReference::MSM(msm) => {
                            let mut msm = msm.clone();
                            msm.scale(power_of_y);
                            msm
                        }
                    };
                    (msm, r_eval)
                })
                .reduce(|(mut msm_acc, r_eval_acc), (msm, r_eval)| {
                    msm_acc.add_msm(&msm);
                    (msm_acc, r_eval_acc + r_eval)
                })
                .unwrap();

            inner_msm.scale(power_of_v * z_diff_i);
            outer_msm.add_msm(inner_msm);
            r_outer_acc += power_of_v * r_inner_acc * z_diff_i;
        }

        let mut outer_msm = outer_msm.normalize();
        let g1: E::G1 = self.params.g[0].into();
        outer_msm.append_term(-r_outer_acc, g1);
        outer_msm.append_term(-z_0, h1.into());
        outer_msm.append_term(*u, h2.into());

        msm_accumulator.left.append_term(E::Scalar::ONE, h2.into());

        msm_accumulator.right.add_msm(&outer_msm);

        Ok(GuardKZG::new(msm_accumulator))
    }
}