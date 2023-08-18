mod prover;
pub mod verifier;

use crate::poly::commitment::{self, MSM};
use crate::poly::kzg::msm::MSMKZG;
use crate::poly::query::CommitmentReference;
use crate::poly::VerifierQuery;
use crate::HashMap;
use crate::{
    arithmetic::{eval_polynomial, lagrange_interpolate, CurveAffine},
    poly::{query::Query, Coeff, Polynomial},
    transcript::ChallengeScalar,
};
use ff::Field;
use gstd::{
    collections::{btree_map::Entry, BTreeMap},
    marker::PhantomData,
};
use halo2curves_wasm::bn256::{Bn256, Fr};
use halo2curves_wasm::pairing::Engine;
pub use prover::ProverSHPLONK;
pub use verifier::VerifierSHPLONK;

#[derive(Clone, Copy, Debug)]
struct U {}
type ChallengeU<F> = ChallengeScalar<F, U>;

#[derive(Clone, Copy, Debug)]
struct V {}
type ChallengeV<F> = ChallengeScalar<F, V>;

#[derive(Clone, Copy, Debug)]
struct Y {}
type ChallengeY<F> = ChallengeScalar<F, Y>;

#[derive(Debug, Clone, PartialEq)]
pub struct Commitment<F: Field, T: PartialEq + Clone>((T, Vec<F>));

impl<F: Field, T: PartialEq + Clone> Commitment<F, T> {
    fn get(&self) -> T {
        self.0 .0.clone()
    }

    fn evals(&self) -> Vec<F> {
        self.0 .1.clone()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RotationSet<F: Field, T: PartialEq + Clone> {
    commitments: Vec<Commitment<F, T>>,
    points: Vec<F>,
}

#[derive(Clone, Debug)]
pub enum CommitmentDereference<C: CurveAffine, M: MSM<C>> {
    Commitment(C, usize),
    MSM(M, usize),
}

impl<C: CurveAffine, M: MSM<C>> CommitmentDereference<C, M> {
    fn from_reference(reference: CommitmentReference<'_, C, M>) -> Self {
        match reference {
            CommitmentReference::Commitment(commitment) => {
                Self::Commitment(*commitment, commitment as *const C as usize)
            }
            CommitmentReference::MSM(msm) => Self::MSM(msm.clone(), msm as *const M as usize),
        }
    }
}

impl<C: CurveAffine, M: MSM<C>> PartialEq for CommitmentDereference<C, M> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (&Self::Commitment(_, a_ptr_addr), &Self::Commitment(_, b_ptr_addr)) => {
                a_ptr_addr == b_ptr_addr
            }
            (&Self::MSM(_, a_ptr_addr), &Self::MSM(_, b_ptr_addr)) => a_ptr_addr == b_ptr_addr,
            _ => false,
        }
    }
}

#[derive(Debug)]
pub struct IntermediateSetsData<F: Field> {
    rotation_sets:
        Vec<RotationSet<F, CommitmentDereference<<Bn256 as Engine>::G1Affine, MSMKZG<Bn256>>>>,
    super_point_set: BTreeSet<F>,

    commitments: HashMap<usize, <Bn256 as Engine>::G1Affine>,
    msms: HashMap<usize, MSMKZG<Bn256>>,
}

impl IntermediateSetsData<Fr> {
    pub fn get_sets(
        &self,
    ) -> IntermediateSets<Fr, VerifierQuery<'_, <Bn256 as Engine>::G1Affine, MSMKZG<Bn256>>> {
        IntermediateSets {
            super_point_set: self.super_point_set.clone(),
            rotation_sets: self
                .rotation_sets
                .iter()
                .map(|rs| RotationSet {
                    commitments: rs
                        .commitments
                        .iter()
                        .map(|comm| {
                            Commitment((
                                match comm.0 .0 {
                                    CommitmentDereference::Commitment(_, ptr) => {
                                        CommitmentReference::Commitment(
                                            self.commitments.get(&ptr).unwrap(),
                                        )
                                    }
                                    CommitmentDereference::MSM(_, ptr) => {
                                        CommitmentReference::MSM(self.msms.get(&ptr).unwrap())
                                    }
                                },
                                comm.0 .1.clone(),
                            ))
                        })
                        .collect(),
                    points: rs.points.clone(),
                })
                .collect(),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct IntermediateSets<F: Field, Q: Query<F>> {
    rotation_sets: Vec<RotationSet<F, Q::Commitment>>,
    super_point_set: BTreeSet<F>,
}

impl IntermediateSets<Fr, VerifierQuery<'_, <Bn256 as Engine>::G1Affine, MSMKZG<Bn256>>> {
    pub fn into_data(self) -> IntermediateSetsData<Fr> {
        let mut commitments = HashMap::new();
        let mut msms = HashMap::new();

        let rotation_sets = self
            .rotation_sets
            .into_iter()
            .map(|rs| RotationSet {
                points: rs.points,
                commitments: rs
                    .commitments
                    .into_iter()
                    .map(|comm| {
                        Commitment((
                            match comm.0 .0 {
                                CommitmentReference::Commitment(commitment) => {
                                    commitments.insert(
                                        commitment as *const <Bn256 as Engine>::G1Affine as usize,
                                        *commitment,
                                    );

                                    CommitmentDereference::Commitment(
                                        *commitment,
                                        commitment as *const <Bn256 as Engine>::G1Affine as usize,
                                    )
                                }
                                CommitmentReference::MSM(msm) => {
                                    msms.insert(msm as *const MSMKZG<Bn256> as usize, msm.clone());

                                    CommitmentDereference::MSM(
                                        msm.clone(),
                                        msm as *const MSMKZG<Bn256> as usize,
                                    )
                                }
                            },
                            comm.0 .1,
                        ))
                    })
                    .collect::<Vec<Commitment<_, _>>>(),
            })
            .collect();

        IntermediateSetsData {
            rotation_sets,
            super_point_set: self.super_point_set,
            commitments,
            msms,
        }
    }
}

pub fn construct_intermediate_sets<F: Field + Ord, I, Q: Query<F, Eval = F>>(
    queries: I,
) -> IntermediateSets<F, Q>
where
    I: IntoIterator<Item = Q> + Clone,
{
    let queries = queries.into_iter().collect::<Vec<_>>();

    // Find evaluation of a commitment at a rotation
    let get_eval = |commitment: Q::Commitment, rotation: F| -> F {
        queries
            .iter()
            .find(|query| query.get_commitment() == commitment && query.get_point() == rotation)
            .unwrap()
            .get_eval()
    };

    // All points that appear in queries
    let mut super_point_set = BTreeSet::new();

    // Collect rotation sets for each commitment
    // Example elements in the vector:
    // (C_0, {r_5}),
    // (C_1, {r_1, r_2, r_3}),
    // (C_2, {r_2, r_3, r_4}),
    // (C_3, {r_2, r_3, r_4}),
    // ...
    let mut commitment_rotation_set_map: Vec<(Q::Commitment, BTreeSet<F>)> = vec![];
    for query in queries.iter() {
        let rotation = query.get_point();
        super_point_set.insert(rotation);
        if let Some(commitment_rotation_set) = commitment_rotation_set_map
            .iter_mut()
            .find(|(commitment, _)| *commitment == query.get_commitment())
        {
            let (_, rotation_set) = commitment_rotation_set;
            rotation_set.insert(rotation);
        } else {
            commitment_rotation_set_map.push((
                query.get_commitment(),
                BTreeSet::from_iter(gstd::iter::once(rotation)),
            ));
        };
    }

    // Flatten rotation sets and collect commitments that opens against each commitment set
    // Example elements in the vector:
    // {r_5}: [C_0],
    // {r_1, r_2, r_3} : [C_1]
    // {r_2, r_3, r_4} : [C_2, C_3],
    // ...
    // NOTE: we want to make the order of the collection of rotation sets independent of the opening points, to ease the verifier computation
    let mut rotation_set_commitment_map: Vec<(BTreeSet<F>, Vec<Q::Commitment>)> = vec![];
    for (commitment, rotation_set) in commitment_rotation_set_map.into_iter() {
        if let Some(rotation_set_commitment) = rotation_set_commitment_map
            .iter_mut()
            .find(|(set, _)| set == &rotation_set)
        {
            let (_, commitments) = rotation_set_commitment;
            commitments.push(commitment);
        } else {
            rotation_set_commitment_map.push((rotation_set, vec![commitment]));
        };
    }

    let rotation_sets = rotation_set_commitment_map
        .into_iter()
        .map(|(rotations, commitments)| {
            let rotations_vec = rotations.iter().collect::<Vec<_>>();
            let commitments: Vec<Commitment<F, Q::Commitment>> = commitments
                .into_iter()
                .map(|commitment| {
                    let evals: Vec<F> = rotations_vec
                        .iter()
                        .map(|&&rotation| get_eval(commitment, rotation))
                        .collect();
                    Commitment((commitment, evals))
                })
                .collect();

            RotationSet {
                commitments,
                points: rotations.into_iter().collect(),
            }
        })
        .collect::<Vec<RotationSet<_, _>>>();

    IntermediateSets {
        rotation_sets,
        super_point_set,
    }
}

use gstd::prelude::*;
