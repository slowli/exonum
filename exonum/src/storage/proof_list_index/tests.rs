// Copyright 2018 The Exonum Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use rand::{thread_rng, Rng};
use serde_json;

use std::cmp;

use super::{pair_hash, ListProof, ListProofError, ProofListIndex, RootNode};
use crypto::{hash, CryptoHash, Hash};
use storage::Database;

const IDX_NAME: &'static str = "idx_name";

fn random_values<R: Rng>(rng: &mut R, len: usize) -> Vec<Vec<u8>> {
    use std::collections::HashSet;
    let mut exists = HashSet::new();
    let generator = |_| {
        let mut new_val: Vec<u8> = vec![0; 10];
        rng.fill_bytes(&mut new_val);

        while exists.contains(&new_val) {
            rng.fill_bytes(&mut new_val);
        }
        exists.insert(new_val.clone());
        new_val
    };

    (0..len).map(generator).collect::<Vec<_>>()
}

fn gen_tempdir_name() -> String {
    thread_rng().gen_ascii_chars().take(10).collect()
}

fn list_methods(db: Box<dyn Database>) {
    let mut fork = db.fork();
    let mut index = ProofListIndex::new(IDX_NAME, &mut fork);

    assert!(index.is_empty());
    assert_eq!(index.len(), 0);
    index.push(vec![1]);
    assert!(!index.is_empty());
    assert_eq!(index.len(), 1);

    index.push(vec![2]);
    assert_eq!(index.len(), 2);

    index.push(vec![3]);
    assert_eq!(index.len(), 3);

    assert_eq!(index.get(0), Some(vec![1]));
    assert_eq!(index.get(1), Some(vec![2]));
    assert_eq!(index.get(2), Some(vec![3]));
}

fn height(db: Box<dyn Database>) {
    let mut fork = db.fork();
    let mut index = ProofListIndex::new(IDX_NAME, &mut fork);

    index.push(vec![1]);
    assert_eq!(index.height(), 1);

    index.push(vec![2]);
    assert_eq!(index.height(), 2);

    index.push(vec![3]);
    assert_eq!(index.height(), 3);

    index.push(vec![4]);
    assert_eq!(index.height(), 3);

    assert_eq!(index.len(), 4);
    assert_eq!(index.get(0), Some(vec![1]));
    assert_eq!(index.get(1), Some(vec![2]));
    assert_eq!(index.get(2), Some(vec![3]));
    assert_eq!(index.get(3), Some(vec![4]));

    index.set(1, vec![10]);
    assert_eq!(index.get(1), Some(vec![10]));
}

fn iter(db: Box<dyn Database>) {
    let mut fork = db.fork();
    let mut list_index = ProofListIndex::new(IDX_NAME, &mut fork);

    list_index.extend(vec![1u8, 2, 3]);

    assert_eq!(list_index.iter().collect::<Vec<u8>>(), vec![1, 2, 3]);
    assert_eq!(list_index.iter_from(0).collect::<Vec<u8>>(), vec![1, 2, 3]);
    assert_eq!(list_index.iter_from(1).collect::<Vec<u8>>(), vec![2, 3]);
    assert_eq!(
        list_index.iter_from(3).collect::<Vec<u8>>(),
        Vec::<u8>::new()
    );
}

fn simple_proof(db: Box<dyn Database>) {
    let mut fork = db.fork();
    let mut index = ProofListIndex::new(IDX_NAME, &mut fork);

    let h0 = 2u64.hash();
    let h1 = 4u64.hash();
    let h2 = 6u64.hash();
    let h01 = pair_hash(&h0, &h1);
    let h22 = hash(h2.as_ref());
    let h012 = pair_hash(&h01, &h22);

    assert_eq!(
        index.merkle_root(),
        RootNode::node_hash(&Hash::default(), 0)
    );

    index.push(2u64);

    assert_eq!(index.merkle_root(), RootNode::node_hash(&h0, 1));
    let proof = index.get_proof(0);
    assert_eq!(proof, ListProof::new(vec![(0, 2u64)], 1));
    assert_eq!(*proof.validate(index.merkle_root()).unwrap(), [(0, 2)]);

    index.push(4u64);
    assert_eq!(index.merkle_root(), RootNode::node_hash(&h01, 2));

    let proof = index.get_proof(0);
    assert_eq!(proof, {
        let mut proof = ListProof::new(vec![(0, 2u64)], 2);
        proof.push_hash(1, 1, h1);
        proof
    });
    assert_eq!(*proof.validate(index.merkle_root()).unwrap(), [(0, 2)]);

    let proof = index.get_proof(1);
    assert_eq!(proof, {
        let mut proof = ListProof::new(vec![(1, 4u64)], 2);
        proof.push_hash(1, 0, h0);
        proof
    });
    assert_eq!(*proof.validate(index.merkle_root()).unwrap(), [(1, 4)]);

    let proof = index.get_range_proof(0, 2);
    assert_eq!(proof, ListProof::new(vec![(0, 2u64), (1, 4u64)], 2));
    assert_eq!(
        *proof.validate(index.merkle_root()).unwrap(),
        [(0, 2), (1, 4)]
    );

    index.push(6u64);
    assert_eq!(index.merkle_root(), RootNode::node_hash(&h012, 3));

    let proof = index.get_proof(0);
    assert_eq!(proof, {
        let mut proof = ListProof::new(vec![(0, 2u64)], 3);
        proof.push_hash(1, 1, h1);
        proof.push_hash(2, 1, h22);
        proof
    });
    assert_eq!(*proof.validate(index.merkle_root()).unwrap(), [(0, 2)]);

    let proof = index.get_range_proof(1, 3);
    assert_eq!(proof, {
        let mut proof = ListProof::new(vec![(1, 4u64), (2, 6u64)], 3);
        proof.push_hash(1, 0, h0);
        proof
    });
    assert_eq!(
        *proof.validate(index.merkle_root()).unwrap(),
        [(1, 4u64), (2, 6u64)]
    );

    let proof = index.get_range_proof(0, 2);
    assert_eq!(proof, {
        let mut proof = ListProof::new(vec![(0, 2u64), (1, 4u64)], 3);
        proof.push_hash(2, 1, h22);
        proof
    });
    assert_eq!(
        *proof.validate(index.merkle_root()).unwrap(),
        [(0, 2u64), (1, 4u64)]
    );
}

fn random_proofs(db: Box<dyn Database>) {
    const LIST_SIZE: usize = 1 << 10;
    const MAX_RANGE_SIZE: u64 = 128;

    let mut fork = db.fork();
    let mut index = ProofListIndex::new(IDX_NAME, &mut fork);

    let mut rng = thread_rng();
    let values = random_values(&mut rng, LIST_SIZE);

    for value in &values {
        index.push(value.clone());
    }

    let table_merkle_root = index.merkle_root();

    for _ in 0..10 {
        let start = rng.gen_range(0, LIST_SIZE as u64);
        let end = rng.gen_range(start + 1, LIST_SIZE as u64 + 1);
        let end = cmp::min(end, start + MAX_RANGE_SIZE);

        let range_proof = index.get_range_proof(start, end);

        {
            let (indices, actual_values): (Vec<_>, Vec<_>) = range_proof
                .validate(table_merkle_root)
                .unwrap()
                .to_vec()
                .into_iter()
                .unzip();
            assert_eq!(indices, (start..end).collect::<Vec<_>>());

            let expected_values = &values[start as usize..end as usize];
            assert_eq!(expected_values, actual_values.as_slice());
        }
    }
}

fn simple_merkle_root(db: Box<dyn Database>) {
    let h1 = hash(&[1]);
    let h2 = hash(&[2]);

    let mut fork = db.fork();
    let mut index = ProofListIndex::new(IDX_NAME, &mut fork);
    assert_eq!(index.get(0), None);
    index.push(vec![1]);
    assert_eq!(index.merkle_root(), RootNode::node_hash(&h1, 1));

    index.set(0, vec![2]);
    assert_eq!(index.merkle_root(), RootNode::node_hash(&h2, 1));
}

fn same_merkle_root(db: Box<dyn Database>) {
    let hash1 = {
        let mut fork = db.fork();

        let mut list = ProofListIndex::new(IDX_NAME, &mut fork);
        list.push(vec![1]);
        list.push(vec![2]);
        list.push(vec![3]);
        list.push(vec![4]);

        list.set(0, vec![4]);
        list.set(1, vec![7]);
        list.set(2, vec![5]);
        list.set(3, vec![1]);

        list.merkle_root()
    };
    let hash2 = {
        let mut fork = db.fork();

        let mut list = ProofListIndex::new(IDX_NAME, &mut fork);
        list.push(vec![4]);
        list.push(vec![7]);
        list.push(vec![5]);
        list.push(vec![1]);

        list.merkle_root()
    };
    assert_eq!(hash1, hash2);
}

#[test]
fn proof_json_serialization() {
    let mut proof = ListProof::new(vec![(1, "foo".to_owned()), (2, "bar".to_owned())], 4);
    proof.push_hash(1, 0, 4u64.hash());
    proof.push_hash(2, 1, 2u64.hash());
    proof.push_hash(3, 1, 1u64.hash());

    let json = serde_json::to_value(&proof).unwrap();
    assert_eq!(
        json,
        json!({
            "values": [(1, "foo"), (2, "bar")],
            "hashes": [
                { "height": 1, "index": 0, "hash": 4u64.hash() },
                { "height": 2, "index": 1, "hash": 2u64.hash() },
                { "height": 3, "index": 1, "hash": 1u64.hash() },
            ],
            "height": 4,
        })
    );

    let proof_from_json: ListProof<String> = serde_json::from_value(json).unwrap();
    assert_eq!(proof_from_json, proof);
}

#[test]
fn unordered_proofs() {
    let json = json!({
        "values": [(2, "foo"), (1, "bar")],
        "hashes": [],
        "height": 2,
    });
    let proof: ListProof<String> = serde_json::from_value(json).unwrap();
    assert_eq!(
        proof.validate(().hash()).unwrap_err(),
        ListProofError::Unordered
    );

    let json = json!({
        "values": [(2, "foo")],
        "hashes": [
            { "height": 1, "index": 3, "hash": Hash::zero() },
            { "height": 1, "index": 1, "hash": Hash::zero() },
        ],
        "height": 2,
    });
    let proof: ListProof<String> = serde_json::from_value(json).unwrap();
    assert_eq!(
        proof.validate(().hash()).unwrap_err(),
        ListProofError::Unordered
    );

    let json = json!({
        "values": [(2, "foo")],
        "hashes": [
            { "height": 2, "index": 1, "hash": Hash::zero() },
            { "height": 2, "index": 3, "hash": Hash::zero() },
            { "height": 1, "index": 2, "hash": Hash::zero() },
        ],
        "height": 5,
    });
    let proof: ListProof<String> = serde_json::from_value(json).unwrap();
    assert_eq!(
        proof.validate(().hash()).unwrap_err(),
        ListProofError::Unordered
    );
}

#[test]
fn proofs_with_unexpected_branches() {
    let root_hash = ().hash();

    let proof: ListProof<u64> = serde_json::from_value(json!({
        "values": [(2, 2)],
        "hashes": [
            { "height": 10, "index": 2, "hash": Hash::zero() },
        ],
        "height": 5,
    })).unwrap();
    assert_eq!(
        proof.validate(root_hash).unwrap_err(),
        ListProofError::UnexpectedBranch
    );

    let proof: ListProof<u64> = serde_json::from_value(json!({
        "values": [(2, 2)],
        "hashes": [
            { "height": 5, "index": 0, "hash": Hash::zero() },
        ],
        "height": 5,
    })).unwrap();
    assert_eq!(
        proof.validate(root_hash).unwrap_err(),
        ListProofError::UnexpectedBranch
    );

    let mut proof = ListProof::new(vec![(1, "foo".to_owned()), (2, "bar".to_owned())], 3);
    proof.push_hash(2, 2, Hash::zero());
    assert_eq!(
        proof.validate(root_hash).unwrap_err(),
        ListProofError::UnexpectedBranch
    );

    let mut proof = ListProof::new(vec![(1, "foo".to_owned()), (2, "bar".to_owned())], 3);
    proof.push_hash(1, 4, Hash::zero());
    assert_eq!(
        proof.validate(root_hash).unwrap_err(),
        ListProofError::UnexpectedBranch
    );

    let mut proof = ListProof::new(vec![(1, 1u64), (2, 2), (4, 4)], 4);
    proof.push_hash(1, 0, Hash::zero());
    proof.push_hash(1, 3, Hash::zero());
    proof.push_hash(2, 3, Hash::zero());
    assert_eq!(
        proof.validate(root_hash).unwrap_err(),
        ListProofError::UnexpectedBranch
    );
}

#[test]
fn proofs_with_unexpected_leaf() {
    let proof: ListProof<u64> = serde_json::from_value(json!({
        "values": [(2, 2)],
        "hashes": [
            { "height": 0, "index": 1, "hash": Hash::zero() },
            { "height": 1, "index": 1, "hash": Hash::zero() },
        ],
        "height": 5,
    })).unwrap();
    assert_eq!(
        proof.validate(1u64.hash()).unwrap_err(),
        ListProofError::UnexpectedLeaf
    );
}

#[test]
fn proofs_with_missing_entry() {
    let proof = ListProof::new(vec![(1, 1u64), (2, 2)], 3);
    // (1, 0) is missing
    assert_eq!(
        proof.validate(1u64.hash()).unwrap_err(),
        ListProofError::MissingEntry
    );

    let mut proof = ListProof::new(vec![(1, 1u64)], 4);
    proof.push_hash(1, 0, Hash::zero());
    // (2, 1) is missing
    assert_eq!(
        proof.validate(1u64.hash()).unwrap_err(),
        ListProofError::MissingEntry
    );

    let mut proof = ListProof::new(vec![(1, 1u64), (2, 2)], 4);
    proof.push_hash(1, 0, Hash::zero());
    proof.push_hash(1, 3, Hash::zero());
    // (3, 1) is missing
    assert_eq!(
        proof.validate(1u64.hash()).unwrap_err(),
        ListProofError::MissingEntry
    );
}

macro_rules! test_on_db {
    ($fn_name:ident) => {
        #[test]
        fn $fn_name() {
            let dir = TempDir::new(super::gen_tempdir_name().as_str()).unwrap();
            let path = dir.path();
            let db = create_database(path);
            super::$fn_name(db);
        }
    };
}

macro_rules! common_tests {
    () => {
        test_on_db!(list_methods);
        test_on_db!(height);
        test_on_db!(iter);
        test_on_db!(simple_proof);
        test_on_db!(random_proofs);
        test_on_db!(simple_merkle_root);
        test_on_db!(same_merkle_root);
    };
}

mod memorydb {
    use std::path::Path;
    use storage::{Database, MemoryDB};
    use tempdir::TempDir;

    fn create_database(_: &Path) -> Box<dyn Database> {
        Box::new(MemoryDB::new())
    }

    common_tests!();
}

mod rocksdb {
    use std::path::Path;
    use storage::{Database, DbOptions, RocksDB};
    use tempdir::TempDir;

    fn create_database(path: &Path) -> Box<dyn Database> {
        let opts = DbOptions::default();
        Box::new(RocksDB::open(path, &opts).unwrap())
    }

    common_tests!();
}
