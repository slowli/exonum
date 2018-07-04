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

use std::cmp::Ordering;

use super::{super::StorageValue, key::ProofListKey, pair_hash, RootNode};
use crypto::{hash, Hash};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
struct HashedEntry {
    #[serde(flatten)]
    key: ProofListKey,
    hash: Hash,
}

impl HashedEntry {
    fn new(key: ProofListKey, hash: Hash) -> Self {
        HashedEntry { key, hash }
    }
}

/// TODO
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ListProof<V> {
    hashes: Vec<HashedEntry>,
    values: Vec<(u64, V)>,
    height: u8,
}

fn merge<T, U>(first: T, second: U) -> impl Iterator<Item = Result<HashedEntry, ()>>
where
    T: Iterator<Item = HashedEntry>,
    U: Iterator<Item = HashedEntry>,
{
    struct Merge<T, U> {
        first: T,
        second: U,
        first_item: Option<HashedEntry>,
        second_item: Option<HashedEntry>,
    }

    impl<T, U> Merge<T, U>
    where
        T: Iterator<Item = HashedEntry>,
        U: Iterator<Item = HashedEntry>,
    {
        fn new(mut first: T, mut second: U) -> Self {
            let (first_item, second_item) = (first.next(), second.next());
            Merge {
                first,
                second,
                first_item,
                second_item,
            }
        }
    }

    impl<T, U> Iterator for Merge<T, U>
    where
        T: Iterator<Item = HashedEntry>,
        U: Iterator<Item = HashedEntry>,
    {
        type Item = Result<HashedEntry, ()>;

        fn next(&mut self) -> Option<Self::Item> {
            match (self.first_item, self.second_item) {
                (Some(x), Some(y)) => match x.key.cmp(&y.key) {
                    Ordering::Less => {
                        self.first_item = self.first.next();
                        Some(Ok(x))
                    }
                    Ordering::Greater => {
                        self.second_item = self.second.next();
                        Some(Ok(y))
                    }
                    Ordering::Equal => Some(Err(())),
                },

                (Some(x), None) => {
                    self.first_item = self.first.next();
                    Some(Ok(x))
                }

                (None, Some(y)) => {
                    self.second_item = self.second.next();
                    Some(Ok(y))
                }

                (None, None) => None,
            }
        }
    }

    Merge::new(first, second)
}

fn hash_layer(layer: &[HashedEntry]) -> Result<Vec<HashedEntry>, ListProofError> {
    let mut hashed = Vec::with_capacity(layer.len() / 2 + 1);

    for chunk in layer.chunks(2) {
        match *chunk {
            [x, y] => {
                if !x.key.is_left() || y.key.index() != x.key.index() + 1 {
                    return Err(ListProofError::MissingEntry);
                }

                hashed.push(HashedEntry::new(
                    x.key.parent(),
                    pair_hash(&x.hash, &y.hash),
                ));
            }

            [last] => {
                if !last.key.is_left() {
                    return Err(ListProofError::MissingEntry);
                }

                hashed.push(HashedEntry::new(
                    last.key.parent(),
                    hash(last.hash.as_ref()),
                ));
            }

            _ => unreachable!(),
        }
    }

    Ok(hashed)
}

impl<V: StorageValue> ListProof<V> {
    pub(super) fn new<I>(values: I, height: u8) -> Self
    where
        I: IntoIterator<Item = (u64, V)>,
    {
        ListProof {
            values: values.into_iter().collect(),
            height,
            hashes: vec![],
        }
    }

    pub(super) fn push_hash(&mut self, height: u8, index: u64, hash: Hash) -> &mut Self {
        debug_assert!(height > 0);
        debug_assert!(height < self.height);

        let key = ProofListKey::new(height, index);
        debug_assert!(
            if let Some(&HashedEntry { key: last_key, .. }) = self.hashes.last() {
                key > last_key
            } else {
                true
            }
        );

        self.hashes.push(HashedEntry::new(key, hash));
        self
    }

    fn collect(&self) -> Result<Hash, ListProofError> {
        let ordered = self.values
            .windows(2)
            .all(|window| window[0].0 < window[1].0);
        if !ordered {
            return Err(ListProofError::Unordered);
        }

        let ordered = self.hashes
            .windows(2)
            .all(|window| window[0].key < window[1].key);
        if !ordered {
            return Err(ListProofError::Unordered);
        }

        for &HashedEntry { key, .. } in &self.hashes {
            let height = key.height();

            if height == 0 {
                return Err(ListProofError::UnexpectedLeaf);
            }
            if height >= self.height || key.index() >= (1 << (self.height - height)) {
                return Err(ListProofError::UnexpectedBranch);
            }
        }

        let mut layer: Vec<_> = self.values
            .iter()
            .map(|(i, value)| HashedEntry::new(ProofListKey::new(1, *i), value.hash()))
            .collect();

        let mut hashes = self.hashes.clone();
        let mut index_bound = None;

        for height in 1..self.height {
            let split_index = hashes.iter().position(|entry| entry.key.height() > height);
            let remaining_hashes = if let Some(i) = split_index {
                hashes.split_off(i)
            } else {
                vec![]
            };

            if let (Some(last), Some(bound)) = (hashes.last(), index_bound) {
                if last.key.index() > bound {
                    return Err(ListProofError::UnexpectedBranch);
                }
            }

            let merged = merge(layer.into_iter(), hashes.into_iter())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| ListProofError::DuplicateItem)?;

            if index_bound.is_none() && merged.len() % 2 == 1 {
                index_bound = Some(merged.last().unwrap().key.index());
            }
            if let Some(ref mut bound) = index_bound {
                if *bound == 0 {
                    // We can arrive at a single element only at the last layer.
                    return Err(ListProofError::MissingEntry);
                }
                *bound >>= 1;
            }

            layer = hash_layer(&merged)?;
            hashes = remaining_hashes;
        }

        debug_assert_eq!(layer.len(), 1);
        debug_assert_eq!(layer[0].key, ProofListKey::new(self.height, 0));
        Ok(layer[0].hash)
    }
}

/// An error that is returned when the list proof is invalid.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum ListProofError {
    /// The proof is too short and does not correspond to the height of the tree.
    UnexpectedLeaf,
    /// The proof is too long and does not correspond to the height of the tree.
    UnexpectedBranch,
    /// The hash of the proof is not equal to the trusted root hash.
    UnmatchedRootHash,

    /// TODO
    Unordered,
    /// TODO
    DuplicateItem,
    /// TODO
    MissingEntry,
}

impl<V: StorageValue> ListProof<V> {
    /// Verifies the correctness of the proof by the trusted Merkle root hash and the number of
    /// elements in the tree.
    ///
    /// If the proof is valid, a vector with indices and references to elements is returned.
    /// Otherwise, `Err` is returned.
    pub fn validate(&self, merkle_root: Hash) -> Result<&[(u64, V)], ListProofError> {
        let tree_root = self.collect()?;

        if RootNode::node_hash(&tree_root, self.height) != merkle_root {
            return Err(ListProofError::UnmatchedRootHash);
        }
        Ok(&self.values)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::CryptoHash;

    fn entry(height: u8, index: u64) -> HashedEntry {
        HashedEntry::new(ProofListKey::new(height, index), index.hash())
    }

    #[test]
    fn merge_example() {
        let first = vec![entry(1, 0), entry(1, 5), entry(2, 5)].into_iter();
        let second = vec![
            entry(1, 1),
            entry(2, 2),
            entry(2, 3),
            entry(3, 0),
            entry(4, 1),
        ].into_iter();
        let merged = merge(first, second).collect::<Result<Vec<_>, _>>().unwrap();

        assert_eq!(
            merged,
            vec![
                entry(1, 0),
                entry(1, 1),
                entry(1, 5),
                entry(2, 2),
                entry(2, 3),
                entry(2, 5),
                entry(3, 0),
                entry(4, 1),
            ]
        );
    }

    #[test]
    fn hash_layer_example() {
        let layer = vec![
            entry(1, 0),
            entry(1, 1),
            entry(1, 6),
            entry(1, 7),
            entry(1, 8),
        ];
        let hashed = hash_layer(&layer).unwrap();
        assert!(hashed.iter().map(|entry| entry.key,).eq(vec![
            ProofListKey::new(2, 0),
            ProofListKey::new(2, 3),
            ProofListKey::new(2, 4),
        ],));

        assert_eq!(hashed[0].hash, pair_hash(&0u64.hash(), &1u64.hash()));
        assert_eq!(hashed[2].hash, hash(8u64.hash().as_ref()));

        // layer[0] has odd index
        let layer = vec![entry(1, 1), entry(1, 2)];
        assert!(hash_layer(&layer).is_err());

        // layer[1] is not adjacent to layer[0]
        let layer = vec![entry(1, 0), entry(1, 2)];
        assert!(hash_layer(&layer).is_err());
        let layer = vec![entry(1, 0), entry(1, 3)];
        assert!(hash_layer(&layer).is_err());

        // layer[-1] has odd index
        let layer = vec![entry(1, 0), entry(1, 1), entry(1, 7)];
        assert!(hash_layer(&layer).is_err());
    }
}
