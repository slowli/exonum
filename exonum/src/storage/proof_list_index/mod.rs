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

//! An implementation of a Merkelized version of an array list (Merkle tree).

pub use self::proof::{ListProof, ListProofError};

use byteorder::{BigEndian, ByteOrder};

use std::{borrow::Cow, cell::Cell, marker::PhantomData};

use self::key::ProofListKey;
use super::{
    base_index::{BaseIndex, BaseIndexIter}, indexes_metadata::IndexType, Fork, Snapshot,
    StorageKey, StorageValue,
};
use crypto::{hash, CryptoHash, Hash, HashStream, HASH_SIZE};

mod key;
mod proof;
#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Copy)]
struct RootNode {
    hash: Hash,
    length: u64,
}

impl RootNode {
    fn to_array(&self) -> [u8; HASH_SIZE + 8] {
        let mut array = [0; HASH_SIZE + 8];
        array[0..HASH_SIZE].copy_from_slice(self.hash.as_ref());
        BigEndian::write_u64(&mut array[HASH_SIZE..], self.length);
        array
    }

    fn height(&self) -> u8 {
        self.length.next_power_of_two().trailing_zeros() as u8 + 1
    }

    fn node_hash(merkle_root: &Hash, height: u8) -> Hash {
        HashStream::new()
            .update(merkle_root.as_ref())
            .update(&[height])
            .hash()
    }

    fn update_hash(&mut self, merkle_root: &Hash) {
        self.hash = Self::node_hash(merkle_root, self.height())
    }
}

impl Default for RootNode {
    fn default() -> Self {
        RootNode {
            hash: hash(&[0; HASH_SIZE + 1]),
            length: 0,
        }
    }
}

impl CryptoHash for RootNode {
    fn hash(&self) -> Hash {
        self.hash
    }
}

impl StorageValue for RootNode {
    fn into_bytes(self) -> Vec<u8> {
        self.to_array().to_vec()
    }

    fn from_bytes(value: Cow<[u8]>) -> Self {
        let buf = value.as_ref();

        let hash = Hash::from_slice(&buf[0..HASH_SIZE]).unwrap();
        let length = BigEndian::read_u64(&buf[HASH_SIZE..]);

        RootNode { hash, length }
    }
}

// TODO: Implement pop and truncate methods for Merkle tree. (ECR-173)

/// A Merkelized version of an array list that provides proofs of existence for the list items.
///
/// `ProofListIndex` implements a Merkle tree, storing elements as leaves and using `u64` as
/// an index. `ProofListIndex` requires that elements implement the [`StorageValue`] trait.
///
/// [`StorageValue`]: ../trait.StorageValue.html
#[derive(Debug)]
pub struct ProofListIndex<T, V> {
    base: BaseIndex<T>,
    root_node: Cell<Option<RootNode>>,
    _v: PhantomData<V>,
}

/// An iterator over the items of a `ProofListIndex`.
///
/// This struct is created by the [`iter`] or
/// [`iter_from`] method on [`ProofListIndex`]. See its documentation for details.
///
/// [`iter`]: struct.ProofListIndex.html#method.iter
/// [`iter_from`]: struct.ProofListIndex.html#method.iter_from
/// [`ProofListIndex`]: struct.ProofListIndex.html
#[derive(Debug)]
pub struct ProofListIndexIter<'a, V> {
    base_iter: BaseIndexIter<'a, ProofListKey, V>,
}

fn pair_hash(h1: &Hash, h2: &Hash) -> Hash {
    HashStream::new()
        .update(h1.as_ref())
        .update(h2.as_ref())
        .hash()
}


/// Hash of an empty index.
pub fn empty_hash() -> Hash {
    RootNode::node_hash(&Hash::zero(), 0)
}

impl<T, V> ProofListIndex<T, V>
where
    T: AsRef<dyn Snapshot>,
    V: StorageValue,
{
    /// Creates a new index representation based on the name and storage view.
    ///
    /// Storage view can be specified as [`&Snapshot`] or [`&mut Fork`]. In the first case, only
    /// immutable methods are available. In the second case, both immutable and mutable methods are
    /// available.
    ///
    /// [`&Snapshot`]: ../trait.Snapshot.html
    /// [`&mut Fork`]: ../struct.Fork.html
    ///
    /// # Examples
    ///
    /// ```
    /// use exonum::storage::{MemoryDB, Database, ProofListIndex};
    ///
    /// let db = MemoryDB::new();
    /// let name = "name";
    ///
    /// let snapshot = db.snapshot();
    /// let index: ProofListIndex<_, u8> = ProofListIndex::new(name, &snapshot);
    ///
    /// let mut fork = db.fork();
    /// let mut mut_index: ProofListIndex<_, u8> = ProofListIndex::new(name, &mut fork);
    /// ```
    pub fn new<S: AsRef<str>>(index_name: S, view: T) -> Self {
        ProofListIndex {
            base: BaseIndex::new(index_name, IndexType::ProofList, view),
            root_node: Cell::new(None),
            _v: PhantomData,
        }
    }

    /// Creates a new index representation based on the name, common prefix of its keys
    /// and storage view.
    ///
    /// Storage view can be specified as [`&Snapshot`] or [`&mut Fork`]. In the first case, only
    /// immutable methods are available. In the second case, both immutable and mutable methods are
    /// available.
    ///
    /// [`&Snapshot`]: ../trait.Snapshot.html
    /// [`&mut Fork`]: ../struct.Fork.html
    ///
    /// # Examples
    ///
    /// ```
    /// use exonum::storage::{MemoryDB, Database, ProofListIndex};
    ///
    /// let db = MemoryDB::new();
    /// let name = "name";
    /// let index_id = vec![01];
    ///
    /// let snapshot = db.snapshot();
    /// let index: ProofListIndex<_, u8> =
    ///                             ProofListIndex::new_in_family(name, &index_id, &snapshot);
    ///
    /// let mut fork = db.fork();
    /// let mut mut_index : ProofListIndex<_, u8> =
    ///                                 ProofListIndex::new_in_family(name, &index_id, &mut fork);
    /// ```
    pub fn new_in_family<S: AsRef<str>, I: StorageKey>(
        family_name: S,
        index_id: &I,
        view: T,
    ) -> Self {
        ProofListIndex {
            base: BaseIndex::new_in_family(family_name, index_id, IndexType::ProofList, view),
            root_node: Cell::new(None),
            _v: PhantomData,
        }
    }

    fn has_branch(&self, key: ProofListKey) -> bool {
        debug_assert!(key.height() > 0);
        key.first_left_leaf_index() < self.len()
    }

    fn get_branch(&self, key: ProofListKey) -> Option<Hash> {
        if self.has_branch(key) {
            self.base.get(&key)
        } else {
            None
        }
    }

    fn get_branch_unchecked(&self, key: ProofListKey) -> Hash {
        debug_assert!(self.has_branch(key));
        self.base.get(&key).unwrap()
    }

    fn construct_proof(&self, from: u64, to: u64) -> ListProof<V> {
        let items = (from..to)
            .into_iter()
            .zip(self.iter_from(from).take((to - from) as usize));
        let mut proof = ListProof::new(items, self.height());

        let (mut left, mut right) = (from, to - 1);
        for height in 1..self.height() {
            if left % 2 == 1 {
                let hash = self.get_branch_unchecked(ProofListKey::new(height, left - 1));
                proof.push_hash(height, left - 1, hash);
            }

            if right % 2 == 0 {
                if let Some(hash) = self.get_branch(ProofListKey::new(height, right + 1)) {
                    proof.push_hash(height, right + 1, hash);
                }
            }

            left >>= 1;
            right >>= 1;
        }

        proof
    }

    /// Returns the element at the indicated position or `None` if the indicated position
    /// is out of bounds.
    ///
    /// # Examples
    ///
    /// ```
    /// use exonum::storage::{MemoryDB, Database, ProofListIndex};
    ///
    /// let db = MemoryDB::new();
    /// let name = "name";
    /// let mut fork = db.fork();
    /// let mut index = ProofListIndex::new(name, &mut fork);
    /// assert_eq!(None, index.get(0));
    ///
    /// index.push(10);
    /// assert_eq!(Some(10), index.get(0));
    /// ```
    pub fn get(&self, index: u64) -> Option<V> {
        self.base.get(&ProofListKey::leaf(index))
    }

    /// Returns the last element of the proof list or `None` if it is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use exonum::storage::{MemoryDB, Database, ProofListIndex};
    ///
    /// let db = MemoryDB::new();
    /// let name = "name";
    /// let mut fork = db.fork();
    /// let mut index = ProofListIndex::new(name, &mut fork);
    /// assert_eq!(None, index.last());
    ///
    /// index.push(1);
    /// assert_eq!(Some(1), index.last());
    /// ```
    pub fn last(&self) -> Option<V> {
        match self.len() {
            0 => None,
            l => self.get(l - 1),
        }
    }

    /// Returns `true` if the proof list contains no elements.
    ///
    /// # Examples
    ///
    /// ```
    /// use exonum::storage::{MemoryDB, Database, ProofListIndex};
    ///
    /// let db = MemoryDB::new();
    /// let name = "name";
    /// let mut fork = db.fork();
    /// let mut index = ProofListIndex::new(name, &mut fork);
    /// assert!(index.is_empty());
    ///
    /// index.push(10);
    /// assert!(!index.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn root_node(&self) -> RootNode {
        if self.root_node.get().is_none() {
            let root_node = self.base.get(&()).unwrap_or_default();
            self.root_node.set(Some(root_node));
        }

        self.root_node.get().unwrap()
    }

    /// Returns the number of elements in the proof list.
    ///
    /// # Examples
    ///
    /// ```
    /// use exonum::storage::{MemoryDB, Database, ProofListIndex};
    ///
    /// let db = MemoryDB::new();
    /// let name = "name";
    /// let mut fork = db.fork();
    /// let mut index = ProofListIndex::new(name, &mut fork);
    /// assert_eq!(0, index.len());
    ///
    /// index.push(1);
    /// assert_eq!(1, index.len());
    /// ```
    pub fn len(&self) -> u64 {
        self.root_node().length
    }

    /// Returns the height of the proof list.
    ///
    /// # Examples
    ///
    /// ```
    /// use exonum::storage::{MemoryDB, Database, ProofListIndex};
    ///
    /// let db = MemoryDB::new();
    /// let name = "name";
    /// let mut fork = db.fork();
    /// let mut index = ProofListIndex::new(name, &mut fork);
    /// assert_eq!(1, index.height());
    ///
    /// index.push(1);
    /// assert_eq!(1, index.len());
    ///
    /// index.push(1);
    /// assert_eq!(2, index.len());
    /// ```
    pub fn height(&self) -> u8 {
        self.len().next_power_of_two().trailing_zeros() as u8 + 1
    }

    /// Returns the Merkle root hash of the proof list or the default hash value
    /// if it is empty. The default hash consists solely of zeroes.
    ///
    /// # Examples
    ///
    /// ```
    /// use exonum::storage::{MemoryDB, Database, ProofListIndex};
    /// use exonum::crypto::Hash;
    ///
    /// let db = MemoryDB::new();
    /// let name = "name";
    /// let mut fork = db.fork();
    /// let mut index = ProofListIndex::new(name, &mut fork);
    ///
    /// let default_hash = index.merkle_root();
    /// assert_eq!(Hash::default(), default_hash);
    ///
    /// index.push(1);
    /// let hash = index.merkle_root();
    /// assert_ne!(hash, default_hash);
    /// ```
    pub fn merkle_root(&self) -> Hash {
        self.root_node().hash
    }

    /// Returns the proof of existence for the list element at the specified position.
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of bounds.
    ///
    /// # Examples
    ///
    /// ```
    /// use exonum::storage::{MemoryDB, Database, ProofListIndex};
    ///
    /// let db = MemoryDB::new();
    /// let name = "name";
    /// let mut fork = db.fork();
    /// let mut index = ProofListIndex::new(name, &mut fork);
    ///
    /// index.push(1);
    ///
    /// let proof = index.get_proof(0);
    /// ```
    pub fn get_proof(&self, index: u64) -> ListProof<V> {
        if index >= self.len() {
            panic!(
                "Index out of bounds: the len is {} but the index is {}",
                self.len(),
                index
            );
        }
        self.construct_proof(index, index + 1)
    }

    /// Returns the proof of existence for the list elements in the specified range.
    ///
    /// # Panics
    ///
    /// Panics if the range is out of bounds.
    ///
    /// # Examples
    ///
    /// ```
    /// use exonum::storage::{MemoryDB, Database, ProofListIndex};
    ///
    /// let db = MemoryDB::new();
    /// let name = "name";
    /// let mut fork = db.fork();
    /// let mut index = ProofListIndex::new(name, &mut fork);
    ///
    /// index.extend([1, 2, 3, 4, 5].iter().cloned());
    ///
    /// let list_proof = index.get_range_proof(1, 3);
    /// ```
    pub fn get_range_proof(&self, from: u64, to: u64) -> ListProof<V> {
        if to > self.len() {
            panic!(
                "Illegal range boundaries: the len is {:?}, but the range end is {:?}",
                self.len(),
                to
            )
        }
        if to <= from {
            panic!(
                "Illegal range boundaries: the range start is {:?}, but the range end is {:?}",
                from, to
            )
        }

        self.construct_proof(from, to)
    }

    /// Returns an iterator over the list. The iterator element type is V.
    ///
    /// # Examples
    ///
    /// ```
    /// use exonum::storage::{MemoryDB, Database, ProofListIndex};
    ///
    /// let db = MemoryDB::new();
    /// let name = "name";
    /// let snapshot = db.snapshot();
    /// let index: ProofListIndex<_, u8> = ProofListIndex::new(name, &snapshot);
    ///
    /// for val in index.iter() {
    ///     println!("{}", val);
    /// }
    /// ```
    pub fn iter(&self) -> ProofListIndexIter<V> {
        ProofListIndexIter {
            base_iter: self.base.iter(&0u8),
        }
    }

    /// Returns an iterator over the list starting from the specified position. The iterator
    /// element type is V.
    ///
    /// # Examples
    ///
    /// ```
    /// use exonum::storage::{MemoryDB, Database, ProofListIndex};
    ///
    /// let db = MemoryDB::new();
    /// let name = "name";
    /// let snapshot = db.snapshot();
    /// let index: ProofListIndex<_, u8> = ProofListIndex::new(name, &snapshot);
    ///
    /// for val in index.iter_from(1) {
    ///     println!("{}", val);
    /// }
    /// ```
    pub fn iter_from(&self, from: u64) -> ProofListIndexIter<V> {
        ProofListIndexIter {
            base_iter: self.base.iter_from(&0u8, &ProofListKey::leaf(from)),
        }
    }
}

impl<'a, V> ProofListIndex<&'a mut Fork, V>
where
    V: StorageValue,
{
    fn set_root_node(&mut self, root_node: RootNode) {
        self.base.put(&(), root_node);
        self.root_node.set(Some(root_node));
    }

    fn set_branch(&mut self, key: ProofListKey, hash: Hash) {
        debug_assert!(key.height() > 0);

        self.base.put(&key, hash)
    }

    /// Appends an element to the back of the proof list.
    ///
    /// # Examples
    ///
    /// ```
    /// use exonum::storage::{MemoryDB, Database, ProofListIndex};
    ///
    /// let db = MemoryDB::new();
    /// let name = "name";
    /// let mut fork = db.fork();
    /// let mut index = ProofListIndex::new(name, &mut fork);
    ///
    /// index.push(1);
    /// assert!(!index.is_empty());
    /// ```
    pub fn push(&mut self, value: V) {
        let mut root_node = self.root_node();
        let len = root_node.length;
        root_node.length += 1;
        self.set_root_node(root_node);

        let mut key = ProofListKey::new(1, len);
        let mut node_hash = value.hash();
        self.base.put(&key, node_hash);
        self.base.put(&ProofListKey::leaf(len), value);

        let height = self.height();
        while key.height() < height {
            node_hash = if key.is_left() {
                hash(self.get_branch_unchecked(key).as_ref())
            } else {
                pair_hash(
                    &self.get_branch_unchecked(key.as_left()),
                    &self.get_branch_unchecked(key),
                )
            };

            key = key.parent();
            self.set_branch(key, node_hash);
        }

        root_node.update_hash(&node_hash);
        self.set_root_node(root_node);
    }

    /// Extends the proof list with the contents of an iterator.
    ///
    /// # Examples
    ///
    /// ```
    /// use exonum::storage::{MemoryDB, Database, ProofListIndex};
    ///
    /// let db = MemoryDB::new();
    /// let name = "name";
    /// let mut fork = db.fork();
    /// let mut index = ProofListIndex::new(name, &mut fork);
    ///
    /// index.extend([1, 2, 3].iter().cloned());
    /// assert_eq!(3, index.len());
    /// ```
    pub fn extend<I>(&mut self, iter: I)
    where
        I: IntoIterator<Item = V>,
    {
        for value in iter {
            self.push(value)
        }
    }

    /// Changes a value at the specified position.
    ///
    /// # Panics
    ///
    /// Panics if `index` is equal or greater than the current length of the proof list.
    ///
    /// # Examples
    ///
    /// ```
    /// use exonum::storage::{MemoryDB, Database, ProofListIndex};
    ///
    /// let db = MemoryDB::new();
    /// let name = "name";
    /// let mut fork = db.fork();
    /// let mut index = ProofListIndex::new(name, &mut fork);
    ///
    /// index.push(1);
    /// assert_eq!(Some(1), index.get(0));
    ///
    /// index.set(0, 100);
    /// assert_eq!(Some(100), index.get(0));
    /// ```
    pub fn set(&mut self, index: u64, value: V) {
        if index >= self.len() {
            panic!(
                "Index out of bounds: the len is {} but the index is {}",
                self.len(),
                index
            );
        }

        let mut key = ProofListKey::new(1, index);
        let mut node_hash = value.hash();
        self.base.put(&key, node_hash);
        self.base.put(&ProofListKey::leaf(index), value);

        while key.height() < self.height() {
            let (left, right) = (key.as_left(), key.as_right());
            node_hash = if self.has_branch(right) {
                pair_hash(
                    &self.get_branch_unchecked(left),
                    &self.get_branch_unchecked(right),
                )
            } else {
                hash(self.get_branch_unchecked(left).as_ref())
            };
            key = key.parent();
            self.set_branch(key, node_hash);
        }

        let mut root_node = self.root_node();
        root_node.update_hash(&node_hash);
        self.set_root_node(root_node);
    }

    /// Clears the proof list, removing all values.
    ///
    /// # Notes
    ///
    /// Currently, this method is not optimized to delete a large set of data. During the execution of
    /// this method, the amount of allocated memory is linearly dependent on the number of elements
    /// in the index.
    ///
    /// # Examples
    ///
    /// ```
    /// use exonum::storage::{MemoryDB, Database, ProofListIndex};
    ///
    /// let db = MemoryDB::new();
    /// let name = "name";
    /// let mut fork = db.fork();
    /// let mut index = ProofListIndex::new(name, &mut fork);
    ///
    /// index.push(1);
    /// assert!(!index.is_empty());
    ///
    /// index.clear();
    /// assert!(index.is_empty());
    /// ```
    pub fn clear(&mut self) {
        self.root_node.set(Some(RootNode::default()));
        self.base.clear()
    }
}

impl<'a, T, V> ::std::iter::IntoIterator for &'a ProofListIndex<T, V>
where
    T: AsRef<dyn Snapshot>,
    V: StorageValue,
{
    type Item = V;
    type IntoIter = ProofListIndexIter<'a, V>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, V> Iterator for ProofListIndexIter<'a, V>
where
    V: StorageValue,
{
    type Item = V;

    fn next(&mut self) -> Option<Self::Item> {
        self.base_iter.next().map(|(_, v)| v)
    }
}
