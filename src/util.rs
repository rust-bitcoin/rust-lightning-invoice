/// Due to the "no unnecessary dependencies" policy some fundamental algorithms and data structures
/// have to be reimplemented.

use std::borrow::Borrow;
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;
use std::iter::FromIterator;

/// Counts elements from an Iterator. Use `Iterator::collect::<Counter>::()` to do so.
pub struct Counter<T: Hash + Eq + Debug> {
	counter: HashMap<T, usize>,
}

impl<T: Hash + Eq + Debug> Counter<T> {
	pub fn new() -> Counter<T> {
		Counter {
			counter: HashMap::new(),
		}
	}

	pub fn count<Q>(&self, key: &Q) -> usize
	where T: Borrow<Q>,
	      Q: Hash + Eq
	{
		self.counter.get(key).cloned().unwrap_or(0)
	}
}

impl<T: Hash + Eq + Debug> FromIterator<T> for Counter<T> {
	fn from_iter<I: IntoIterator<Item=T>>(iter: I) -> Self {
		let mut counter = HashMap::<T, usize>::new();
		for item in iter {
			let current_count = counter.get(&item).cloned().unwrap_or(0);
			counter.insert(item, current_count + 1);
		}
		Counter {
			counter: counter,
		}
	}
}