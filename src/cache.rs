use std::collections::HashMap;
use std::time::Instant;

/// Simple LRU cache keyed by SHA256 hash.
/// Used for input deduplication and AI narrative caching.
pub struct LruCache<V> {
    max_entries: usize,
    entries: HashMap<String, CacheEntry<V>>,
}

struct CacheEntry<V> {
    value: V,
    last_access: Instant,
}

impl<V> LruCache<V> {
    pub fn new(max_entries: usize) -> Self {
        Self {
            max_entries,
            entries: HashMap::with_capacity(max_entries),
        }
    }

    pub fn get(&mut self, key: &str) -> Option<&V> {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.last_access = Instant::now();
            Some(&entry.value)
        } else {
            None
        }
    }

    pub fn insert(&mut self, key: String, value: V) {
        if self.entries.len() >= self.max_entries {
            // Evict least recently used
            if let Some(evict_key) = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.last_access)
                .map(|(k, _)| k.clone())
            {
                self.entries.remove(&evict_key);
            }
        }
        self.entries.insert(key, CacheEntry {
            value,
            last_access: Instant::now(),
        });
    }

    pub fn contains(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn capacity(&self) -> usize {
        self.max_entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_basic() {
        let mut cache: LruCache<String> = LruCache::new(10);
        cache.insert("key1".to_string(), "value1".to_string());
        assert_eq!(cache.get("key1"), Some(&"value1".to_string()));
        assert!(cache.get("key2").is_none());
    }

    #[test]
    fn test_cache_eviction() {
        let mut cache: LruCache<i32> = LruCache::new(2);
        cache.insert("a".to_string(), 1);
        cache.insert("b".to_string(), 2);
        cache.insert("c".to_string(), 3); // evicts 'a'
        assert!(cache.get("a").is_none());
        assert_eq!(cache.get("b"), Some(&2));
        assert_eq!(cache.get("c"), Some(&3));
    }

    #[test]
    fn test_cache_clear() {
        let mut cache: LruCache<i32> = LruCache::new(10);
        cache.insert("a".to_string(), 1);
        cache.clear();
        assert_eq!(cache.len(), 0);
    }
}
