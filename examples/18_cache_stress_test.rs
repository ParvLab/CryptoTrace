use cryptotrace::cache::LruCache;
use std::time::Instant;

fn main() {
    println!("=== LRU Cache Stress Test ===\n");

    let capacity = 10_000;
    let mut cache: LruCache<String> = LruCache::new(capacity);
    println!("Capacity: {} entries", capacity);

    let start = Instant::now();
    for i in 0..capacity {
        cache.insert(format!("key_{}", i), format!("value_{}", i));
    }
    let fill_time = start.elapsed();
    println!("Fill {} entries: {:?} ({:.0} inserts/sec)",
        capacity, fill_time, capacity as f64 / fill_time.as_secs_f64());
    println!("Cache size after fill: {}", cache.len());

    let start = Instant::now();
    for _ in 0..100_000 {
        let _ = cache.get(&format!("key_{}", 0));
    }
    println!("100K hot reads: {:?} ({:.0} reads/sec)",
        start.elapsed(), 100_000.0 / start.elapsed().as_secs_f64());

    let start = Instant::now();
    let evict_count = 5_000;
    for i in capacity..capacity + evict_count {
        cache.insert(format!("key_{}", i), format!("new_value_{}", i));
    }
    let evict_time = start.elapsed();
    println!("Evict {} entries: {:?}", evict_count, evict_time);
    println!("Cache size after eviction: {} (capacity: {})", cache.len(), capacity);

    let mut hits = 0;
    for i in 0..100 {
        if cache.get(&format!("key_{}", i)).is_some() {
            hits += 1;
        }
    }
    println!("Hot keys (0-99) surviving eviction: {}/100 ({:.0}%)", hits, hits as f64);

    cache.clear();
    assert!(cache.is_empty());
    println!("Cache cleared: size={}, is_empty={}", cache.len(), cache.is_empty());
}
