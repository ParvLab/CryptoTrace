fn main() {
    println!("=== Community Provider Round-Robin ===\n");

    let registry = cryptotrace::providers::community::CommunityRegistry::load_default()
        .expect("Failed to load community registry");
    println!("Loaded {} providers", registry.providers.len());

    let verified = registry.by_trust_level("verified");
    let community = registry.by_trust_level("community");
    let experimental = registry.by_trust_level("experimental");

    println!("  Verified: {}", verified.len());
    println!("  Community: {}", community.len());
    println!("  Experimental: {}", experimental.len());

    if let Some(provider) = registry.get("entropy-shannon") {
        println!("\nProvider details:");
        println!("  Name: {}", provider.name);
        println!("  Description: {}", provider.description);
        println!("  Trust: {}", provider.trust_level);
        println!("  Version: {}", provider.version);
        println!("  Categories: {:?}", provider.categories);
    }

    println!("\n--- Encoding Providers ---");
    for provider in registry.by_categories(&["encoding"]).into_iter().take(5) {
        println!("  Provider: {} (trust: {})", provider.name, provider.trust_level);
    }
}
