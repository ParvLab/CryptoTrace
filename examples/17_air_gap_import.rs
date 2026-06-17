fn main() {
    println!("=== Air-Gapped Update Import ===\n");

    let tmp_dir = std::env::temp_dir().join("cryptotrace_update_demo");
    std::fs::create_dir_all(&tmp_dir).ok();

    let update_content = r#"
- name: "TestSignature"
  offset: 0
  magic: [0xDE, 0xAD, 0xBE, 0xEF]
  category: "test"
  risk_level: "medium"
  description: "Test signature for air-gap demo"
"#;

    let update_path = tmp_dir.join("update.yaml");
    std::fs::write(&update_path, update_content).expect("Failed to write update");

    let sig_path = tmp_dir.join("update.yaml.sig");
    std::fs::write(&sig_path, b"placeholder-signature").ok();

    println!("Update package created at: {:?}", update_path);
    println!("Signature file: {:?}", sig_path);

    let manager = cryptotrace::update::UpdateManager::new(&tmp_dir);
    println!("Current version: {}", manager.current_version());

    match manager.check_for_updates() {
        Ok(available) => println!("Updates available: {}", available),
        Err(e) => println!("Check (expected without network): {}", e),
    }

    match manager.import_local(&update_path, Some(&sig_path)) {
        Ok(_) => println!("Update imported successfully"),
        Err(e) => println!("Import (expected without valid signature): {}", e),
    }

    match manager.apply_verified_update(&update_path, &sig_path) {
        Ok(_) => println!("Update applied successfully"),
        Err(e) => println!("Apply (expected): {}", e),
    }

    std::fs::remove_dir_all(&tmp_dir).ok();
    println!("\nCleanup complete");
}
