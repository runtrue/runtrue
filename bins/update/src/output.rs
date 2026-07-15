pub(crate) fn print_verified(verified: &runtrue_update::VerifiedRelease) {
    println!(
        "{}",
        serde_json::json!({"target_path":verified.target_path,"sha256":verified.target.sha256.to_string(),"length":verified.target.length,"version":verified.target.version,"root_version":verified.next_state.trusted_root.signed.header.version,"targets_version":verified.next_state.targets.as_ref().map(|v|v.version),"snapshot_version":verified.next_state.snapshot.as_ref().map(|v|v.version),"timestamp_version":verified.next_state.timestamp.as_ref().map(|v|v.version)})
    );
}
