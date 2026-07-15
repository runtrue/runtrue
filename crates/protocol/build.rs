use std::{env, error::Error, path::PathBuf};

fn main() -> Result<(), Box<dyn Error>> {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let proto_root = manifest_dir.join("../../proto");
    let proto = proto_root.join("runner/v1/runner.proto");
    let proto_v2 = proto_root.join("runner/v2/object_transfer.proto");
    let output_dir = PathBuf::from(env::var("OUT_DIR")?);
    let descriptor_v1 = output_dir.join("runtrue.runner.v1.bin");
    let descriptor_v2 = output_dir.join("runtrue.runner.v2.bin");
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let protoc_include = protoc_bin_vendored::include_path()?;

    env::set_var("PROTOC", protoc);
    println!("cargo:rerun-if-changed={}", proto.display());
    println!("cargo:rerun-if-changed={}", proto_v2.display());

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .btree_map(".runtrue.runner.v1.RunnerInventory.labels")
        .type_attribute(
            ".runtrue.runner.v1.RunnerMessage.body",
            "#[allow(clippy::large_enum_variant)]",
        )
        .boxed(".runtrue.runner.v1.ControlMessage.body.lease_offer")
        .file_descriptor_set_path(descriptor_v1)
        .compile_protos(&[proto], &[proto_root.clone(), protoc_include.clone()])?;

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .file_descriptor_set_path(descriptor_v2)
        .compile_protos(&[proto_v2], &[proto_root, protoc_include])?;

    Ok(())
}
