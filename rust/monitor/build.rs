use anyhow::Context as _;
use aya_build::cargo_metadata;


fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;

    println!("cargo:rerun-if-changed=bindgen.h");
    let bindings = bindgen::Builder::default()
        .header("bindgen.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs
    let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap_or("gen".into()));
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    /*let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name == "rust-ebpf")
        .ok_or_else(|| anyhow!("rust-ebpf package not found"))?;*/
    //aya_build::build_ebpf([ebpf_package])
    Ok(())
}
