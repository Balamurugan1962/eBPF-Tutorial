use aya_build::cargo_metadata;

fn main() {
    let cargo_metadata::Metadata { packages, .. } =
        cargo_metadata::MetadataCommand::new().no_deps().exec().unwrap();
    let bpf_packages: Vec<_> = packages
        .into_iter()
        .filter(|p| p.name == "dns-allowlist-ebpf")
        .collect();
    aya_build::build_ebpf(bpf_packages).unwrap();
}
