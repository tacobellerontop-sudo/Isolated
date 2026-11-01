// Embeds the icon, version info, and application manifest on Windows.
fn main() {
    println!("cargo:rerun-if-changed=../../assets/isolated.rc");
    println!("cargo:rerun-if-changed=../../assets/isolated.manifest");
    println!("cargo:rerun-if-changed=../../assets/isolated.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let version = std::env::var("CARGO_PKG_VERSION").unwrap();
        let mut parts: Vec<String> = version.split(['.', '-']).take(3).map(String::from).collect();
        parts.resize(3, "0".into());
        let comma = format!("{},{},{},0", parts[0], parts[1], parts[2]);
        embed_resource::compile(
            "../../assets/isolated.rc",
            [
                format!("VERSION_COMMA={comma}"),
                format!("VERSION_STR=\\\"{version}\\\""),
            ],
        )
        .manifest_optional()
        .unwrap();
    }
}
