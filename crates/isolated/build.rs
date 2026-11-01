// Embeds the icon, version info, and application manifest on Windows. The
// .rc file is generated with the version filled in, because rc.exe and
// windres disagree on how quoted macro values are passed.
fn main() {
    println!("cargo:rerun-if-changed=../../assets/isolated.rc.in");
    println!("cargo:rerun-if-changed=../../assets/isolated.manifest");
    println!("cargo:rerun-if-changed=../../assets/isolated.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    let mut parts: Vec<String> = version.split(['.', '-', '+']).take(3).map(String::from).collect();
    parts.resize(3, "0".into());
    let comma = format!("{},{},{},0", parts[0], parts[1], parts[2]);
    let assets = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("..")
        .join("..")
        .join("assets")
        .canonicalize()
        .unwrap();
    // rc.exe and windres both accept forward slashes; avoid \\?\ prefixes.
    let dir = assets.to_string_lossy().replace("\\\\?\\", "").replace('\\', "/");
    let template = std::fs::read_to_string(assets.join("isolated.rc.in")).unwrap();
    let rc = template
        .replace("@ASSETS@", &dir)
        .replace("@VERSION_COMMA@", &comma)
        .replace("@VERSION@", &version);
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("isolated.rc");
    std::fs::write(&out, rc).unwrap();
    embed_resource::compile(&out, embed_resource::NONE)
        .manifest_optional()
        .unwrap();
}
