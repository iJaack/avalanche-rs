use std::io::Result;

fn main() -> Result<()> {
    prost_build::Config::new()
        .bytes(&["."])
        .compile_protos(&["proto/p2p/p2p.proto"], &["proto/"])?;
    Ok(())
}
