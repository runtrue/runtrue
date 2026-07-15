use std::{env, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os().skip(1).map(PathBuf::from);
    let source = args.next().ok_or("missing input WAT path")?;
    let output = args.next().ok_or("missing output Wasm path")?;
    if args.next().is_some() {
        return Err("expected exactly an input and output path".into());
    }

    let component = wat::parse_file(&source)?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output, component)?;
    println!("built {}", output.display());
    Ok(())
}
