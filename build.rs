use std::{fs::File, io::Write, path::PathBuf};

use ico::{IconDir, IconDirEntry, IconImage};

#[cfg(windows)]
fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let icon_path = PathBuf::from(out_dir).join("swatcrypt_icon.ico");
    write_icon(&icon_path).expect("failed to write icon");

    let mut res = winres::WindowsResource::new();
    res.set_icon(icon_path.to_str().expect("icon path"));
    res.compile().expect("failed to embed icon");
}

#[cfg(not(windows))]
fn main() {}

fn write_icon(path: &std::path::Path) -> std::io::Result<()> {
    let (w, h): (u32, u32) = (64, 64);
    let mut rgba = vec![0u8; (w * h * 4) as usize];

    let mut put_rect = |x0: u32, y0: u32, x1: u32, y1: u32, r: u8, g: u8, b: u8, a: u8| {
        for y in y0..y1 {
            for x in x0..x1 {
                let idx = ((y * w + x) * 4) as usize;
                rgba[idx] = r;
                rgba[idx + 1] = g;
                rgba[idx + 2] = b;
                rgba[idx + 3] = a;
            }
        }
    };

    // Body of lock
    put_rect(18, 28, 46, 52, 200, 16, 16, 255);
    // Shackle
    put_rect(22, 16, 42, 28, 220, 40, 40, 255);
    put_rect(26, 12, 38, 16, 220, 40, 40, 255);
    // Keyhole
    put_rect(30, 36, 34, 44, 0, 0, 0, 255);
    put_rect(30, 44, 34, 48, 0, 0, 0, 180);

    let image = IconImage::from_rgba_data(w, h, rgba);
    let entry = IconDirEntry::encode(&image).expect("encode icon entry");
    let mut dir = IconDir::new(ico::ResourceType::Icon);
    dir.add_entry(entry);

    let mut file = File::create(path)?;
    dir.write(&mut file)?;
    file.flush()
}
