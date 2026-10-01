//! Build-time setup:
//! - Embeds a Windows application manifest that forces ARCTracker Sync to run
//!   elevated. Raw-socket capture (`SIO_RCVALL`) requires Administrator, so the
//!   app requests it up front: Windows shows the UAC prompt before the process
//!   starts and the app always runs with the rights it needs.
//! - Bakes the ARC chevron mark (`assets/arc-mark.png`) into raw RGBA at the
//!   window (256²) and tray (32²) sizes, so the runtime needs no image decoder.
//! - Encodes the same mark into a multi-size `.ico` and embeds it as the
//!   executable's Win32 icon resource, which is what Explorer and the taskbar
//!   show for the `.exe` (separate from the runtime egui window icon).

use std::path::{Path, PathBuf};
use std::{env, fs};

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let square = squared_mark();
    bake_rgba_icons(&square, &out_dir);

    #[cfg(windows)]
    {
        use embed_manifest::manifest::ExecutionLevel;
        use embed_manifest::{embed_manifest, new_manifest};

        embed_manifest(
            new_manifest("ARCTracker.Sync")
                .requested_execution_level(ExecutionLevel::RequireAdministrator),
        )
        .expect("failed to embed the Windows application manifest");

        embed_exe_icon(&square, &out_dir);
    }

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/arc-mark.png");
    // `rust_i18n::i18n!("locales")` embeds the catalogs at compile time but does
    // not tell cargo, so a locale-only edit would otherwise ship stale strings.
    // Rerunning this script on a catalog change rebuilds the crate with them.
    println!("cargo:rerun-if-changed=locales");
}

/// Decode `assets/arc-mark.png` and pad it onto a transparent square (aspect
/// preserved, centered). Shared by the RGBA bakes and the `.ico` so every icon
/// surface shows the identical mark.
fn squared_mark() -> image::RgbaImage {
    let source = image::open("assets/arc-mark.png")
        .expect("failed to open assets/arc-mark.png")
        .into_rgba8();

    let (width, height) = source.dimensions();
    let side = width.max(height);
    let mut square = image::RgbaImage::from_pixel(side, side, image::Rgba([0, 0, 0, 0]));
    let x = ((side - width) / 2) as i64;
    let y = ((side - height) / 2) as i64;
    image::imageops::overlay(&mut square, &source, x, y);
    square
}

/// Emit Lanczos3-downscaled raw RGBA for the window (256²) and tray (32²) icons.
fn bake_rgba_icons(square: &image::RgbaImage, out_dir: &Path) {
    use image::imageops::FilterType;

    for size in [256u32, 32u32] {
        let resized = image::imageops::resize(square, size, size, FilterType::Lanczos3);
        let path = out_dir.join(format!("icon_{size}.rgba"));
        fs::write(&path, resized.into_raw())
            .unwrap_or_else(|error| panic!("writing {}: {error}", path.display()));
    }
}

/// Encode `square` into a multi-size `.ico` and link it as the PE icon resource.
#[cfg(windows)]
fn embed_exe_icon(square: &image::RgbaImage, out_dir: &Path) {
    use image::codecs::ico::{IcoEncoder, IcoFrame};
    use image::imageops::FilterType;
    use image::ExtendedColorType;

    // Standard Windows shell icon sizes; the shell picks the best fit per view.
    const SIZES: [u32; 7] = [16, 24, 32, 48, 64, 128, 256];
    let frames: Vec<IcoFrame> = SIZES
        .iter()
        .map(|&size| {
            let resized = image::imageops::resize(square, size, size, FilterType::Lanczos3);
            // ICO frames are PNG-compressed (valid on Vista+), so 256² stays small.
            IcoFrame::as_png(resized.as_raw(), size, size, ExtendedColorType::Rgba8)
                .unwrap_or_else(|error| panic!("encoding {size}² icon frame: {error}"))
        })
        .collect();

    let ico_path = out_dir.join("app.ico");
    let file = fs::File::create(&ico_path)
        .unwrap_or_else(|error| panic!("creating {}: {error}", ico_path.display()));
    IcoEncoder::new(file)
        .encode_images(&frames)
        .expect("encoding the app .ico");

    // Resource id `1` is the lowest, so the shell uses it as *the* app icon.
    // Backslashes in the path must be escaped for the .rc string literal.
    let rc_path = out_dir.join("app.rc");
    let ico_literal = ico_path.display().to_string().replace('\\', "\\\\");
    fs::write(&rc_path, format!("1 ICON \"{ico_literal}\"\n"))
        .unwrap_or_else(|error| panic!("writing {}: {error}", rc_path.display()));

    // Compile + link the icon-only .rc. embed-manifest remains the sole manifest
    // source, so this never produces a duplicate-manifest link error.
    embed_resource::compile(&rc_path, embed_resource::NONE)
        .manifest_optional()
        .expect("embedding the executable icon resource");
}
