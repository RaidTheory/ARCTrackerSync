//! Builds an egui font stack from Windows system fonts so every locale renders
//! without bundling multi-megabyte font files.
//!
//! egui needs the actual glyph data, so for CJK locales we load the matching
//! Windows UI font (Malgun Gothic / Microsoft YaHei / Microsoft JhengHei / Yu
//! Gothic) and chain it behind Segoe UI (Latin + Cyrillic + Hebrew coverage).
//! The chain is rebuilt whenever the active language changes.

use std::sync::Arc;

use eframe::egui::{self, FontData, FontDefinitions, FontFamily};

struct FontCandidate {
    /// Unique egui font name.
    key: &'static str,
    /// File names under the Windows fonts directory, in priority order.
    files: &'static [&'static str],
}

const SEGOE_UI: FontCandidate = FontCandidate {
    key: "segoe-ui",
    files: &["segoeui.ttf"],
};

/// Locale-specific CJK fallback fonts, in the order egui should consult them.
fn locale_fallbacks(locale: &str) -> &'static [FontCandidate] {
    match locale {
        "ko" => &[FontCandidate {
            key: "malgun-gothic",
            files: &["malgun.ttf"],
        }],
        "zh-CN" => &[FontCandidate {
            key: "microsoft-yahei",
            files: &["msyh.ttc", "msyh.ttf"],
        }],
        "zh-TW" => &[FontCandidate {
            key: "microsoft-jhenghei",
            files: &["msjh.ttc", "msjh.ttf"],
        }],
        "ja" => &[
            FontCandidate {
                key: "yu-gothic",
                files: &["YuGothR.ttc", "YuGothM.ttc"],
            },
            FontCandidate {
                key: "meiryo",
                files: &["meiryo.ttc"],
            },
        ],
        _ => &[],
    }
}

/// Build a [`FontDefinitions`] that starts with the locale's preferred fonts
/// and falls back through Segoe UI to egui's built-in fonts, so missing system
/// fonts never produce blank text.
pub fn definitions_for_locale(locale: &str) -> FontDefinitions {
    let mut fonts = FontDefinitions::default();
    let mut chain: Vec<String> = Vec::new();

    // Latin / Cyrillic / Hebrew base first so western text stays crisp.
    register_candidate(&mut fonts, &SEGOE_UI, &mut chain);

    for candidate in locale_fallbacks(locale) {
        register_candidate(&mut fonts, candidate, &mut chain);
    }

    if !chain.is_empty() {
        for family in [FontFamily::Proportional, FontFamily::Monospace] {
            let entry = fonts.families.entry(family).or_default();
            // Put the system fonts ahead of egui's bundled defaults.
            for name in chain.iter().rev() {
                entry.insert(0, name.clone());
            }
        }
    }

    fonts
}

fn register_candidate(
    fonts: &mut FontDefinitions,
    candidate: &FontCandidate,
    chain: &mut Vec<String>,
) {
    if fonts.font_data.contains_key(candidate.key) {
        chain.push(candidate.key.to_string());
        return;
    }

    for file in candidate.files {
        if let Some(bytes) = read_system_font(file) {
            fonts.font_data.insert(
                candidate.key.to_string(),
                Arc::new(FontData::from_owned(bytes)),
            );
            chain.push(candidate.key.to_string());
            return;
        }
    }
}

#[cfg(windows)]
fn read_system_font(file_name: &str) -> Option<Vec<u8>> {
    let fonts_dir = windows_fonts_dir()?;
    let path = fonts_dir.join(file_name);
    std::fs::read(path).ok()
}

#[cfg(not(windows))]
fn read_system_font(_file_name: &str) -> Option<Vec<u8>> {
    None
}

#[cfg(windows)]
fn windows_fonts_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("SystemRoot")
        .map(std::path::PathBuf::from)
        .map(|root| root.join("Fonts"))
}

pub fn apply_locale(ctx: &egui::Context, locale: &str) {
    ctx.set_fonts(definitions_for_locale(locale));
}
