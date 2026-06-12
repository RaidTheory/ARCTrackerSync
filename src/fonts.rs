//! Builds an egui font stack from Windows system fonts so every locale renders
//! without bundling multi-megabyte font files.
//!
//! egui needs the actual glyph data, so for CJK locales we load the matching
//! Windows UI font (Malgun Gothic / Microsoft YaHei / Microsoft JhengHei / Yu
//! Gothic) and chain it behind Segoe UI (Latin + Cyrillic + Hebrew coverage).
//! The chain is rebuilt whenever the active language changes.
//!
//! By default only the active locale's CJK font loads, keeping the footprint
//! small. The language picker, though, lists every locale's native name
//! (한국어, 简体中文, 繁體中文, 日本語), which needs all the CJK fonts at once;
//! those tens of megabytes load lazily, only once that dropdown is opened, via
//! [`apply_locale_with_all_cjk`].

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

/// The CJK locales with their own fallback font, in language-picker order.
const CJK_LOCALES: [&str; 4] = ["ko", "zh-CN", "zh-TW", "ja"];

/// The CJK locales to load fonts for. The active locale (if CJK) always comes
/// first so its regional Han glyphs take priority in body text. When
/// `include_all` is set — for the language picker, which lists every locale's
/// native name — the remaining CJK locales follow so those names also render.
fn cjk_load_order(active: &str, include_all: bool) -> Vec<&'static str> {
    let mut order: Vec<&'static str> = Vec::new();
    if let Some(found) = CJK_LOCALES.iter().copied().find(|locale| *locale == active) {
        order.push(found);
    }
    if include_all {
        for locale in CJK_LOCALES {
            if locale != active {
                order.push(locale);
            }
        }
    }
    order
}

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

/// Build a [`FontDefinitions`] for the active locale: Segoe UI plus the
/// locale's own CJK font, falling back to egui's built-in fonts so missing
/// system fonts never produce blank text.
pub fn definitions_for_locale(locale: &str) -> FontDefinitions {
    build_definitions(locale, false)
}

/// Like [`definitions_for_locale`], but also loads every other CJK locale's
/// font so the language picker can render all of the native names. Heavier
/// (tens of MB), so it is applied lazily — only once the picker is opened.
pub fn definitions_for_locale_with_all_cjk(locale: &str) -> FontDefinitions {
    build_definitions(locale, true)
}

fn build_definitions(locale: &str, include_all_cjk: bool) -> FontDefinitions {
    let mut fonts = FontDefinitions::default();
    let mut chain: Vec<String> = Vec::new();

    // Latin / Cyrillic / Hebrew base first so western text stays crisp.
    register_candidate(&mut fonts, &SEGOE_UI, &mut chain);

    // The active locale's CJK font first (for correct regional glyphs in body
    // text); for the picker, the remaining CJK fonts follow so every native
    // name renders. `register_candidate` dedupes.
    for cjk_locale in cjk_load_order(locale, include_all_cjk) {
        for candidate in locale_fallbacks(cjk_locale) {
            register_candidate(&mut fonts, candidate, &mut chain);
        }
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

/// Apply the active locale's fonts plus every CJK fallback, so the language
/// picker renders all native names. Call once the picker is opened.
pub fn apply_locale_with_all_cjk(ctx: &egui::Context, locale: &str) {
    ctx.set_fonts(definitions_for_locale_with_all_cjk(locale));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_load_order_is_active_locale_only() {
        // The lazy default keeps the footprint small: a non-CJK locale loads no
        // CJK font, and a CJK locale loads only its own.
        assert!(cjk_load_order("en", false).is_empty());
        assert_eq!(cjk_load_order("ja", false), ["ja"]);
        assert_eq!(cjk_load_order("zh-CN", false), ["zh-CN"]);
    }

    #[test]
    fn picker_load_order_is_all_cjk_with_active_first() {
        // When the language picker opens it lists 한국어, 简体中文, 繁體中文,
        // and 日本語, so every CJK font must load.
        assert_eq!(cjk_load_order("en", true), ["ko", "zh-CN", "zh-TW", "ja"]);

        // The active CJK locale leads so its regional Han glyphs win in body
        // text; the rest follow so the other native names still render.
        assert_eq!(
            cjk_load_order("zh-TW", true),
            ["zh-TW", "ko", "zh-CN", "ja"]
        );
        assert_eq!(cjk_load_order("ja", true), ["ja", "ko", "zh-CN", "zh-TW"]);

        // Every CJK locale is present exactly once regardless of the active one.
        let mut deduped = cjk_load_order("ko", true);
        deduped.sort_unstable();
        deduped.dedup();
        assert_eq!(deduped, ["ja", "ko", "zh-CN", "zh-TW"]);
    }
}
