//! Localization for ARCTracker Sync.
//!
//! Wraps `rust-i18n` over this app's own per-locale catalogs in
//! `apps/arctracker-sync/locales/<locale>.json` (rust-i18n `_version: 1`, flat
//! `SyncApp.*` keys, `%{var}` placeholders). The web app's `messages/` are
//! unaffected. `en.json` is the source of truth; the other 19 locales are
//! translations. Every user-facing string flows through [`tr!`].
//!
//! The `rust_i18n::i18n!("locales", fallback = "en")` invocation lives in
//! `lib.rs` because `t!` resolves the generated catalog items relative to
//! `crate::`.

/// The 20 ARCTracker UI locales, in language-picker display order (mirrors
/// `UI_LOCALES` in `apps/web/src/config/locales.ts`).
pub const UI_LOCALES: &[&str] = &[
    "en", "de", "fr", "es", "pt", "pt-BR", "pl", "no", "da", "it", "ja", "ko", "zh-CN", "zh-TW",
    "ru", "tr", "uk", "hr", "sr", "he",
];

/// Native display name for each supported locale (mirrors `LOCALE_CONFIG`).
pub fn native_name(locale: &str) -> &'static str {
    match locale {
        "en" => "English",
        "de" => "Deutsch",
        "fr" => "Français",
        "es" => "Español",
        "pt" => "Português",
        "pt-BR" => "Português (Brasil)",
        "pl" => "Polski",
        "no" => "Norsk",
        "da" => "Dansk",
        "it" => "Italiano",
        "ja" => "日本語",
        "ko" => "한국어",
        "zh-CN" => "简体中文",
        "zh-TW" => "繁體中文",
        "ru" => "Русский",
        "tr" => "Türkçe",
        "uk" => "Українська",
        "hr" => "Hrvatski",
        "sr" => "Srpski",
        "he" => "עברית",
        _ => "English",
    }
}

/// Resolve the active locale from (1) a persisted preference, otherwise
/// (2) the Windows UI language mapped to the nearest supported locale,
/// otherwise (3) English. Returns one of [`UI_LOCALES`].
pub fn resolve_locale(preferred: Option<&str>) -> &'static str {
    if let Some(preferred) = preferred {
        if let Some(matched) = match_supported(preferred) {
            return matched;
        }
    }

    if let Some(system) = system_ui_language() {
        if let Some(matched) = match_supported(&system) {
            return matched;
        }
    }

    "en"
}

pub fn set_active_locale(locale: &str) {
    let resolved = match_supported(locale).unwrap_or("en");
    rust_i18n::set_locale(resolved);
}

pub fn active_locale() -> String {
    rust_i18n::locale().to_string()
}

/// Map an arbitrary BCP-47 tag to the nearest supported UI locale: exact
/// match, then the script-qualified Chinese variants, then the bare language
/// subtag (`de-AT` → `de`).
fn match_supported(tag: &str) -> Option<&'static str> {
    let normalized = normalize_tag(tag);

    if let Some(found) = UI_LOCALES
        .iter()
        .copied()
        .find(|locale| normalize_tag(locale) == normalized)
    {
        return Some(found);
    }

    // Chinese needs script disambiguation before falling back to language.
    if normalized.starts_with("zh") {
        if normalized.contains("hant")
            || normalized.contains("tw")
            || normalized.contains("hk")
            || normalized.contains("mo")
        {
            return Some("zh-TW");
        }
        return Some("zh-CN");
    }

    if normalized.starts_with("pt") {
        if normalized.contains("br") {
            return Some("pt-BR");
        }
        return Some("pt");
    }

    let language = normalized.split('-').next().unwrap_or(&normalized);
    UI_LOCALES
        .iter()
        .copied()
        .find(|locale| locale.split('-').next() == Some(language))
}

fn normalize_tag(tag: &str) -> String {
    tag.trim().replace('_', "-").to_ascii_lowercase()
}

/// Translate a `SyncApp.*` key, optionally interpolating named arguments.
///
/// `tr!("SyncApp.action.signIn")` for a plain string, or
/// `tr!("SyncApp.state.synced.body", account => name, time => when)` to fill
/// the `%{account}` / `%{time}` placeholders the build step produced.
#[macro_export]
macro_rules! tr {
    ($key:expr) => {
        $crate::i18n::__translate($key, &[])
    };
    ($key:expr, $($name:ident => $value:expr),+ $(,)?) => {
        $crate::i18n::__translate(
            $key,
            &[$((stringify!($name), ::std::string::ToString::to_string(&$value))),+],
        )
    };
}

/// Backing function for [`tr!`].
#[doc(hidden)]
pub fn __translate(key: &str, args: &[(&str, String)]) -> String {
    let mut text = rust_i18n::t!(key).to_string();
    for (name, value) in args {
        let placeholder = format!("%{{{name}}}");
        text = text.replace(&placeholder, value);
    }
    text
}

#[cfg(windows)]
fn system_ui_language() -> Option<String> {
    use std::os::windows::ffi::OsStringExt;

    const LOCALE_NAME_MAX_LENGTH: usize = 85;
    let mut buffer = [0u16; LOCALE_NAME_MAX_LENGTH];
    let written = unsafe { GetUserDefaultLocaleName(buffer.as_mut_ptr(), buffer.len() as i32) };
    if written <= 1 {
        return None;
    }

    let len = (written as usize).saturating_sub(1).min(buffer.len());
    let value = std::ffi::OsString::from_wide(&buffer[..len]);
    value.into_string().ok().filter(|tag| !tag.is_empty())
}

#[cfg(not(windows))]
fn system_ui_language() -> Option<String> {
    std::env::var("LANG")
        .ok()
        .and_then(|value| value.split('.').next().map(str::to_string))
        .filter(|tag| !tag.is_empty())
}

#[cfg(windows)]
#[link(name = "Kernel32")]
extern "system" {
    fn GetUserDefaultLocaleName(lp_locale_name: *mut u16, cch_locale_name: i32) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_locale_matches() {
        assert_eq!(match_supported("de"), Some("de"));
        assert_eq!(match_supported("pt-BR"), Some("pt-BR"));
        assert_eq!(match_supported("zh-CN"), Some("zh-CN"));
    }

    #[test]
    fn region_variants_fall_back_to_language() {
        assert_eq!(match_supported("de-AT"), Some("de"));
        assert_eq!(match_supported("en-US"), Some("en"));
        assert_eq!(match_supported("fr-CA"), Some("fr"));
    }

    #[test]
    fn chinese_scripts_resolve_to_catalogs() {
        assert_eq!(match_supported("zh-Hant"), Some("zh-TW"));
        assert_eq!(match_supported("zh-Hant-TW"), Some("zh-TW"));
        assert_eq!(match_supported("zh-Hans"), Some("zh-CN"));
        assert_eq!(match_supported("zh"), Some("zh-CN"));
    }

    #[test]
    fn portuguese_variants_split_brazil() {
        assert_eq!(match_supported("pt-PT"), Some("pt"));
        assert_eq!(match_supported("pt-br"), Some("pt-BR"));
    }

    #[test]
    fn unknown_tag_resolves_to_english() {
        assert_eq!(resolve_locale(Some("xx")), "en");
        assert_eq!(resolve_locale(Some("de")), "de");
    }

    #[test]
    fn catalog_resolves_real_text_not_raw_keys() {
        // Regression guard: if the rust-i18n catalog's namespace or format ever
        // drifts from the `SyncApp.*` keys the UI looks up, `t!` returns the key
        // string itself and the whole UI renders raw keys. Assert real English
        // text resolves so that failure is loud here instead of silent in the app.
        rust_i18n::set_locale("en");
        assert_eq!(__translate("SyncApp.appName", &[]), "ARCTracker Sync");
        assert_ne!(
            __translate("SyncApp.state.signedOut.title", &[]),
            "SyncApp.state.signedOut.title"
        );
        // The post-sync Stash CTA key must resolve to real text, not the raw key.
        assert_eq!(
            __translate("SyncApp.action.viewStash", &[]),
            "View your stash"
        );
        // Named placeholder interpolation (%{var}) works end to end.
        assert_eq!(
            __translate(
                "SyncApp.footer.signedInAs",
                &[("account", "Matt".to_string())]
            ),
            "Signed in as Matt"
        );
        // The capture-method settings keys must resolve to real text.
        assert_eq!(
            __translate("SyncApp.settings.captureMethod", &[]),
            "Capture method"
        );
        assert_ne!(
            __translate("SyncApp.state.needsAttention.npcapBody", &[]),
            "SyncApp.state.needsAttention.npcapBody"
        );
    }
}
