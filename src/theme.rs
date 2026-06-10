//! ARC design tokens and the egui theme built from them.
//!
//! Add new values to the scales below rather than hardcoding pixel literals
//! in render code.

use eframe::egui::{self, Color32, Stroke, Vec2};

// ----- spacing (4pt rhythm) --------------------------------------------------

pub const SPACE_XS: f32 = 4.0;
pub const SPACE_SM: f32 = 8.0;
pub const SPACE_MD: f32 = 12.0;
pub const SPACE_LG: f32 = 16.0;
pub const SPACE_XL: f32 = 24.0;

// ----- type scale ------------------------------------------------------------

/// Screen and hero titles.
pub const TEXT_TITLE: f32 = 20.0;
/// Modal titles.
pub const TEXT_SUBTITLE: f32 = 18.0;
/// Body copy and standard labels.
pub const TEXT_BODY: f32 = 14.0;
/// Secondary body copy (modal bodies, changelog, session notices).
pub const TEXT_SECONDARY: f32 = 13.0;
/// Captions: pills, progress stages, settings sublabels, footer.
pub const TEXT_CAPTION: f32 = 12.0;

// ----- radii & strokes ---------------------------------------------------------

pub const RADIUS_CARD: u8 = 8;
pub const RADIUS_CONTROL: u8 = 6;

// ----- widths ------------------------------------------------------------------

/// Content column cap: wider windows center this column instead of stretching.
pub const CONTENT_MAX_WIDTH: f32 = 680.0;
/// Shared max width for all modal dialogs.
pub const MODAL_WIDTH: f32 = 480.0;
/// Wide combo boxes (e.g. network adapter names).
pub const COMBO_WIDE: f32 = 360.0;

// ----- pill tinting -------------------------------------------------------------

pub const PILL_FILL_OPACITY: f32 = 0.16;
pub const PILL_STROKE_OPACITY: f32 = 0.55;

// ----- palette -------------------------------------------------------------------

pub fn arc_bg() -> Color32 {
    Color32::from_rgb(18, 24, 31)
}

pub fn arc_card() -> Color32 {
    Color32::from_rgb(26, 33, 42)
}

pub fn arc_input() -> Color32 {
    Color32::from_rgb(22, 29, 37)
}

pub fn arc_muted() -> Color32 {
    Color32::from_rgb(36, 44, 55)
}

pub fn arc_border() -> Color32 {
    Color32::from_rgb(52, 61, 74)
}

pub fn arc_foreground() -> Color32 {
    Color32::from_rgb(237, 240, 244)
}

pub fn arc_muted_text() -> Color32 {
    Color32::from_rgb(156, 164, 176)
}

pub fn arc_primary() -> Color32 {
    Color32::from_rgb(255, 198, 1)
}

pub fn arc_primary_foreground() -> Color32 {
    Color32::from_rgb(24, 25, 28)
}

pub fn arc_success() -> Color32 {
    Color32::from_rgb(80, 220, 150)
}

pub fn arc_warning() -> Color32 {
    Color32::from_rgb(248, 165, 80)
}

// ----- theme ------------------------------------------------------------------------

pub fn apply_arc_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = arc_bg();
    visuals.window_fill = arc_card();
    visuals.extreme_bg_color = arc_input();
    visuals.faint_bg_color = arc_muted();
    visuals.hyperlink_color = arc_primary();
    visuals.selection.bg_fill = arc_primary();
    visuals.selection.stroke = Stroke::new(1.0, arc_primary_foreground());
    visuals.widgets.inactive.bg_fill = arc_input();
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, arc_foreground());
    visuals.widgets.hovered.bg_fill = arc_muted();
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, arc_foreground());
    visuals.widgets.active.bg_fill = arc_primary();
    visuals.widgets.active.fg_stroke = Stroke::new(1.0, arc_primary_foreground());

    let mut style = (*ctx.style()).clone();
    style.visuals = visuals;
    style.spacing.item_spacing = Vec2::new(SPACE_SM, SPACE_SM);
    style.spacing.button_padding = Vec2::new(12.0, 7.0);
    style.spacing.combo_width = 220.0;
    ctx.set_style(style);
}
