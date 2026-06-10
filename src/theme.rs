//! ARC design tokens and the egui theme built from them.
//!
//! Add new values to the scales below rather than hardcoding pixel literals
//! in render code. oklch values (in comments) are the source of truth for each
//! color; the `Color32` literals are the sRGB fallback used at runtime.

use eframe::egui::{self, Color32, CornerRadius, Stroke, Vec2};

// ----- spacing (4pt rhythm) --------------------------------------------------

pub const SPACE_XS: f32 = 4.0;
pub const SPACE_SM: f32 = 8.0;
pub const SPACE_MD: f32 = 12.0;
pub const SPACE_LG: f32 = 16.0;
pub const SPACE_XL: f32 = 24.0;

// ----- type scale ------------------------------------------------------------

/// Hub hero title
pub const TEXT_HUB_TITLE: f32 = 24.0;
/// Screen / section titles
pub const TEXT_TITLE: f32 = 20.0;
/// Modal titles
pub const TEXT_SUBTITLE: f32 = 18.0;
/// Hero body copy
pub const TEXT_HERO_BODY: f32 = 14.5;
/// Body copy and standard labels
pub const TEXT_BODY: f32 = 14.0;
/// Stepper phase labels
pub const TEXT_STEP_LABEL: f32 = 13.5;
/// Secondary body copy (modal bodies, changelog, session notices)
pub const TEXT_SECONDARY: f32 = 13.0;
/// Footer status line
pub const TEXT_FOOTER: f32 = 12.5;
/// Captions: pills, settings sublabels
pub const TEXT_CAPTION: f32 = 12.0;
/// Status pill / chip label (title-bar "Signed in", update pill)
pub const TEXT_PILL: f32 = 11.5;
/// Stepper sub-labels
pub const TEXT_SUBLABEL: f32 = 11.5;
/// Mono eyebrow above the hero title
pub const TEXT_EYEBROW: f32 = 11.0;

// ----- radii & strokes ---------------------------------------------------------

/// Outer window frame (the rounded borderless chrome)
pub const RADIUS_WINDOW: u8 = 14;
pub const RADIUS_CARD: u8 = 13;
/// Icon tiles and the larger tinted tiles
pub const RADIUS_TILE: u8 = 12;
pub const RADIUS_CONTROL: u8 = 10;
/// Fully rounded pills / toggle tracks (saturates at the u8 ceiling)
pub const RADIUS_PILL: u8 = 255;

// ----- hub / chrome layout ------------------------------------------------------

/// Custom title bar height
pub const TITLE_BAR_HEIGHT: f32 = 42.0;
/// Custom footer height.
pub const FOOTER_HEIGHT: f32 = 52.0;
/// Horizontal padding inside the body (between chrome and content)
pub const BODY_PAD_X: f32 = 22.0;
/// Vertical padding inside the body.
pub const BODY_PAD_Y: f32 = 24.0;
/// Left stepper rail width.
pub const RAIL_WIDTH: f32 = 196.0;
/// Gap between the stepper rail and the hero panel (divider sits in the middle)
pub const COLUMN_GAP: f32 = 30.0;
/// Minimum height of one stepper row
pub const STEP_ROW_HEIGHT: f32 = 64.0;
/// Stepper node circle diameter.
pub const NODE_DIAMETER: f32 = 26.0;
/// Hero icon tile (rounded square) size
pub const ICON_TILE: f32 = 44.0;
/// Window control buttons (minimize / maximize / tray / close)
pub const WINDOW_BUTTON: f32 = 30.0;

// ----- widths ------------------------------------------------------------------

/// Shared max width for all modal dialogs.
pub const MODAL_WIDTH: f32 = 480.0;
/// Settings dropdowns (network adapter, etc.).
pub const COMBO_ADAPTER: f32 = 184.0;

// ----- tinting -------------------------------------------------------------------

pub const PILL_FILL_OPACITY: f32 = 0.15;
pub const PILL_STROKE_OPACITY: f32 = 0.42;
/// Fill opacity for tone-tinted tiles / status cards.
pub const TONE_FILL_OPACITY: f32 = 0.14;
/// Stroke opacity for tone-tinted status cards.
pub const TONE_STROKE_OPACITY: f32 = 0.40;

// ----- palette -------------------------------------------------------------------

/// Window background. oklch(0.135 0.017 236)
pub fn arc_bg() -> Color32 {
    Color32::from_rgb(16, 23, 32)
}

/// Title bar / footer chrome. oklch(0.118 0.017 238)
pub fn arc_titlebar() -> Color32 {
    Color32::from_rgb(13, 20, 28)
}

/// Cards / tiles. oklch(0.188 0.016 234)
pub fn arc_card() -> Color32 {
    Color32::from_rgb(27, 35, 45)
}

/// Inputs / ghost fills. oklch(0.172 0.015 236)
pub fn arc_input() -> Color32 {
    Color32::from_rgb(24, 31, 40)
}

/// Faint hover / muted surface (≈ border-soft). oklch(0.232 0.012 240)
pub fn arc_muted() -> Color32 {
    Color32::from_rgb(37, 44, 54)
}

/// Card borders. oklch(0.268 0.012 240)
pub fn arc_border() -> Color32 {
    Color32::from_rgb(44, 52, 63)
}

/// Hairlines / dividers. oklch(0.232 0.012 240)
pub fn arc_border_soft() -> Color32 {
    Color32::from_rgb(37, 44, 54)
}

/// Control borders / pending stepper nodes. oklch(0.340 0.013 242)
pub fn arc_border_strong() -> Color32 {
    Color32::from_rgb(59, 68, 80)
}

/// Primary text. oklch(0.965 0.006 240)
pub fn arc_foreground() -> Color32 {
    Color32::from_rgb(238, 241, 245)
}

/// Body text. oklch(0.712 0.013 246)
pub fn arc_muted_text() -> Color32 {
    Color32::from_rgb(154, 163, 176)
}

/// Captions / sub-labels. oklch(0.560 0.014 248)
pub fn arc_fg_dim() -> Color32 {
    Color32::from_rgb(114, 123, 137)
}

/// Brand gold (softened). oklch(0.855 0.165 89)
pub fn arc_primary() -> Color32 {
    Color32::from_rgb(251, 200, 44)
}

/// Text on the gold accent. oklch(0.185 0.02 252)
pub fn arc_primary_foreground() -> Color32 {
    Color32::from_rgb(21, 32, 43)
}

/// Synced / success. oklch(0.80 0.135 162)
pub fn arc_success() -> Color32 {
    Color32::from_rgb(95, 216, 163)
}

/// Attention / warn. oklch(0.815 0.125 66)
pub fn arc_warning() -> Color32 {
    Color32::from_rgb(249, 177, 102)
}

/// Hover tint for the close button.
pub fn arc_danger() -> Color32 {
    Color32::from_rgb(232, 86, 86)
}

// ----- theme ------------------------------------------------------------------------

pub fn apply_arc_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = arc_bg();
    visuals.window_fill = arc_card();
    visuals.window_stroke = Stroke::new(1.0, arc_border());
    visuals.window_corner_radius = CornerRadius::same(RADIUS_CARD);
    visuals.extreme_bg_color = arc_input();
    visuals.faint_bg_color = arc_muted();
    visuals.hyperlink_color = arc_primary();
    visuals.selection.bg_fill = arc_primary();
    visuals.selection.stroke = Stroke::new(1.0, arc_primary_foreground());

    for state in [
        &mut visuals.widgets.inactive,
        &mut visuals.widgets.hovered,
        &mut visuals.widgets.active,
        &mut visuals.widgets.open,
        &mut visuals.widgets.noninteractive,
    ] {
        state.corner_radius = CornerRadius::same(RADIUS_CONTROL);
    }

    visuals.widgets.inactive.bg_fill = arc_input();
    visuals.widgets.inactive.weak_bg_fill = arc_input();
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, arc_border());
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, arc_foreground());
    visuals.widgets.hovered.bg_fill = arc_muted();
    visuals.widgets.hovered.weak_bg_fill = arc_muted();
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, arc_border_strong());
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, arc_foreground());
    // Pressed/active state stays subtle (a faint surface) rather than flashing
    // the gold accent, which inverted text and made controls hard to read.
    visuals.widgets.active.bg_fill = arc_muted();
    visuals.widgets.active.weak_bg_fill = arc_muted();
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, arc_border_strong());
    visuals.widgets.active.fg_stroke = Stroke::new(1.0, arc_foreground());

    let mut style = (*ctx.style()).clone();
    style.visuals = visuals;
    style.spacing.item_spacing = Vec2::new(SPACE_SM, SPACE_SM);
    style.spacing.button_padding = Vec2::new(12.0, 7.0);
    style.spacing.combo_width = 220.0;
    ctx.set_style(style);
}
