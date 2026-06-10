//! Shared ARC-styled widgets. All sizing/coloring comes from [`crate::theme`]
//! tokens so the components stay on one visual scale.

use eframe::egui::{self, Align, Color32, CornerRadius, Frame, Margin, RichText, Stroke, Vec2};

use crate::theme::{
    arc_border, arc_card, arc_foreground, arc_input, arc_muted_text, arc_primary,
    arc_primary_foreground, arc_success, PILL_FILL_OPACITY, PILL_STROKE_OPACITY, RADIUS_CARD,
    RADIUS_CONTROL, SPACE_MD, SPACE_SM, SPACE_XS, TEXT_BODY, TEXT_CAPTION, TEXT_TITLE,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageState {
    Done,
    Current,
    Pending,
}

pub fn stage(done: bool, current: bool) -> StageState {
    if done {
        StageState::Done
    } else if current {
        StageState::Current
    } else {
        StageState::Pending
    }
}

pub fn primary_button(ui: &mut egui::Ui, label: &str) -> bool {
    let button = egui::Button::new(
        RichText::new(label)
            .strong()
            .color(arc_primary_foreground()),
    )
    .fill(arc_primary())
    .stroke(Stroke::NONE)
    .corner_radius(CornerRadius::same(RADIUS_CONTROL));
    ui.add(button).clicked()
}

pub fn secondary_button(ui: &mut egui::Ui, label: &str) -> bool {
    let button = egui::Button::new(RichText::new(label).color(arc_foreground()))
        .fill(arc_input())
        .stroke(Stroke::new(1.0, arc_border()))
        .corner_radius(CornerRadius::same(RADIUS_CONTROL));
    ui.add(button).clicked()
}

pub fn link_button(ui: &mut egui::Ui, label: &str) -> bool {
    ui.add(egui::Button::new(RichText::new(label).color(arc_primary())).frame(false))
        .clicked()
}

/// One segment of the Steam|Epic launcher toggle.
pub fn launcher_segment(ui: &mut egui::Ui, label: &str, selected: bool) -> bool {
    let (fill, text, stroke) = if selected {
        (arc_primary(), arc_primary_foreground(), Stroke::NONE)
    } else {
        (
            arc_input(),
            arc_foreground(),
            Stroke::new(1.0, arc_border()),
        )
    };
    let button = egui::Button::new(RichText::new(label).size(TEXT_CAPTION).color(text))
        .fill(fill)
        .stroke(stroke)
        .corner_radius(CornerRadius::same(RADIUS_CONTROL));
    ui.add(button).clicked()
}

pub fn toggle_row(ui: &mut egui::Ui, label: &str, sub: &str, value: &mut bool) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.label(RichText::new(label).color(arc_foreground()));
            ui.label(
                RichText::new(sub)
                    .size(TEXT_CAPTION)
                    .color(arc_muted_text()),
            );
        });
        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
            changed = ui.add(egui::Checkbox::without_text(value)).changed();
        });
    });
    changed
}

pub fn settings_section<R>(
    ui: &mut egui::Ui,
    title: &str,
    add_contents: impl FnOnce(&mut egui::Ui) -> R,
) -> R {
    card(ui, |ui| {
        ui.label(
            RichText::new(title)
                .size(TEXT_BODY)
                .strong()
                .color(arc_primary()),
        );
        ui.add_space(SPACE_MD);
        add_contents(ui)
    })
}

pub fn card<R>(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui) -> R) -> R {
    Frame::NONE
        .fill(arc_card())
        .stroke(Stroke::new(1.0, arc_border()))
        .corner_radius(CornerRadius::same(RADIUS_CARD))
        .inner_margin(Margin::same(16))
        .show(ui, |ui| {
            // Span the content column so every card shares one width.
            ui.set_width(ui.available_width());
            add_contents(ui)
        })
        .inner
}

pub fn pill(ui: &mut egui::Ui, text: &str, color: Color32) {
    pill_frame(color).show(ui, |ui| {
        ui.label(pill_text(text, color));
    });
}

/// Like [`pill`], but the whole chip is a click target (the header
/// "update available" indicator).
pub fn clickable_pill(ui: &mut egui::Ui, text: &str, color: Color32) -> egui::Response {
    let inner = pill_frame(color).show(ui, |ui| {
        ui.label(pill_text(text, color));
    });
    ui.interact(
        inner.response.rect,
        egui::Id::new("arc_update_pill"),
        egui::Sense::click(),
    )
    .on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn pill_frame(color: Color32) -> Frame {
    Frame::NONE
        .fill(color.linear_multiply(PILL_FILL_OPACITY))
        .stroke(Stroke::new(1.0, color.linear_multiply(PILL_STROKE_OPACITY)))
        .corner_radius(CornerRadius::same(RADIUS_CONTROL))
        .inner_margin(Margin::symmetric(8, 4))
}

fn pill_text(text: &str, color: Color32) -> RichText {
    RichText::new(text).size(TEXT_CAPTION).strong().color(color)
}

pub fn progress_stage(ui: &mut egui::Ui, label: &str, state: StageState) {
    let (color, marker) = match state {
        StageState::Done => (arc_success(), "●"),
        StageState::Current => (arc_primary(), "◆"),
        StageState::Pending => (arc_muted_text(), "○"),
    };
    ui.label(RichText::new(marker).size(TEXT_CAPTION).color(color));
    ui.add_space(SPACE_XS);
    let text_color = if state == StageState::Pending {
        arc_muted_text()
    } else {
        arc_foreground()
    };
    let mut text = RichText::new(label).size(TEXT_CAPTION).color(text_color);
    if state == StageState::Current {
        text = text.strong();
    }
    ui.label(text);
}

pub fn status_dot(ui: &mut egui::Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(Vec2::new(14.0, 14.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), 7.0, color);
}

/// Spinner plus status line; the update dialog body while installing.
pub fn spinner_row(ui: &mut egui::Ui, label: &str) {
    ui.horizontal(|ui| {
        ui.spinner();
        ui.add_space(SPACE_SM);
        ui.label(RichText::new(label).size(TEXT_BODY).color(arc_foreground()));
    });
}

/// The shared top bar: optional ARC mark, screen title, and a right-aligned
/// slot (pills on the hub, nothing on settings). A `leading` slot renders
/// before the mark for the settings back link.
pub fn screen_header(
    ui: &mut egui::Ui,
    mark: Option<&egui::TextureHandle>,
    title: &str,
    leading: impl FnOnce(&mut egui::Ui),
    right: impl FnOnce(&mut egui::Ui),
) {
    ui.horizontal(|ui| {
        leading(ui);
        if let Some(mark) = mark {
            ui.image((mark.id(), Vec2::splat(20.0)));
        }
        ui.label(
            RichText::new(title)
                .size(TEXT_TITLE)
                .strong()
                .color(arc_foreground()),
        );
        ui.with_layout(egui::Layout::right_to_left(Align::Center), right);
    });
}
