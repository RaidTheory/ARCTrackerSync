//! Shared ARC-styled widgets. All sizing/coloring comes from [`crate::theme`]
//! tokens so the components stay on one visual scale.

use eframe::egui::{
    self, pos2, vec2, Align, Align2, Color32, CornerRadius, FontId, Frame, Layout, Margin, Pos2,
    Rect, RichText, Sense, Shape, Stroke, StrokeKind, Vec2,
};

use crate::theme::{
    arc_bg, arc_border, arc_border_soft, arc_border_strong, arc_card, arc_danger, arc_fg_dim,
    arc_foreground, arc_input, arc_muted, arc_muted_text, arc_primary, arc_primary_foreground,
    ICON_TILE, NODE_DIAMETER, PILL_FILL_OPACITY, PILL_STROKE_OPACITY, RADIUS_CARD, RADIUS_CONTROL,
    RADIUS_PILL, RADIUS_TILE, SPACE_MD, SPACE_SM, SPACE_XS, STEP_ROW_HEIGHT, TEXT_BODY,
    TEXT_CAPTION, TEXT_EYEBROW, TEXT_PILL, TEXT_STEP_LABEL, TEXT_SUBLABEL, TONE_FILL_OPACITY,
    TONE_STROKE_OPACITY, WINDOW_BUTTON,
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

// ----- buttons ----------------------------------------------------------------

pub fn primary_button(ui: &mut egui::Ui, label: &str) -> bool {
    let button = egui::Button::new(
        RichText::new(label)
            .strong()
            .color(arc_primary_foreground()),
    )
    .fill(arc_primary())
    .stroke(Stroke::NONE)
    .corner_radius(CornerRadius::same(RADIUS_CONTROL));
    ui.add(button)
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
}

pub fn secondary_button(ui: &mut egui::Ui, label: &str) -> bool {
    let button = egui::Button::new(RichText::new(label).color(arc_foreground()))
        .fill(arc_input())
        .stroke(Stroke::new(1.0, arc_border()))
        .corner_radius(CornerRadius::same(RADIUS_CONTROL));
    ui.add(button)
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
}

pub fn link_button(ui: &mut egui::Ui, label: &str) -> bool {
    ui.add(egui::Button::new(RichText::new(label).color(arc_primary())).frame(false))
        .on_hover_cursor(egui::CursorIcon::PointingHand)
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
    ui.add(button)
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
}

// ----- cards ------------------------------------------------------------------

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

/// A tone-tinted status card (success "synced until…", warn notices)
pub fn tone_card<R>(
    ui: &mut egui::Ui,
    tone: Color32,
    add_contents: impl FnOnce(&mut egui::Ui) -> R,
) -> R {
    Frame::NONE
        .fill(tone.linear_multiply(TONE_FILL_OPACITY))
        .stroke(Stroke::new(1.0, tone.linear_multiply(TONE_STROKE_OPACITY)))
        .corner_radius(CornerRadius::same(RADIUS_TILE))
        .inner_margin(Margin::symmetric(14, 12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add_contents(ui)
        })
        .inner
}

/// A settings group: a card with a gold mono eyebrow title and hairline-separated
pub fn settings_card<R>(
    ui: &mut egui::Ui,
    title: &str,
    add_contents: impl FnOnce(&mut egui::Ui) -> R,
) -> R {
    card(ui, |ui| {
        mono_eyebrow(ui, title, arc_primary());
        ui.add_space(SPACE_MD);
        add_contents(ui)
    })
}

/// One settings row: label + optional sub-label on the left, a control placed
pub fn settings_row(
    ui: &mut egui::Ui,
    label: &str,
    sub: &str,
    add_control: impl FnOnce(&mut egui::Ui),
) {
    ui.add_space(SPACE_XS);
    ui.horizontal(|ui| {
        // Lay the control out from the right edge first so the remaining width
        // bounds the text column — a long sub-label (or translation) wraps
        // instead of running underneath the control.
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            add_control(ui);
            ui.with_layout(Layout::top_down(Align::Min), |ui| {
                ui.label(RichText::new(label).color(arc_foreground()));
                if !sub.is_empty() {
                    ui.label(RichText::new(sub).size(TEXT_CAPTION).color(arc_fg_dim()));
                }
            });
        });
    });
    ui.add_space(SPACE_XS);
}

/// Full-width hairline divider used between settings rows
pub fn hairline(ui: &mut egui::Ui) {
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), 1.0), Sense::hover());
    ui.painter().hline(
        rect.x_range(),
        rect.center().y,
        Stroke::new(1.0, arc_border_soft()),
    );
}

// ----- pills ------------------------------------------------------------------

/// Padding inside pills.
const PILL_PAD_X: f32 = 12.0;
const PILL_PAD_Y: f32 = 6.5;

/// Draw a pill background (fill + stroke) into `rect`.
fn paint_pill_bg(ui: &egui::Ui, rect: Rect, color: Color32) {
    let painter = ui.painter();
    painter.rect_filled(
        rect,
        CornerRadius::same(RADIUS_PILL),
        color.linear_multiply(PILL_FILL_OPACITY),
    );
    painter.rect_stroke(
        rect,
        CornerRadius::same(RADIUS_PILL),
        Stroke::new(1.0, color.linear_multiply(PILL_STROKE_OPACITY)),
        StrokeKind::Inside,
    );
}

pub fn pill(ui: &mut egui::Ui, text: &str, color: Color32) {
    let galley =
        ui.painter()
            .layout_no_wrap(text.to_owned(), FontId::proportional(TEXT_PILL), color);
    let ink = galley.mesh_bounds;
    let dot = 6.0;
    let gap = 6.0;
    // Draw the capsule at an exact size we control (the font's line box is
    // inflated, so we can't rely on egui auto-sizing the frame).
    let w = PILL_PAD_X * 2.0 + dot + gap + galley.size().x;
    let h = TEXT_PILL + 1.0 + PILL_PAD_Y * 2.0;
    let (rect, _) = ui.allocate_exact_size(vec2(w, h), Sense::hover());
    paint_pill_bg(ui, rect, color);
    let cy = rect.center().y;
    ui.painter()
        .circle_filled(pos2(rect.left() + PILL_PAD_X + dot / 2.0, cy), 3.0, color);
    ui.painter().galley(
        pos2(rect.left() + PILL_PAD_X + dot + gap, cy - ink.center().y),
        galley,
        color,
    );
}

/// Like [`pill`], but the whole chip is a click target (the "update available"
/// indicator in the title bar).
pub fn clickable_pill(ui: &mut egui::Ui, text: &str, color: Color32) -> egui::Response {
    let galley =
        ui.painter()
            .layout_no_wrap(text.to_owned(), FontId::proportional(TEXT_PILL), color);
    let ink = galley.mesh_bounds;
    let w = PILL_PAD_X * 2.0 + galley.size().x;
    let h = TEXT_PILL + 1.0 + PILL_PAD_Y * 2.0;
    let (rect, response) = ui.allocate_exact_size(vec2(w, h), Sense::click());
    paint_pill_bg(ui, rect, color);
    ui.painter().galley(
        pos2(rect.left() + PILL_PAD_X, rect.center().y - ink.center().y),
        galley,
        color,
    );
    response.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// Uppercase monospace eyebrow (hero "<PHASE> · STEP n OF 4", settings titles)
pub fn mono_eyebrow(ui: &mut egui::Ui, text: &str, color: Color32) {
    ui.label(
        RichText::new(text.to_uppercase())
            .font(FontId::monospace(TEXT_EYEBROW))
            .color(color),
    );
}

// ----- status / spinners ------------------------------------------------------

/// Spinner plus status line; the update dialog body while installing.
pub fn spinner_row(ui: &mut egui::Ui, label: &str) {
    ui.horizontal(|ui| {
        ui.spinner();
        ui.add_space(SPACE_SM);
        ui.label(RichText::new(label).size(TEXT_BODY).color(arc_foreground()));
    });
}

// ----- toggle switch ----------------------------------------------------------

/// A 42×24 pill toggle. Returns true when toggled this frame.
pub fn toggle_switch(ui: &mut egui::Ui, on: &mut bool) -> bool {
    let (rect, mut response) = ui.allocate_exact_size(vec2(42.0, 24.0), Sense::click());
    if response.clicked() {
        *on = !*on;
        response.mark_changed();
    }
    let how_on = ui.ctx().animate_bool_with_time(response.id, *on, 0.12);

    let track = mix(arc_input(), arc_primary(), how_on);
    let painter = ui.painter();
    painter.rect_filled(rect, CornerRadius::same(RADIUS_PILL), track);
    if how_on < 1.0 {
        painter.rect_stroke(
            rect,
            CornerRadius::same(RADIUS_PILL),
            Stroke::new(1.0, arc_border_strong()),
            StrokeKind::Inside,
        );
    }
    let knob_x = egui::lerp((rect.left() + 12.0)..=(rect.right() - 12.0), how_on);
    let knob = mix(arc_fg_dim(), arc_primary_foreground(), how_on);
    painter.circle_filled(pos2(knob_x, rect.center().y), 9.0, knob);

    response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .changed()
}

// ----- vertical stepper -------------------------------------------------------

pub struct StepperNode<'a> {
    /// 1-based step number, shown inside pending nodes.
    pub number: usize,
    pub label: &'a str,
    pub sub: &'a str,
    pub state: StageState,
}

/// The persistent left rail: four nodes joined by connectors, each with a phase
/// label and sub-label. `tone` colors the current node's ring/halo/dot; `busy`
/// makes that halo breathe. Renders fully without animation.
pub fn vertical_stepper(ui: &mut egui::Ui, nodes: &[StepperNode<'_>], tone: Color32, busy: bool) {
    let node_r = NODE_DIAMETER / 2.0;
    let count = nodes.len();
    let time = ui.input(|input| input.time) as f32;

    for (index, node) in nodes.iter().enumerate() {
        let width = ui.available_width();
        let (rect, _) = ui.allocate_exact_size(vec2(width, STEP_ROW_HEIGHT), Sense::hover());
        let painter = ui.painter();
        let center = pos2(rect.left() + node_r, rect.center().y);

        // Connector down to the next node (accent once this step is done).
        if index + 1 < count {
            let color = if node.state == StageState::Done {
                arc_primary()
            } else {
                arc_border_soft()
            };
            let top = pos2(center.x, center.y + node_r + 4.0);
            let bottom = pos2(center.x, center.y + STEP_ROW_HEIGHT - node_r - 4.0);
            painter.line_segment([top, bottom], Stroke::new(2.0, color));
        }

        match node.state {
            StageState::Done => {
                painter.circle_filled(center, node_r, arc_primary());
                draw_check(painter, center, arc_primary_foreground());
            }
            StageState::Current => {
                let halo = if busy {
                    0.10 + 0.18 * (0.5 + 0.5 * (time * 3.0).sin())
                } else {
                    0.18
                };
                painter.circle_filled(center, node_r + 6.0, tone.linear_multiply(halo));
                painter.circle_stroke(center, node_r, Stroke::new(2.0, tone));
                painter.circle_filled(center, 4.5, tone);
            }
            StageState::Pending => {
                painter.circle_stroke(center, node_r, Stroke::new(1.5, arc_border_strong()));
                painter.text(
                    center,
                    Align2::CENTER_CENTER,
                    node.number.to_string(),
                    FontId::proportional(12.0),
                    arc_fg_dim(),
                );
            }
        }

        let label_color = match node.state {
            StageState::Current => arc_foreground(),
            StageState::Pending => arc_fg_dim(),
            StageState::Done => arc_muted_text(),
        };
        let text_x = center.x + node_r + 14.0;
        painter.text(
            pos2(text_x, center.y - 9.0),
            Align2::LEFT_CENTER,
            node.label,
            FontId::proportional(TEXT_STEP_LABEL),
            label_color,
        );
        painter.text(
            pos2(text_x, center.y + 9.0),
            Align2::LEFT_CENTER,
            node.sub,
            FontId::proportional(TEXT_SUBLABEL),
            arc_fg_dim(),
        );
    }

    if busy {
        ui.ctx().request_repaint();
    }
}

// ----- hero icon tile ---------------------------------------------------------

/// The 44×44 rounded tone-tinted tile above the hero eyebrow. Shows a spinner
/// for busy phases, otherwise a simple per-phase glyph.
pub fn icon_tile(ui: &mut egui::Ui, phase: usize, tone: Color32, busy: bool) {
    let (rect, _) = ui.allocate_exact_size(vec2(ICON_TILE, ICON_TILE), Sense::hover());
    ui.painter().rect_filled(
        rect,
        CornerRadius::same(RADIUS_TILE),
        tone.linear_multiply(TONE_FILL_OPACITY),
    );
    if busy {
        // paint_at fills the given rect, so use a small centered rect rather
        // than the whole 44px tile.
        let inner = Rect::from_center_size(rect.center(), Vec2::splat(20.0));
        egui::Spinner::new().color(tone).paint_at(ui, inner);
    } else {
        draw_phase_icon(ui.painter(), rect.center(), tone, phase);
    }
}

// ----- window chrome ----------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowButton {
    Minimize,
    Maximize,
    Restore,
    Close,
}

/// A 30×30 ghost window-control button with a painter-drawn glyph. Close hovers
/// red; the rest hover with a faint fill.
pub fn window_button(ui: &mut egui::Ui, kind: WindowButton) -> bool {
    let (rect, response) =
        ui.allocate_exact_size(vec2(WINDOW_BUTTON, WINDOW_BUTTON), Sense::click());
    let hovered = response.hovered();
    let is_close = kind == WindowButton::Close;
    let painter = ui.painter();

    if hovered {
        let fill = if is_close { arc_danger() } else { arc_muted() };
        painter.rect_filled(rect, CornerRadius::same(8), fill);
    }
    let fg = if is_close && hovered {
        Color32::WHITE
    } else if hovered {
        arc_foreground()
    } else {
        arc_muted_text()
    };
    let c = rect.center();
    let stroke = Stroke::new(1.4, fg);
    match kind {
        WindowButton::Minimize => {
            painter.line_segment([c + vec2(-5.0, 0.0), c + vec2(5.0, 0.0)], stroke);
        }
        WindowButton::Maximize => {
            painter.rect_stroke(
                Rect::from_center_size(c, vec2(10.0, 10.0)),
                CornerRadius::same(2),
                stroke,
                StrokeKind::Middle,
            );
        }
        WindowButton::Restore => {
            painter.rect_stroke(
                Rect::from_min_size(c + vec2(-3.0, -5.0), vec2(8.0, 8.0)),
                CornerRadius::same(2),
                stroke,
                StrokeKind::Middle,
            );
            painter.rect_stroke(
                Rect::from_min_size(c + vec2(-5.0, -3.0), vec2(8.0, 8.0)),
                CornerRadius::same(2),
                stroke,
                StrokeKind::Middle,
            );
        }
        WindowButton::Close => {
            painter.line_segment([c + vec2(-5.0, -5.0), c + vec2(5.0, 5.0)], stroke);
            painter.line_segment([c + vec2(-5.0, 5.0), c + vec2(5.0, -5.0)], stroke);
        }
    }
    response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
}

/// Invisible edge/corner grab zones that drive native window resizing. Skip
/// calling this while maximized.
pub fn resize_handles(ctx: &egui::Context, ui: &mut egui::Ui, rect: Rect) {
    use egui::{CursorIcon, ResizeDirection, ViewportCommand};

    let m = 6.0;
    let zones = [
        (
            Rect::from_min_max(
                pos2(rect.left() + m, rect.top()),
                pos2(rect.right() - m, rect.top() + m),
            ),
            CursorIcon::ResizeNorth,
            ResizeDirection::North,
        ),
        (
            Rect::from_min_max(
                pos2(rect.left() + m, rect.bottom() - m),
                pos2(rect.right() - m, rect.bottom()),
            ),
            CursorIcon::ResizeSouth,
            ResizeDirection::South,
        ),
        (
            Rect::from_min_max(
                pos2(rect.left(), rect.top() + m),
                pos2(rect.left() + m, rect.bottom() - m),
            ),
            CursorIcon::ResizeWest,
            ResizeDirection::West,
        ),
        (
            Rect::from_min_max(
                pos2(rect.right() - m, rect.top() + m),
                pos2(rect.right(), rect.bottom() - m),
            ),
            CursorIcon::ResizeEast,
            ResizeDirection::East,
        ),
        (
            Rect::from_min_max(rect.left_top(), pos2(rect.left() + m, rect.top() + m)),
            CursorIcon::ResizeNorthWest,
            ResizeDirection::NorthWest,
        ),
        (
            Rect::from_min_max(
                pos2(rect.right() - m, rect.top()),
                pos2(rect.right(), rect.top() + m),
            ),
            CursorIcon::ResizeNorthEast,
            ResizeDirection::NorthEast,
        ),
        (
            Rect::from_min_max(
                pos2(rect.left(), rect.bottom() - m),
                pos2(rect.left() + m, rect.bottom()),
            ),
            CursorIcon::ResizeSouthWest,
            ResizeDirection::SouthWest,
        ),
        (
            Rect::from_min_max(
                pos2(rect.right() - m, rect.bottom() - m),
                rect.right_bottom(),
            ),
            CursorIcon::ResizeSouthEast,
            ResizeDirection::SouthEast,
        ),
    ];

    for (index, (zone, cursor, direction)) in zones.into_iter().enumerate() {
        let response = ui.interact(zone, ui.id().with(("arc_resize", index)), Sense::drag());
        if response.hovered() || response.dragged() {
            ctx.set_cursor_icon(cursor);
        }
        if response.drag_started() {
            ctx.send_viewport_cmd(ViewportCommand::BeginResize(direction));
        }
    }
}

// ----- painter helpers --------------------------------------------------------

fn mix(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let f = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    Color32::from_rgb(f(a.r(), b.r()), f(a.g(), b.g()), f(a.b(), b.b()))
}

fn draw_check(painter: &egui::Painter, center: Pos2, color: Color32) {
    let stroke = Stroke::new(2.0, color);
    let p1 = center + vec2(-4.5, 0.0);
    let p2 = center + vec2(-1.0, 3.5);
    let p3 = center + vec2(5.0, -3.5);
    painter.line_segment([p1, p2], stroke);
    painter.line_segment([p2, p3], stroke);
}

fn arc_points(
    center: Pos2,
    radius: f32,
    start_deg: f32,
    end_deg: f32,
    segments: usize,
) -> Vec<Pos2> {
    (0..=segments)
        .map(|i| {
            let t = start_deg + (end_deg - start_deg) * (i as f32 / segments as f32);
            let a = t.to_radians();
            pos2(center.x + radius * a.cos(), center.y + radius * a.sin())
        })
        .collect()
}

fn arrowhead(painter: &egui::Painter, points: &[Pos2], color: Color32) {
    let n = points.len();
    if n < 2 {
        return;
    }
    let tip = points[n - 1];
    let dir = (tip - points[n - 2]).normalized();
    let normal = vec2(-dir.y, dir.x);
    let back = tip - dir * 5.0;
    painter.add(Shape::convex_polygon(
        vec![tip, back + normal * 3.5, back - normal * 3.5],
        color,
        Stroke::NONE,
    ));
}

fn draw_phase_icon(painter: &egui::Painter, center: Pos2, color: Color32, phase: usize) {
    let stroke = Stroke::new(2.0, color);
    match phase {
        0 => {
            // Account — head + shoulders.
            painter.circle_stroke(center + vec2(0.0, -5.0), 4.0, stroke);
            let dome = arc_points(center + vec2(0.0, 8.5), 8.0, 180.0, 360.0, 18);
            painter.add(Shape::line(dome, stroke));
        }
        1 => {
            // Launcher — 2×2 app grid.
            let size = 7.0;
            let step = size / 2.0 + 1.0;
            for (dx, dy) in [(-1.0, -1.0), (1.0, -1.0), (-1.0, 1.0), (1.0, 1.0)] {
                painter.rect_filled(
                    Rect::from_center_size(center + vec2(dx * step, dy * step), vec2(size, size)),
                    CornerRadius::same(2),
                    color,
                );
            }
        }
        2 => {
            // Play — triangle.
            painter.add(Shape::convex_polygon(
                vec![
                    center + vec2(-5.0, -7.0),
                    center + vec2(7.0, 0.0),
                    center + vec2(-5.0, 7.0),
                ],
                color,
                Stroke::NONE,
            ));
        }
        _ => {
            // Sync — two chasing arcs.
            let lower = arc_points(center, 8.0, 25.0, 165.0, 16);
            let upper = arc_points(center, 8.0, 205.0, 345.0, 16);
            painter.add(Shape::line(lower.clone(), stroke));
            painter.add(Shape::line(upper.clone(), stroke));
            arrowhead(painter, &lower, color);
            arrowhead(painter, &upper, color);
        }
    }
}

/// A footer ghost button: a gear glyph + label (e.g. "Settings"). Sizes itself
/// to the label so it reads as a single icon+text unit regardless of layout
/// direction.
pub fn settings_button(ui: &mut egui::Ui, label: &str) -> bool {
    let font_size = 13.0;
    let font = FontId::proportional(font_size);
    // Lay out with PLACEHOLDER so the hover color can be applied at paint time.
    let galley = ui
        .painter()
        .layout_no_wrap(label.to_owned(), font, Color32::PLACEHOLDER);
    let icon = 13.0;
    let gap = 7.0;
    let pad_x = 10.0;
    let width = pad_x * 2.0 + icon + gap + galley.size().x;
    let (rect, response) = ui.allocate_exact_size(vec2(width, WINDOW_BUTTON), Sense::click());
    let hovered = response.hovered();
    let painter = ui.painter();
    if hovered {
        painter.rect_filled(rect, CornerRadius::same(8), arc_muted());
    }
    let fg = if hovered {
        arc_foreground()
    } else {
        arc_muted_text()
    };
    // Center both the glyph and the label on the button's vertical center. Use
    // the cap region (ink top + ~half a cap height) rather than the full ink
    // center, so descenders like the "g" don't push the text up.
    let cy = rect.center().y;
    let text_top = cy - (galley.mesh_bounds.top() + 0.36 * font_size);
    draw_gear(
        painter,
        pos2(rect.left() + pad_x + icon / 2.0, cy),
        fg,
        icon,
    );
    painter.galley(pos2(rect.left() + pad_x + icon + gap, text_top), galley, fg);
    response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
}

/// A gear glyph: a hub circle ringed by eight short spokes.
fn draw_gear(painter: &egui::Painter, center: Pos2, color: Color32, size: f32) {
    // The "spoke" settings glyph: a hub ring with eight evenly-spaced spokes.
    // Round caps on both ends make every spoke look identical so the icon reads
    // as symmetric and round.
    let stroke = Stroke::new(1.6, color);
    let cap = stroke.width / 2.0;
    let hub = size * 0.20;
    let r_in = size * 0.31;
    let r_out = size * 0.47;
    painter.circle_stroke(center, hub, stroke);
    for i in 0..8 {
        let angle = (i as f32) * std::f32::consts::FRAC_PI_4;
        let dir = vec2(angle.cos(), angle.sin());
        let p_in = center + dir * r_in;
        let p_out = center + dir * r_out;
        painter.line_segment([p_in, p_out], stroke);
        painter.circle_filled(p_in, cap, color);
        painter.circle_filled(p_out, cap, color);
    }
}

/// A 34×34 ghost back button (left arrow), used in the settings header.
pub fn back_button(ui: &mut egui::Ui) -> bool {
    let (rect, response) = ui.allocate_exact_size(vec2(34.0, 34.0), Sense::click());
    let hovered = response.hovered();
    let painter = ui.painter();
    if hovered {
        painter.rect_filled(rect, CornerRadius::same(8), arc_muted());
    }
    let fg = if hovered {
        arc_foreground()
    } else {
        arc_muted_text()
    };
    let stroke = Stroke::new(1.7, fg);
    let c = rect.center();
    painter.line_segment([c + vec2(7.0, 0.0), c + vec2(-7.0, 0.0)], stroke);
    painter.line_segment([c + vec2(-7.0, 0.0), c + vec2(-2.0, -5.0)], stroke);
    painter.line_segment([c + vec2(-7.0, 0.0), c + vec2(-2.0, 5.0)], stroke);
    response
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
}

/// A full-width secondary button (the settings "Quit" action).
pub fn secondary_button_full(ui: &mut egui::Ui, label: &str) -> bool {
    let button = egui::Button::new(RichText::new(label).color(arc_foreground()))
        .fill(arc_input())
        .stroke(Stroke::new(1.0, arc_border_strong()))
        .corner_radius(CornerRadius::same(RADIUS_CONTROL));
    ui.add_sized(vec2(ui.available_width(), 38.0), button)
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
}

/// A tone-tinted check badge used inline (e.g. the synced status card).
pub fn inline_check(ui: &mut egui::Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(vec2(18.0, 18.0), Sense::hover());
    let center = rect.center() - vec2(0.0, 1.0);
    ui.painter()
        .circle_filled(center, 9.0, color.linear_multiply(0.22));
    draw_check(ui.painter(), center, color);
}

/// A 40×40 accent-tinted rounded tile holding a refresh glyph — the explainer
/// modal's header badge.
pub fn refresh_badge(ui: &mut egui::Ui) {
    let (rect, _) = ui.allocate_exact_size(vec2(40.0, 40.0), Sense::hover());
    let accent = arc_primary();
    let painter = ui.painter();
    painter.rect_filled(rect, CornerRadius::same(11), accent.linear_multiply(0.15));
    painter.rect_stroke(
        rect,
        CornerRadius::same(11),
        Stroke::new(1.0, accent.linear_multiply(0.40)),
        StrokeKind::Inside,
    );
    let arc = arc_points(rect.center(), 6.5, 130.0, 400.0, 28);
    painter.add(Shape::line(arc.clone(), Stroke::new(2.0, accent)));
    arrowhead(painter, &arc, accent);
}

/// A light gold radial glow at the top-center of `area`, matching the design's
/// accent gradient. Pass a painter clipped to the body so it can't bleed over
/// the title bar or the window's rounded corners.
pub fn top_glow(painter: &egui::Painter, area: Rect) {
    let accent = arc_primary();
    let center = pos2(area.center().x, area.top() - area.height() * 0.04);
    let rx = area.width() * 0.6;
    let ry = area.height() * 0.4;
    let inner = Color32::from_rgba_unmultiplied(accent.r(), accent.g(), accent.b(), 38);
    let outer = Color32::from_rgba_unmultiplied(accent.r(), accent.g(), accent.b(), 0);
    let mut mesh = egui::Mesh::default();
    mesh.colored_vertex(center, inner);
    let segments = 48;
    for i in 0..=segments {
        let angle = (i as f32 / segments as f32) * std::f32::consts::TAU;
        mesh.colored_vertex(
            pos2(center.x + rx * angle.cos(), center.y + ry * angle.sin()),
            outer,
        );
    }
    for i in 1..=segments {
        mesh.add_triangle(0, i as u32, i as u32 + 1);
    }
    painter.add(mesh);
}

/// A modal pre-styled like the app's cards: a soft dimmed backdrop and a
/// generously padded card frame.
pub fn arc_modal(id: &str) -> egui::Modal {
    let bg = arc_bg();
    egui::Modal::new(egui::Id::new(id))
        .backdrop_color(Color32::from_rgba_unmultiplied(bg.r(), bg.g(), bg.b(), 188))
        .frame(
            Frame::NONE
                .fill(arc_card())
                .stroke(Stroke::new(1.0, arc_border()))
                .corner_radius(CornerRadius::same(RADIUS_CARD))
                .inner_margin(Margin::same(26)),
        )
}
