//! Minimalist dark visual tokens and compact UI building blocks.
use eframe::egui::{self, Color32, Margin, RichText, Rounding, Stroke, Vec2};

pub const BG_CANVAS: Color32 = Color32::from_rgb(15, 17, 22);
pub const BG_PANEL: Color32 = Color32::from_rgb(19, 22, 29);
pub const BG_CARD: Color32 = Color32::from_rgb(24, 28, 37);
pub const BG_NESTED: Color32 = Color32::from_rgb(18, 21, 28);
pub const BG_INPUT: Color32 = Color32::from_rgb(13, 15, 20);
pub const BORDER_SUBTLE: Color32 = Color32::from_rgb(39, 45, 58);

pub const ACCENT: Color32 = Color32::from_rgb(92, 142, 248);
pub const ACCENT_FILL: Color32 = Color32::from_rgb(44, 77, 152);
pub const ACCENT_BG: Color32 = Color32::from_rgb(29, 45, 79);

pub const GREEN: Color32 = Color32::from_rgb(68, 204, 144);
pub const GREEN_BG: Color32 = Color32::from_rgb(22, 54, 41);

pub const AMBER: Color32 = Color32::from_rgb(242, 174, 64);
pub const AMBER_BG: Color32 = Color32::from_rgb(61, 45, 20);

pub const RED: Color32 = Color32::from_rgb(239, 98, 98);
pub const RED_BG: Color32 = Color32::from_rgb(64, 27, 30);

pub const TEXT_PRIMARY: Color32 = Color32::from_rgb(232, 236, 244);
pub const TEXT_MUTED: Color32 = Color32::from_rgb(142, 151, 168);

pub fn apply_theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = BG_CANVAS;
    visuals.window_fill = BG_PANEL;
    visuals.extreme_bg_color = BG_INPUT;
    visuals.faint_bg_color = BG_NESTED;
    visuals.override_text_color = Some(TEXT_PRIMARY);

    let rounding = Rounding::same(6.0);
    visuals.widgets.noninteractive.bg_fill = BG_CARD;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, BORDER_SUBTLE);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT_PRIMARY);
    visuals.widgets.noninteractive.rounding = rounding;

    visuals.widgets.inactive.bg_fill = Color32::from_rgb(31, 36, 48);
    visuals.widgets.inactive.weak_bg_fill = Color32::from_rgb(28, 33, 44);
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, BORDER_SUBTLE);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT_PRIMARY);
    visuals.widgets.inactive.rounding = rounding;

    visuals.widgets.hovered.bg_fill = Color32::from_rgb(40, 47, 62);
    visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(36, 43, 57);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, ACCENT);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0, Color32::WHITE);
    visuals.widgets.hovered.rounding = rounding;

    visuals.widgets.active.bg_fill = ACCENT_FILL;
    visuals.widgets.active.weak_bg_fill = ACCENT_FILL;
    visuals.widgets.active.bg_stroke = Stroke::new(1.0, ACCENT);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0, Color32::WHITE);
    visuals.widgets.active.rounding = rounding;

    visuals.selection.bg_fill = ACCENT_FILL;
    visuals.selection.stroke = Stroke::new(1.0, Color32::WHITE);

    ctx.set_visuals(visuals);
    ctx.style_mut(|style| {
        style.spacing.item_spacing = Vec2::new(8.0, 8.0);
        style.spacing.button_padding = Vec2::new(10.0, 5.0);
        style.spacing.window_margin = Margin::same(12.0);
    });
}

pub fn card(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::none()
        .fill(BG_CARD)
        .stroke(Stroke::new(1.0, BORDER_SUBTLE))
        .rounding(Rounding::same(8.0))
        .inner_margin(Margin::same(14.0))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add_contents(ui);
        });
}

pub fn nested_card(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::none()
        .fill(BG_NESTED)
        .stroke(Stroke::new(1.0, BORDER_SUBTLE))
        .rounding(Rounding::same(6.0))
        .inner_margin(Margin::same(10.0))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add_contents(ui);
        });
}

pub fn badge(ui: &mut egui::Ui, text: impl Into<String>, fg: Color32, bg: Color32) {
    egui::Frame::none()
        .fill(bg)
        .rounding(Rounding::same(5.0))
        .inner_margin(Margin::symmetric(7.0, 2.0))
        .show(ui, |ui| {
            ui.label(RichText::new(text.into()).size(11.5).color(fg).strong());
        });
}

pub fn primary_button(ui: &mut egui::Ui, label: impl Into<String>) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(label.into()).color(Color32::WHITE).strong())
            .fill(ACCENT_FILL)
            .stroke(Stroke::new(1.0, ACCENT))
            .rounding(Rounding::same(6.0)),
    )
}

pub fn pill_toggle(ui: &mut egui::Ui, selected: bool, label: impl Into<String>) -> egui::Response {
    let label_str = label.into();
    let text = if selected {
        RichText::new(label_str).color(Color32::WHITE).strong()
    } else {
        RichText::new(label_str).color(TEXT_MUTED)
    };
    let fill = if selected {
        ACCENT_BG
    } else {
        Color32::TRANSPARENT
    };
    let stroke = if selected {
        Stroke::new(1.0, ACCENT)
    } else {
        Stroke::new(1.0, BORDER_SUBTLE)
    };
    ui.add(
        egui::Button::new(text)
            .fill(fill)
            .stroke(stroke)
            .rounding(Rounding::same(6.0)),
    )
}

pub fn text_field(ui: &mut egui::Ui, label: &str, hint: &str, value: &mut String) {
    ui.label(RichText::new(label).size(12.0).color(TEXT_MUTED));
    ui.add(
        egui::TextEdit::singleline(value)
            .hint_text(hint)
            .desired_width(f32::INFINITY),
    );
}

pub fn secret_field(ui: &mut egui::Ui, label: &str, hint: &str, value: &mut String) {
    ui.label(RichText::new(label).size(12.0).color(TEXT_MUTED));
    ui.add(
        egui::TextEdit::singleline(value)
            .password(true)
            .hint_text(hint)
            .desired_width(f32::INFINITY),
    );
}

pub fn empty_state(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.add_space(20.0);
    ui.vertical_centered(|ui| {
        ui.label(RichText::new(title).size(15.0).strong());
        ui.add_space(4.0);
        ui.label(RichText::new(subtitle).size(13.0).color(TEXT_MUTED));
    });
    ui.add_space(20.0);
}
