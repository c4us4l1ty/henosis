#![deny(unsafe_code)]
mod backend;
mod state;
mod theme;
mod views;

use backend::{Backend, Event, ParsedProcess, parse_process_line, strip_prompt};
use eframe::egui::{self, Layout, Margin, RichText, Rounding, Stroke};
use henosis_proxy::impedance::ImpedanceMode;
use state::{Page, WorkspaceData};
use std::path::Path;
use std::time::{Duration, Instant};
use theme::{
    ACCENT, ACCENT_BG, AMBER, BG_CARD, BG_PANEL, BORDER_SUBTLE, GREEN, GREEN_BG, RED, TEXT_MUTED,
    TEXT_PRIMARY, apply_theme, badge, card, pill_toggle, primary_button, text_field,
};
use views::processes::ProcessAction;

const MAX_LOG: usize = 64 * 1024;

struct Desktop {
    shell: String,
    backend: Option<Backend>,
    command: String,
    log: String,
    error: String,
    closing: bool,
    close_deadline: Option<Instant>,
    theme_initialized: bool,
    processes: Vec<ParsedProcess>,
    line_buf: String,
    ws: WorkspaceData,
}

impl Default for Desktop {
    fn default() -> Self {
        let name = if cfg!(windows) {
            "henosis-shell.exe"
        } else {
            "henosis-shell"
        };
        let shell = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join(name)))
            .map_or_else(|| name.into(), |p| p.display().to_string());
        Self {
            shell,
            backend: None,
            command: String::new(),
            log: String::new(),
            error: String::new(),
            closing: false,
            close_deadline: None,
            theme_initialized: false,
            processes: Vec::new(),
            line_buf: String::new(),
            ws: WorkspaceData::default(),
        }
    }
}

impl Desktop {
    fn try_autoconnect(&mut self) {
        if Path::new(&self.shell).is_file() {
            self.connect();
        }
    }

    fn connect(&mut self) {
        if self.backend.is_some() {
            return;
        }
        match Backend::start(Path::new(&self.shell)) {
            Ok(mut backend) => {
                let _ = backend.send("list".into());
                self.backend = Some(backend);
                self.error.clear();
                self.ws.set_ok("Connected to workspace shell.");
            }
            Err(error) => {
                let msg = format!("Cannot start {}: {error}", self.shell);
                self.error = msg.clone();
                self.ws.set_err(msg);
            }
        }
    }

    fn disconnect(&mut self) {
        if let Some(backend) = &self.backend {
            backend.close();
            self.ws.set_ok("Closing workspace shell…");
        }
    }

    fn send(&mut self, line: String) {
        let Some(backend) = &mut self.backend else {
            let msg = "Shell is disconnected. Click Connect Shell first.".to_owned();
            self.error = msg.clone();
            self.ws.set_err(msg);
            return;
        };
        let refresh_after = line.starts_with("launch")
            || line.starts_with("stop")
            || line.starts_with("exit");
        match backend.send(line) {
            Ok(()) => {
                self.error.clear();
                if refresh_after {
                    if let Some(b) = &mut self.backend {
                        let _ = b.send("list".into());
                    }
                }
            }
            Err(error) => {
                self.error = error.clone();
                self.ws.set_err(error);
            }
        }
    }

    fn append_log(&mut self, text: &str) {
        self.log.push_str(text);
        if self.log.len() > MAX_LOG {
            let mut cut = self.log.len() - MAX_LOG;
            while !self.log.is_char_boundary(cut) {
                cut += 1;
            }
            self.log.drain(..cut);
        }
    }

    fn ingest_output_lines(&mut self, chunk: &str) {
        self.line_buf.push_str(chunk);
        while let Some(nl) = self.line_buf.find('\n') {
            let line: String = self.line_buf.drain(..=nl).collect();
            let clean = strip_prompt(line.trim_end_matches('\n')).trim();
            if clean == "No processes." {
                self.processes.clear();
            } else if let Some(parsed) = parse_process_line(&line) {
                if let Some(existing) = self.processes.iter_mut().find(|p| p.id == parsed.id) {
                    *existing = parsed;
                } else {
                    self.processes.push(parsed);
                }
            }
        }
    }

    fn record_exit(&mut self, ok: bool, detail: impl std::fmt::Display) {
        self.append_log(&format!("\n[workspace exited: {detail}]\n"));
        self.processes.clear();
        if !ok {
            let msg = format!("Workspace exited with {detail}.");
            self.error = msg.clone();
            self.ws.set_err(msg);
            self.closing = false;
            self.close_deadline = None;
        }
    }

    fn finish_close(&mut self) -> bool {
        if self.backend.is_none() {
            self.closing = false;
            self.close_deadline = None;
            return true;
        }
        if self
            .close_deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            self.closing = false;
            self.close_deadline = None;
            let msg = "Workspace is still shutting down; keep the window open or stop remaining processes before closing.".to_owned();
            self.error = msg.clone();
            self.ws.set_err(msg);
        }
        false
    }

    fn poll(&mut self) {
        let mut exited = None;
        let mut chunks = Vec::new();
        let mut errs = Vec::new();
        if let Some(backend) = &mut self.backend {
            for event in backend.output.try_iter() {
                match event {
                    Event::Output(text) => chunks.push(text),
                    Event::Error(error) => errs.push(error),
                }
            }
            match backend.child.try_wait() {
                Ok(Some(status)) => exited = Some(Ok(status)),
                Ok(None) => {}
                Err(error) => exited = Some(Err(error)),
            }
        }
        for text in chunks {
            self.append_log(&text);
            self.ingest_output_lines(&text);
        }
        for err in errs {
            self.error = err.clone();
            self.ws.set_err(err);
        }
        if let Some(result) = exited {
            if let Some(backend) = self.backend.take() {
                for event in backend.output.try_iter() {
                    match event {
                        Event::Output(text) => {
                            self.append_log(&text);
                            self.ingest_output_lines(&text);
                        }
                        Event::Error(error) => {
                            self.error = error.clone();
                            self.ws.set_err(error);
                        }
                    }
                }
            }
            match result {
                Ok(status) => self.record_exit(status.success(), status),
                Err(error) => self.record_exit(false, error),
            }
        }
    }

    fn render_header(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("henosis_header")
            .frame(
                egui::Frame::none()
                    .fill(BG_PANEL)
                    .inner_margin(Margin::symmetric(14.0, 8.0))
                    .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Henosis")
                            .size(16.0)
                            .color(TEXT_PRIMARY)
                            .strong(),
                    );

                    // Subtle shell status pill
                    let (dot_text, dot_color) = if self.backend.is_some() {
                        ("● Shell", GREEN)
                    } else {
                        ("○ Local", TEXT_MUTED)
                    };
                    if ui
                        .add(
                            egui::Button::new(RichText::new(dot_text).size(11.5).color(dot_color))
                                .fill(egui::Color32::TRANSPARENT)
                                .stroke(Stroke::NONE),
                        )
                        .on_hover_text("Workspace shell connection (click for Settings)")
                        .clicked()
                    {
                        self.ws.page = Page::Settings;
                    }

                    ui.separator();

                    // Compact inline workspace file selectors
                    ui.label(RichText::new("Crux").size(12.0).color(TEXT_MUTED));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.ws.crux_path)
                            .hint_text("crux.jsonl")
                            .desired_width(120.0),
                    );

                    ui.label(RichText::new("Worldline").size(12.0).color(TEXT_MUTED));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.ws.worldline_path)
                            .hint_text("worldline.json")
                            .desired_width(130.0),
                    );

                    // Right-aligned AI Proxy Impedance quick-switch
                    ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                        let active_mode = self.ws.current_impedance();
                        for (mode, label) in [
                            (ImpedanceMode::Blackout, "Blackout"),
                            (ImpedanceMode::Socratic, "Socratic"),
                            (ImpedanceMode::Open, "Open"),
                        ] {
                            if pill_toggle(ui, active_mode == Some(mode), label).clicked() {
                                self.ws.select_impedance(mode);
                            }
                        }
                        ui.label(RichText::new("AI Proxy").size(12.0).color(TEXT_MUTED));
                    });
                });
            });
    }

    fn render_sidebar(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("henosis_sidebar")
            .resizable(false)
            .exact_width(158.0)
            .frame(
                egui::Frame::none()
                    .fill(BG_PANEL)
                    .inner_margin(Margin::symmetric(10.0, 12.0))
                    .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE)),
            )
            .show(ctx, |ui| {
                let open_crux = self.ws.crux.proposals.iter().filter(|p| !p.closed).count();
                let h_count = self.ws.worldline.state.unassisted_capabilities().len();
                let verif_count = self.ws.worldline.state.verifications.len();
                let running_procs = self.processes.iter().filter(|p| p.running).count();

                for page in Page::PRIMARY {
                    let count_hint = match page {
                        Page::Crux if open_crux > 0 => Some(open_crux.to_string()),
                        Page::Worldline if h_count > 0 => Some(format!("{h_count} H")),
                        Page::Akashi if verif_count > 0 => Some(verif_count.to_string()),
                        Page::VaultProxy if self.ws.proxy.is_some() || self.ws.vault.is_some() => {
                            Some("●".into())
                        }
                        Page::Processes if running_procs > 0 => Some(running_procs.to_string()),
                        _ => None,
                    };
                    if sidebar_item(ui, self.ws.page == page, page.label(), count_hint.as_deref()) {
                        self.ws.page = page;
                    }
                    ui.add_space(2.0);
                }

                ui.with_layout(Layout::bottom_up(egui::Align::LEFT), |ui| {
                    if sidebar_item(
                        ui,
                        self.ws.page == Page::Settings,
                        Page::Settings.label(),
                        None,
                    ) {
                        self.ws.page = Page::Settings;
                    }
                });
            });
    }

    fn render_bottom_drawer(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("henosis_bottom_drawer")
            .frame(
                egui::Frame::none()
                    .fill(BG_PANEL)
                    .inner_margin(Margin::symmetric(14.0, 6.0))
                    .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if let Some(task) = &self.ws.running_task {
                        ui.spinner();
                        ui.colored_label(AMBER, task);
                    } else if !self.error.is_empty() {
                        ui.colored_label(RED, &self.error);
                    } else if self.ws.status_is_error {
                        ui.colored_label(RED, &self.ws.status_line);
                    } else {
                        ui.label(
                            RichText::new(&self.ws.status_line)
                                .size(12.5)
                                .color(TEXT_MUTED),
                        );
                    }

                    ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                        let toggle_label = if self.ws.drawer_open {
                            "Console ▾"
                        } else {
                            "Console ▴"
                        };
                        if ui.small_button(toggle_label).clicked() {
                            self.ws.drawer_open = !self.ws.drawer_open;
                        }
                        if self.ws.drawer_open
                            && !self.log.is_empty()
                            && ui.small_button("Clear").clicked()
                        {
                            self.log.clear();
                        }
                    });
                });

                if self.ws.drawer_open {
                    ui.add_space(4.0);
                    egui::Frame::none()
                        .fill(BG_CARD)
                        .rounding(Rounding::same(6.0))
                        .inner_margin(Margin::same(8.0))
                        .stroke(Stroke::new(1.0_f32, BORDER_SUBTLE))
                        .show(ui, |ui| {
                            egui::ScrollArea::vertical()
                                .id_salt("drawer_console_scroll")
                                .max_height(120.0)
                                .stick_to_bottom(true)
                                .show(ui, |ui| {
                                    ui.set_width(ui.available_width());
                                    if self.log.is_empty() {
                                        ui.label(
                                            RichText::new("No shell output yet.")
                                                .monospace()
                                                .size(12.0)
                                                .color(TEXT_MUTED),
                                        );
                                    } else {
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(&self.log).monospace().size(12.0),
                                            )
                                            .selectable(true),
                                        );
                                    }
                                });
                        });

                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("henosis>").monospace().size(12.0).color(ACCENT));
                        let resp = ui.add(
                            egui::TextEdit::singleline(&mut self.command)
                                .hint_text("Type a shell command (help, list, stats crux.jsonl)…")
                                .desired_width(ui.available_width() - 60.0),
                        );
                        let enter_pressed =
                            resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                        if (enter_pressed || ui.small_button("Run").clicked())
                            && !self.command.trim().is_empty()
                        {
                            let line = std::mem::take(&mut self.command);
                            self.send(line);
                            if enter_pressed {
                                resp.request_focus();
                            }
                        }
                    });
                }
            });
    }

    fn render_settings(&mut self, ui: &mut egui::Ui) {
        card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Workspace Shell Connection").size(14.5).strong());
                if self.backend.is_some() {
                    badge(ui, "Connected", GREEN, GREEN_BG);
                } else {
                    badge(ui, "Disconnected", TEXT_MUTED, crate::theme::BG_NESTED);
                }
            });
            ui.add_space(6.0);
            text_field(
                ui,
                "henosis-shell Binary Path",
                "target/debug/henosis-shell",
                &mut self.shell,
            );
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if self.backend.is_none() {
                    if primary_button(ui, "Connect Shell").clicked() {
                        self.connect();
                    }
                } else {
                    if ui.button("Disconnect").clicked() {
                        self.disconnect();
                    }
                    if ui.button("Refresh Processes").clicked() {
                        self.send("list".into());
                    }
                }
            });
        });

        ui.add_space(10.0);
        card(ui, |ui| {
            ui.label(RichText::new("Active Workspace Files").size(14.5).strong());
            ui.add_space(6.0);
            text_field(ui, "Crux Journal (.jsonl)", "crux.jsonl", &mut self.ws.crux_path);
            text_field(
                ui,
                "Worldline Graph (.json)",
                "worldline.json",
                &mut self.ws.worldline_path,
            );
            text_field(
                ui,
                "Encrypted Keyring (.hnv)",
                "vault.hnv",
                &mut self.ws.vault_path,
            );
            if ui.button("Reload Files Now").clicked() {
                self.ws.invalidate_files();
                self.ws.sync_files_if_changed();
                self.ws.set_ok("Reloaded workspace files.");
            }
        });
    }
}

fn sidebar_item(
    ui: &mut egui::Ui,
    selected: bool,
    label: &str,
    count_badge: Option<&str>,
) -> bool {
    let fill = if selected {
        ACCENT_BG
    } else {
        egui::Color32::TRANSPARENT
    };
    let stroke = if selected {
        Stroke::new(1.0_f32, ACCENT)
    } else {
        Stroke::NONE
    };
    let text_color = if selected {
        egui::Color32::WHITE
    } else {
        TEXT_MUTED
    };

    let desired = egui::vec2(ui.available_width(), 32.0);
    let (rect, response) = ui.allocate_exact_size(desired, egui::Sense::click());
    if ui.is_rect_visible(rect) {
        let bg = if !selected && response.hovered() {
            egui::Color32::from_rgb(28, 33, 44)
        } else {
            fill
        };
        ui.painter().rect(rect, Rounding::same(6.0), bg, stroke);
        let left_pos = egui::pos2(rect.left() + 10.0, rect.center().y);
        ui.painter().text(
            left_pos,
            egui::Align2::LEFT_CENTER,
            label,
            egui::FontId::proportional(13.5),
            if response.hovered() {
                egui::Color32::WHITE
            } else {
                text_color
            },
        );
        if let Some(count) = count_badge {
            let right_pos = egui::pos2(rect.right() - 10.0, rect.center().y);
            ui.painter().text(
                right_pos,
                egui::Align2::RIGHT_CENTER,
                count,
                egui::FontId::proportional(11.5),
                if selected { ACCENT } else { TEXT_MUTED },
            );
        }
    }
    response.clicked()
}

impl eframe::App for Desktop {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.theme_initialized {
            apply_theme(ctx);
            self.theme_initialized = true;
        }

        self.poll();
        let async_changed = self.ws.poll_async();
        self.ws.sync_files_if_changed();

        if self.backend.is_some()
            || self.closing
            || self.ws.running_task.is_some()
            || self.ws.proxy.is_some()
            || async_changed
        {
            ctx.request_repaint_after(Duration::from_millis(100));
        }

        if ctx.input(|i| i.viewport().close_requested()) && self.backend.is_some() {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            if !self.closing {
                self.error.clear();
                self.disconnect();
                self.closing = true;
                self.close_deadline = Some(Instant::now() + Duration::from_secs(5));
            }
        }
        if self.closing && self.finish_close() {
            self.ws.stop_proxy();
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }

        self.render_header(ctx);
        self.render_bottom_drawer(ctx);
        self.render_sidebar(ctx);

        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(crate::theme::BG_CANVAS)
                    .inner_margin(Margin::same(18.0)),
            )
            .show(ctx, |ui| match self.ws.page {
                Page::Crux => views::crux::show(ui, &mut self.ws),
                Page::Worldline => views::worldline::show(ui, &mut self.ws),
                Page::Akashi => views::akashi::show(ui, &mut self.ws),
                Page::VaultProxy => views::vault_proxy::show(ui, &mut self.ws),
                Page::Processes => {
                    let connected = self.backend.is_some();
                    if let Some(act) =
                        views::processes::show(ui, &mut self.ws, connected, &self.processes)
                    {
                        match act {
                            ProcessAction::Connect => self.connect(),
                            ProcessAction::Send(cmd) => self.send(cmd),
                        }
                    }
                }
                Page::Settings => self.render_settings(ui),
            });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1040.0, 680.0])
            .with_min_inner_size([760.0, 480.0]),
        ..eframe::NativeOptions::default()
    };
    eframe::run_native(
        "Henosis",
        options,
        Box::new(|_| {
            let mut app = Desktop::default();
            app.try_autoconnect();
            Ok(Box::new(app))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_failure_keeps_window_open_until_second_close() {
        let mut desktop = Desktop {
            closing: true,
            close_deadline: Some(Instant::now()),
            ..Desktop::default()
        };
        desktop.record_exit(false, "exit status: 1");
        assert!(!desktop.closing);
        assert!(desktop.close_deadline.is_none());
        assert!(desktop.error.contains("exit status: 1"));
        assert!(!desktop.finish_close() || desktop.backend.is_none());
    }

    #[test]
    fn log_stays_bounded_on_char_boundaries() {
        let mut desktop = Desktop::default();
        desktop.append_log(&"測".repeat(MAX_LOG));
        assert!(desktop.log.len() <= MAX_LOG);
        assert!(desktop.log.starts_with('測'));
    }

    #[test]
    fn process_output_updates_and_clears_supervised_list() {
        let mut desktop = Desktop::default();
        desktop.ingest_output_lines("henosis> 1  pid=501  running  /bin/sleep\n");
        assert_eq!(desktop.processes.len(), 1);
        assert!(desktop.processes[0].running);

        desktop.ingest_output_lines("1  pid=501  exited (exit status: 0)  /bin/sleep\n");
        assert_eq!(desktop.processes.len(), 1);
        assert!(!desktop.processes[0].running);

        desktop.ingest_output_lines("henosis> No processes.\n");
        assert!(desktop.processes.is_empty());
    }
}
