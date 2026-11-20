//! Minimalist Supervised Processes view backed by the persistent `henosis-shell` supervisor.
use crate::backend::{encode, ParsedProcess};
use crate::state::WorkspaceData;
use crate::theme::{
    badge, card, empty_state, primary_button, text_field, ACCENT, ACCENT_BG, BG_NESTED, GREEN,
    GREEN_BG, TEXT_MUTED,
};
use eframe::egui::{self, Layout, RichText};

pub enum ProcessAction {
    Connect,
    Send(String),
}

pub fn show(
    ui: &mut egui::Ui,
    ws: &mut WorkspaceData,
    connected: bool,
    processes: &[ParsedProcess],
) -> Option<ProcessAction> {
    let mut action = None;

    if !connected {
        ui.add_space(28.0);
        ui.vertical_centered(|ui| {
            ui.label(
                RichText::new("Process supervisor disconnected")
                    .size(16.0)
                    .strong(),
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new("Connect to henosis-shell to launch and stop supervised children.")
                    .color(TEXT_MUTED),
            );
            ui.add_space(10.0);
            if primary_button(ui, "Connect Shell").clicked() {
                action = Some(ProcessAction::Connect);
            }
        });
        return action;
    }

    card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("Launch Supervised Process")
                    .size(14.0)
                    .strong(),
            );
            ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("Refresh").clicked() {
                    action = Some(ProcessAction::Send("list".into()));
                }
            });
        });
        ui.add_space(4.0);
        ui.columns(2, |cols| {
            text_field(
                &mut cols[0],
                "Absolute Executable Path",
                "/bin/sleep",
                &mut ws.proc_program,
            );
            text_field(
                &mut cols[1],
                "Arguments (optional)",
                "30",
                &mut ws.proc_args,
            );
        });
        ui.horizontal(|ui| {
            ui.checkbox(&mut ws.proc_as_group, "Launch as Unix process group");
            if primary_button(ui, "Launch").clicked() {
                let prog = ws.proc_program.trim();
                if prog.is_empty() {
                    ws.set_err("Enter an absolute executable path.");
                } else {
                    match shell_words::split(&ws.proc_args) {
                        Ok(split_args) => {
                            let verb = if ws.proc_as_group {
                                "launch-group"
                            } else {
                                "launch"
                            };
                            let mut tokens: Vec<&str> = Vec::with_capacity(2 + split_args.len());
                            tokens.push(verb);
                            tokens.push(prog);
                            for a in &split_args {
                                tokens.push(a.as_str());
                            }
                            match encode(&tokens) {
                                Ok(cmd) => {
                                    action = Some(ProcessAction::Send(cmd));
                                }
                                Err(err) => ws.set_err(err),
                            }
                        }
                        Err(err) => ws.set_err(format!("Invalid argument quoting: {err}")),
                    }
                }
            }
        });
    });

    ui.add_space(8.0);
    if processes.is_empty() {
        empty_state(
            ui,
            "No supervised processes",
            "Launched children appear here with one-click Stop and Stop Group controls.",
        );
        return action;
    }

    egui::ScrollArea::vertical()
        .id_salt("processes_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for proc in processes {
                card(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        badge(ui, format!("#{}", proc.id), ACCENT, ACCENT_BG);
                        if proc.running {
                            badge(ui, "Running", GREEN, GREEN_BG);
                        } else {
                            badge(ui, &proc.state_label, TEXT_MUTED, BG_NESTED);
                        }
                        ui.label(
                            RichText::new(format!("PID {}", proc.pid))
                                .monospace()
                                .size(12.0)
                                .color(TEXT_MUTED),
                        );
                        ui.label(RichText::new(&proc.program).monospace().size(13.0).strong());

                        if proc.running {
                            ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                                if ui.small_button("Stop Group").clicked() {
                                    let id_str = proc.id.to_string();
                                    if let Ok(cmd) = encode(&["stop-group", &id_str]) {
                                        action = Some(ProcessAction::Send(cmd));
                                    }
                                }
                                if ui.small_button("Stop").clicked() {
                                    let id_str = proc.id.to_string();
                                    if let Ok(cmd) = encode(&["stop", &id_str]) {
                                        action = Some(ProcessAction::Send(cmd));
                                    }
                                }
                            });
                        }
                    });
                });
                ui.add_space(6.0);
            }
        });

    action
}
