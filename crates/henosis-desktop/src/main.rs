#![deny(unsafe_code)]

mod backend;

use backend::{encode, Backend};
use eframe::egui;
use std::path::PathBuf;
use std::time::Duration;

const OUTPUT_LIMIT: usize = 200_000;
const JOURNAL_ACTIONS: &[(&str, &[&str])] = &[
    ("journal", &[]), ("propose", &["Goal", "Hypothesis", "Test"]),
    ("observe", &["Proposal ID", "Outcome"]),
    ("assess", &["Proposal ID", "Information (1–5)", "Failure concern (1–5)", "Cost (1–5)"]),
    ("rank", &[]), ("show", &["Proposal ID"]),
    ("close", &["Proposal ID", "Reason"]), ("reopen", &["Proposal ID", "Reason"]),
    ("pending", &[]), ("stats", &[]), ("search", &["Pattern"]),
];
const DAG_ACTIONS: &[(&str, &[&str])] = &[
    ("state", &[]), ("init", &[]), ("log", &[]), ("verifyall", &[]),
    ("branch", &["Branch name"]), ("checkout", &["Branch name"]),
    ("merge", &["Source branch", "Rationale"]), ("tag", &["Tag name", "Commit ID"]),
];

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Henosis — local workspace").with_inner_size([1120.0, 800.0])
            .with_min_inner_size([760.0, 600.0]),
        ..Default::default()
    };
    eframe::run_native("Henosis", options, Box::new(|cc| {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        Ok(Box::new(Desktop::default()))
    }))
}

struct Desktop {
    backend: Option<Backend>,
    backend_path: String,
    page: usize,
    action: usize,
    fields: Vec<String>,
    journal: String,
    worldline: String,
    program: String,
    arguments: String,
    process_id: String,
    console: String,
    output: String,
    error: String,
    closing: bool,
    exited: bool,
}

impl Default for Desktop {
    fn default() -> Self {
        let binary = if cfg!(windows) { "henosis-shell.exe" } else { "henosis-shell" };
        let sibling = std::env::current_exe().ok().and_then(|p| p.parent().map(|p| p.join(binary)));
        Self {
            backend: None,
            backend_path: sibling.unwrap_or_else(|| PathBuf::from(binary)).display().to_string(),
            page: 0, action: 0, fields: vec![String::new(); 5],
            journal: "crux.jsonl".into(), worldline: "worldline.json".into(),
            program: String::new(), arguments: String::new(), process_id: String::new(),
            console: String::new(), output: String::new(), error: String::new(),
            closing: false, exited: false,
        }
    }
}

impl Desktop {
    fn append(&mut self, text: &str) {
        // Make terminal controls visible; this is a text view, not a terminal.
        for c in text.chars() {
            if c.is_control() && c != '\n' && c != '\t' { self.output.extend(c.escape_default()); }
            else { self.output.push(c); }
        }
        if self.output.len() > OUTPUT_LIMIT {
            let mut cut = self.output.len() - OUTPUT_LIMIT;
            while !self.output.is_char_boundary(cut) { cut += 1; }
            self.output.drain(..cut);
        }
    }

    fn send(&mut self, result: Result<String, String>) {
        self.error.clear();
        let result = result.and_then(|line| {
            self.backend.as_ref().ok_or_else(|| "Start the workspace first.".to_string())?.send(line)
        });
        if let Err(error) = result { self.error = error; }
    }

    fn process_form(&mut self, ui: &mut egui::Ui) {
        ui.heading("Process workspace");
        ui.label("Launch trusted executables with an empty environment. No OS shell is invoked.");
        field(ui, "Absolute executable path", &mut self.program);
        field(ui, "Arguments (shell-style quoting)", &mut self.arguments);
        ui.horizontal(|ui| {
            if ui.button("Launch process").clicked() {
                let result = if !PathBuf::from(&self.program).is_absolute() {
                    Err("Choose an absolute executable path.".into())
                } else {
                    shell_words::split(&self.arguments).map_err(|e| e.to_string()).and_then(|args| {
                        let mut words = vec!["launch", self.program.as_str()];
                        words.extend(args.iter().map(String::as_str));
                        encode(&words)
                    })
                };
                self.send(result);
            }
            if ui.button("Refresh process list").clicked() { self.send(encode(&["list"])); }
        });
        ui.separator();
        field(ui, "Henosis process ID (from the list, not the OS PID)", &mut self.process_id);
        ui.horizontal(|ui| {
            if ui.button("Stop direct child").clicked() {
                self.send(encode(&["stop", &self.process_id]));
            }
            if cfg!(unix) && ui.button("Stop Unix process group").clicked() {
                self.send(encode(&["stop-group", &self.process_id]));
            }
        });
        ui.label("Exit stops direct children, not all descendants. Group stopping is best effort on Unix.");
    }

    fn record_form(&mut self, ui: &mut egui::Ui) {
        let dag = self.page == 2;
        ui.heading(if dag { "Worldline" } else { "Crux journal" });
        ui.label(if dag { "Inspect and manage the existing Merkle-DAG workspace." }
            else { "Local plaintext records. Proposals and observations are user assertions, not verified capability." });
        field(ui, "File path (relative to the desktop's working directory or absolute)",
            if dag { &mut self.worldline } else { &mut self.journal });
        let actions = if dag { DAG_ACTIONS } else { JOURNAL_ACTIONS };
        let previous = self.action;
        egui::ComboBox::from_label("Action").selected_text(actions[self.action].0).show_ui(ui, |ui| {
            for (i, (name, _)) in actions.iter().enumerate() { ui.selectable_value(&mut self.action, i, *name); }
        });
        if previous != self.action { self.fields.iter_mut().for_each(String::clear); }
        let (command, labels) = actions[self.action];
        for (value, label) in self.fields.iter_mut().zip(labels.iter()) { field(ui, label, value); }
        if ui.button(format!("Run {command}")).clicked() {
            let path = if dag { &self.worldline } else { &self.journal };
            let result = if path.trim().is_empty() || self.fields[..labels.len()].iter().any(|s| s.trim().is_empty()) {
                Err("Fill in all fields before submitting.".into())
            } else {
                let mut words = if dag { vec!["dag", command, path.as_str()] } else { vec![command, path.as_str()] };
                words.extend(self.fields[..labels.len()].iter().map(String::as_str));
                encode(&words)
            };
            self.send(result);
        }
        ui.label("Results and backend validation errors appear in Workspace output below. Inspect errors before retrying writes.");
    }
}

fn field(ui: &mut egui::Ui, label: &str, value: &mut String) {
    ui.label(label);
    ui.add(egui::TextEdit::singleline(value).desired_width(f32::INFINITY));
    ui.add_space(5.0);
}

impl eframe::App for Desktop {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.request_repaint_after(Duration::from_millis(100));
        let chunks: Vec<_> = self.backend.as_ref().map(|b| b.output.try_iter().take(64).collect()).unwrap_or_default();
        for chunk in chunks { self.append(&chunk); }
        if let Some(backend) = &mut self.backend {
            match backend.child.try_wait() {
                Ok(Some(status)) if !self.exited => {
                    self.exited = true;
                    self.append(&format!("\nWorkspace exited: {status}\n"));
                }
                Err(error) => self.error = format!("Cannot inspect workspace: {error}"),
                _ => {}
            }
        }
        if ctx.input(|i| i.viewport().close_requested()) && self.backend.is_some() && !self.exited {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.closing = true;
            if let Some(backend) = &self.backend { backend.close(); }
        }
        if self.closing && self.exited { ctx.send_viewport_cmd(egui::ViewportCommand::Close); }

        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.heading("HENOSIS");
                ui.label("/ local workspace");
                ui.separator();
                ui.label(if self.closing { "Closing — waiting for workspace cleanup…" }
                    else if self.exited { "Workspace stopped" }
                    else if self.backend.is_some() { "Workspace running" } else { "Not connected" });
            });
            ui.label(egui::RichText::new("Not a sandbox. Children can access files and the network. Run only trusted software.").color(egui::Color32::from_rgb(235, 186, 105)));
            ui.add_space(8.0);
        });
        egui::SidePanel::left("navigation").exact_width(160.0).show(ctx, |ui| {
            ui.add_space(12.0);
            for (i, title) in ["Processes", "Crux journal", "Worldline", "Console", "Connection"].iter().enumerate() {
                if ui.selectable_label(self.page == i, *title).clicked() {
                    self.page = i; self.action = 0; self.fields.iter_mut().for_each(String::clear);
                }
                ui.add_space(8.0);
            }
            ui.separator();
            ui.label("Local-first • experimental");
            ui.label("No UI state or console history is saved.");
        });
        egui::TopBottomPanel::bottom("output").resizable(true).default_height(280.0).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.strong("Workspace output");
                ui.label("(bounded, stdout and stderr interleaved)");
                if ui.small_button("Clear").clicked() { self.output.clear(); }
            });
            egui::ScrollArea::both().stick_to_bottom(true).show(ui, |ui| {
                ui.add(egui::TextEdit::multiline(&mut self.output).font(egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY).interactive(false));
            });
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            if !self.error.is_empty() { ui.colored_label(egui::Color32::LIGHT_RED, &self.error); ui.separator(); }
            if self.closing {
                ui.heading("Stopping workspace safely");
                ui.label("Pending commands finish before EOF triggers cleanup. Long-running experiments can delay exit. The supervisor is not force-killed.");
                return;
            }
            if self.backend.is_none() && self.page != 4 {
                ui.label("Start the Rust backend in Connection to begin.");
                if ui.button("Open connection settings").clicked() { self.page = 4; }
                ui.separator();
            }
            egui::ScrollArea::vertical().show(ui, |ui| {
                match self.page {
                    0 => self.process_form(ui),
                    1 | 2 => self.record_form(ui),
                    3 => {
                        ui.heading("Advanced workspace console");
                        ui.label("Uses the same commands as the CLI; no OS shell is invoked.");
                        ui.colored_label(egui::Color32::YELLOW, "Do not enter passwords, mnemonics, or credentials here. Commands and responses are visible in memory/on screen.");
                        field(ui, "Command", &mut self.console);
                        ui.horizontal(|ui| {
                            if ui.button("Send command").clicked() {
                                let line = self.console.clone(); self.send(Ok(line));
                                if self.error.is_empty() { self.console.clear(); }
                            }
                            if ui.button("Command reference").clicked() { self.send(encode(&["help"])); }
                        });
                    }
                    _ => {
                        ui.heading("Workspace connection");
                        ui.label("Build both binaries, then select henosis-shell. A sibling binary is selected by default.");
                        field(ui, "Rust backend executable", &mut self.backend_path);
                        ui.label(format!("Working directory: {}", std::env::current_dir().unwrap_or_default().display()));
                        if ui.add_enabled(self.backend.is_none() || self.exited, egui::Button::new("Start workspace")).clicked() {
                            match Backend::start(&PathBuf::from(&self.backend_path)) {
                                Ok(backend) => { self.backend = Some(backend); self.exited = false; self.error.clear(); }
                                Err(error) => self.error = format!("Cannot start backend: {error}"),
                            }
                        }
                        ui.label("The GUI inherits the normal desktop environment; the Rust launcher clears the environment for launched children. No additional isolation is provided.");
                    }
                }
            });
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn output_is_bounded_unicode_and_controls_are_visible() {
        let mut app = Desktop::default();
        app.append(&"測".repeat(OUTPUT_LIMIT));
        assert!(app.output.len() <= OUTPUT_LIMIT);
        app.append("\x1b[31m\n");
        assert!(app.output.ends_with("\\u{1b}[31m\n"));
    }
}
