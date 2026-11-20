//! Minimalist Crux journal view: interactive proposal cards, inline actions, and recovery.
use crate::state::{CruxFilter, CruxInlinePanel, ProposalCard, WorkspaceData};
use crate::theme::{
    badge, card, empty_state, nested_card, pill_toggle, primary_button, text_field, ACCENT,
    ACCENT_BG, AMBER, AMBER_BG, GREEN, GREEN_BG, RED, RED_BG, TEXT_MUTED,
};
use eframe::egui::{self, Layout, RichText};
use henosis_crux::Event as CruxEvent;

pub fn show(ui: &mut egui::Ui, ws: &mut WorkspaceData) {
    // Top action & filter strip
    ui.horizontal_wrapped(|ui| {
        if primary_button(
            ui,
            if ws.crux_new_open {
                "Close New Crux"
            } else {
                "+ New Crux"
            },
        )
        .clicked()
        {
            ws.crux_new_open = !ws.crux_new_open;
        }

        ui.add_space(6.0);
        for (filter, label) in [
            (CruxFilter::Open, "Open"),
            (CruxFilter::Ranked, "Priority"),
            (CruxFilter::Closed, "Closed"),
            (CruxFilter::All, "All"),
        ] {
            if pill_toggle(ui, ws.crux_filter == filter, label).clicked() {
                ws.crux_filter = filter;
            }
        }

        ui.add(
            egui::TextEdit::singleline(&mut ws.crux_search)
                .hint_text("Search goals or hypotheses…")
                .desired_width(190.0),
        );

        if let Some(drift) = &ws.crux.drift {
            if drift.total > 0 {
                let issues = drift.changed + drift.missing;
                if issues == 0 {
                    badge(
                        ui,
                        format!("{} artifact(s) intact", drift.unchanged),
                        GREEN,
                        GREEN_BG,
                    );
                } else {
                    badge(ui, format!("{issues} artifact(s) drifted"), AMBER, AMBER_BG);
                }
            }
        }
    });

    if let Some(err) = &ws.crux.load_error {
        ui.add_space(6.0);
        card(ui, |ui| {
            ui.colored_label(RED, format!("Cannot read {}: {err}", ws.crux_path));
        });
        return;
    }

    // Inline "+ New Crux" composer card
    if ws.crux_new_open {
        ui.add_space(8.0);
        card(ui, |ui| {
            ui.label(RichText::new("New Crux Proposal").size(14.0).strong());
            ui.add_space(4.0);
            text_field(
                ui,
                "Goal",
                "What outcome are you trying to achieve?",
                &mut ws.crux_goal,
            );
            text_field(
                ui,
                "Hypothesis",
                "What load-bearing assumption could fail?",
                &mut ws.crux_hypothesis,
            );
            text_field(
                ui,
                "Falsification Test",
                "Concrete experiment that can disprove it",
                &mut ws.crux_test,
            );
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                if primary_button(ui, "Save Proposal").clicked() {
                    ws.create_proposal();
                }
                if ui.button("Cancel").clicked() {
                    ws.crux_new_open = false;
                }
            });
        });
    }

    // Unfinished attempts recovery banner
    if !ws.crux.unfinished.is_empty() {
        ui.add_space(8.0);
        let unfinished = ws.crux.unfinished.clone();
        card(ui, |ui| {
            ui.horizontal(|ui| {
                badge(ui, "Needs Review", AMBER, AMBER_BG);
                ui.label(
                    RichText::new(format!(
                        "{} unfinished test attempt(s) without a recorded result",
                        unfinished.len()
                    ))
                    .strong(),
                );
            });
            for (attempt_id, proposal_id) in unfinished {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!("Attempt #{attempt_id} (Proposal #{proposal_id})"))
                            .color(TEXT_MUTED),
                    );
                    let note = ws.crux_review_notes.entry(attempt_id).or_default();
                    ui.add(
                        egui::TextEdit::singleline(note)
                            .hint_text("What happened? Record recovery note…")
                            .desired_width(260.0),
                    );
                    if ui.button("Save Note").clicked() {
                        ws.review_unfinished_attempt(proposal_id, attempt_id);
                    }
                });
            }
        });
    }

    if !ws.crux.exists || ws.crux.proposals.is_empty() {
        empty_state(
            ui,
            "No Crux proposals yet",
            "Click '+ New Crux' to record a goal, a falsifiable hypothesis, and a test.",
        );
        return;
    }

    // Filter & order cards
    let query = ws.crux_search.trim().to_ascii_lowercase();
    let mut cards: Vec<ProposalCard> = ws
        .crux
        .proposals
        .iter()
        .filter(|c| match ws.crux_filter {
            CruxFilter::Open => !c.closed,
            CruxFilter::Ranked => !c.closed && c.rank_position.is_some(),
            CruxFilter::Closed => c.closed,
            CruxFilter::All => true,
        })
        .filter(|c| {
            query.is_empty()
                || c.goal.to_ascii_lowercase().contains(&query)
                || c.hypothesis.to_ascii_lowercase().contains(&query)
                || c.test.to_ascii_lowercase().contains(&query)
        })
        .cloned()
        .collect();

    if ws.crux_filter == CruxFilter::Ranked {
        cards.sort_by_key(|c| c.rank_position.unwrap_or(usize::MAX));
    } else {
        cards.reverse();
    }

    ui.add_space(8.0);
    egui::ScrollArea::vertical()
        .id_salt("crux_cards_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if cards.is_empty() {
                empty_state(
                    ui,
                    "No matching proposals",
                    "Try switching filters or clearing search.",
                );
            }
            for item in cards {
                render_proposal_card(ui, ws, &item);
                ui.add_space(8.0);
            }

            // Compact snapshot footer
            if ws.crux.exists {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Snapshot:").size(12.0).color(TEXT_MUTED));
                    ui.add(
                        egui::TextEdit::singleline(&mut ws.crux_backup_dest)
                            .hint_text("backup.jsonl")
                            .desired_width(180.0),
                    );
                    if ui.small_button("Save Backup").clicked() {
                        ws.backup_crux_journal();
                    }
                });
            }
        });
}

fn render_proposal_card(ui: &mut egui::Ui, ws: &mut WorkspaceData, item: &ProposalCard) {
    card(ui, |ui| {
        ui.horizontal(|ui| {
            badge(ui, format!("#{}", item.id), ACCENT, ACCENT_BG);
            if item.closed {
                badge(ui, "Closed", TEXT_MUTED, crate::theme::BG_NESTED);
            } else {
                badge(ui, "Open", GREEN, GREEN_BG);
            }
            if let Some(pos) = item.rank_position {
                badge(ui, format!("Rank #{pos}"), AMBER, AMBER_BG);
            }
            if let Some((info, fail, cost)) = item.latest_score {
                let ratio = f64::from(info) * f64::from(fail) / f64::from(cost.max(1));
                ui.label(
                    RichText::new(format!("Score {ratio:.1} ({info}×{fail}/{cost})"))
                        .size(12.0)
                        .color(TEXT_MUTED),
                );
            }
        });

        ui.add_space(4.0);
        ui.label(RichText::new(&item.goal).size(15.0).strong());
        ui.label(RichText::new(format!("Hypothesis: {}", item.hypothesis)).size(13.0));
        ui.label(
            RichText::new(format!("Test: {}", item.test))
                .size(12.5)
                .color(TEXT_MUTED),
        );

        ui.add_space(6.0);
        ui.horizontal_wrapped(|ui| {
            let obs_active = ws.crux_inline == Some(CruxInlinePanel::Observe(item.id));
            if pill_toggle(ui, obs_active, "Observe").clicked() {
                ws.crux_inline = if obs_active {
                    None
                } else {
                    Some(CruxInlinePanel::Observe(item.id))
                };
            }

            let score_active = ws.crux_inline == Some(CruxInlinePanel::Score(item.id));
            if pill_toggle(ui, score_active, "Score").clicked() {
                if let Some((i, f, c)) = item.latest_score {
                    ws.crux_info_score = i;
                    ws.crux_fail_score = f;
                    ws.crux_cost_score = c;
                }
                ws.crux_inline = if score_active {
                    None
                } else {
                    Some(CruxInlinePanel::Score(item.id))
                };
            }

            let run_active = ws.crux_inline == Some(CruxInlinePanel::Run(item.id));
            if pill_toggle(ui, run_active, "Run Test").clicked() {
                ws.crux_inline = if run_active {
                    None
                } else {
                    Some(CruxInlinePanel::Run(item.id))
                };
            }

            let close_label = if item.closed { "Reopen" } else { "Close" };
            let close_active = ws.crux_inline == Some(CruxInlinePanel::Close(item.id));
            if pill_toggle(ui, close_active, close_label).clicked() {
                ws.crux_inline = if close_active {
                    None
                } else {
                    Some(CruxInlinePanel::Close(item.id))
                };
            }

            if !item.history.is_empty() {
                let expanded = ws.crux_expanded_history.contains(&item.id);
                let hist_label = if expanded {
                    format!("Hide Activity ({})", item.history.len())
                } else {
                    format!("Activity ({})", item.history.len())
                };
                ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button(hist_label).clicked() {
                        if expanded {
                            ws.crux_expanded_history.remove(&item.id);
                        } else {
                            ws.crux_expanded_history.insert(item.id);
                        }
                    }
                });
            }
        });

        // Inline action panel
        match ws.crux_inline.clone() {
            Some(CruxInlinePanel::Observe(id)) if id == item.id => {
                ui.add_space(6.0);
                nested_card(ui, |ui| {
                    text_field(
                        ui,
                        "Outcome",
                        "What did you observe?",
                        &mut ws.crux_outcome_draft,
                    );
                    ui.horizontal(|ui| {
                        if primary_button(ui, "Record Observation").clicked() {
                            ws.record_observation(item.id);
                        }
                        if ui.button("Cancel").clicked() {
                            ws.crux_inline = None;
                        }
                    });
                });
            }
            Some(CruxInlinePanel::Score(id)) if id == item.id => {
                ui.add_space(6.0);
                nested_card(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.add(
                            egui::Slider::new(&mut ws.crux_info_score, 1..=5).text("Information"),
                        );
                        ui.add(
                            egui::Slider::new(&mut ws.crux_fail_score, 1..=5).text("Failure Risk"),
                        );
                        ui.add(egui::Slider::new(&mut ws.crux_cost_score, 1..=5).text("Cost"));
                    });
                    ui.horizontal(|ui| {
                        if primary_button(ui, "Save Score").clicked() {
                            ws.record_assessment(item.id);
                        }
                        if ui.button("Cancel").clicked() {
                            ws.crux_inline = None;
                        }
                    });
                });
            }
            Some(CruxInlinePanel::Run(id)) if id == item.id => {
                ui.add_space(6.0);
                nested_card(ui, |ui| {
                    ui.columns(2, |cols| {
                        text_field(
                            &mut cols[0],
                            "Project Directory",
                            ".",
                            &mut ws.crux_run_project,
                        );
                        text_field(
                            &mut cols[1],
                            "Tracked Artifact (relative file)",
                            "Cargo.toml",
                            &mut ws.crux_run_artifact,
                        );
                    });
                    ui.columns(3, |cols| {
                        text_field(
                            &mut cols[0],
                            "Executable",
                            "/usr/bin/cargo",
                            &mut ws.crux_run_program,
                        );
                        text_field(
                            &mut cols[1],
                            "Arguments",
                            "test --quiet",
                            &mut ws.crux_run_args,
                        );
                        text_field(&mut cols[2], "Expected Exit", "0", &mut ws.crux_run_exit);
                    });
                    text_field(
                        ui,
                        "Forwarded Env Names (optional, comma-separated)",
                        "PATH, RUST_LOG",
                        &mut ws.crux_run_env_keys,
                    );
                    ui.horizontal(|ui| {
                        let enabled = ws.running_task.is_none();
                        if ui
                            .add_enabled(
                                enabled,
                                egui::Button::new(
                                    RichText::new("Execute Trusted Test")
                                        .color(egui::Color32::WHITE)
                                        .strong(),
                                )
                                .fill(crate::theme::ACCENT_FILL),
                            )
                            .clicked()
                        {
                            ws.start_crux_experiment(item.id);
                        }
                        if ui.button("Cancel").clicked() {
                            ws.crux_inline = None;
                        }
                    });
                });
            }
            Some(CruxInlinePanel::Close(id)) if id == item.id => {
                ui.add_space(6.0);
                nested_card(ui, |ui| {
                    let target_closed = !item.closed;
                    text_field(
                        ui,
                        "Reason",
                        if target_closed {
                            "Why close this proposal?"
                        } else {
                            "Why reopen this proposal?"
                        },
                        &mut ws.crux_close_reason,
                    );
                    ui.horizontal(|ui| {
                        let btn = if target_closed {
                            "Confirm Close"
                        } else {
                            "Confirm Reopen"
                        };
                        if primary_button(ui, btn).clicked() {
                            let reason = ws.crux_close_reason.clone();
                            ws.set_proposal_closed(item.id, target_closed, reason);
                        }
                        if ui.button("Cancel").clicked() {
                            ws.crux_inline = None;
                        }
                    });
                });
            }
            _ => {}
        }

        // Expandable activity timeline
        if ws.crux_expanded_history.contains(&item.id) {
            ui.add_space(6.0);
            nested_card(ui, |ui| {
                let mut jump_result = None;
                for (ev_id, ev) in &item.history {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new(format!("#{ev_id}"))
                                .monospace()
                                .size(11.5)
                                .color(TEXT_MUTED),
                        );
                        match ev {
                            CruxEvent::Observed { outcome, .. } => {
                                ui.label(format!("Observed: {outcome}"));
                            }
                            CruxEvent::Assessed {
                                information,
                                failure,
                                cost,
                                ..
                            } => {
                                ui.label(format!(
                                    "Scored info={information}, failure={failure}, cost={cost}"
                                ));
                            }
                            CruxEvent::StatusChanged { closed, reason, .. } => {
                                let tag = if *closed { "Closed" } else { "Reopened" };
                                ui.label(format!("{tag}: {reason}"));
                            }
                            CruxEvent::ExperimentStarted { request, .. } => {
                                ui.label(format!(
                                    "Started {} {:?}",
                                    request.program, request.arguments
                                ));
                            }
                            CruxEvent::ExperimentFailed { error, .. } => {
                                ui.colored_label(RED, format!("Runner error: {error}"));
                            }
                            CruxEvent::AttemptReviewed { attempt, note, .. } => {
                                ui.label(format!("Reviewed attempt #{attempt}: {note}"));
                            }
                            CruxEvent::CommandResult { evidence, .. } => {
                                let matched = !evidence.timed_out
                                    && evidence.exit_code == Some(evidence.expected_exit);
                                if matched {
                                    badge(ui, "Exit Matched", GREEN, GREEN_BG);
                                } else {
                                    badge(ui, "Mismatch / Timeout", RED, RED_BG);
                                }
                                ui.label(format!(
                                    "{} (artifact: {})",
                                    evidence.program, evidence.artifact
                                ));
                                if matched
                                    && evidence.artifact_sha256.is_some()
                                    && ui.small_button("Verify in Akashi →").clicked()
                                {
                                    jump_result = Some(*ev_id);
                                }
                            }
                            CruxEvent::Proposed { .. } => {}
                        }
                    });
                }
                if let Some(rid) = jump_result {
                    ws.jump_to_akashi(None, Some(rid));
                }
            });
        }
    });
}
