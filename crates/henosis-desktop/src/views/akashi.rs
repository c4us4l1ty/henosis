//! Minimalist Akashi verification view: evidence, written proofs, perturbation, and .hcap bundles.
use crate::state::{AkashiMethod, WorkspaceData, PROOF_OPERATORS, PROVENANCES};
use crate::theme::{
    badge, card, empty_state, nested_card, pill_toggle, primary_button, text_field, ACCENT,
    ACCENT_BG, AMBER, AMBER_BG, BG_NESTED, GREEN, GREEN_BG, TEXT_MUTED,
};
use eframe::egui::{self, RichText};

pub fn show(ui: &mut egui::Ui, ws: &mut WorkspaceData) {
    // Method selector pills
    ui.horizontal_wrapped(|ui| {
        for (method, label) in [
            (AkashiMethod::CommandResult, "Command Evidence"),
            (AkashiMethod::WrittenArtifact, "Written Proof"),
            (AkashiMethod::PerturbationSuite, "Perturbation Suite"),
            (AkashiMethod::BundleTransfer, ".hcap Bundle"),
        ] {
            if pill_toggle(ui, ws.akashi_method == method, label).clicked() {
                ws.akashi_method = method;
            }
        }
    });

    ui.add_space(8.0);
    egui::ScrollArea::vertical()
        .id_salt("akashi_main_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            // Shared target node + provenance header card
            card(ui, |ui| {
                ui.columns(2, |cols| {
                    cols[0].label(RichText::new("Capability Node ID").size(12.0).color(TEXT_MUTED));
                    cols[0].horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut ws.akashi_node_id)
                                .hint_text("cap-lockfree-queue")
                                .desired_width(180.0),
                        );
                        if !ws.worldline.state.nodes.is_empty() {
                            egui::ComboBox::from_id_salt("akashi_pick_node")
                                .selected_text("Pick existing")
                                .show_ui(ui, |ui| {
                                    for nid in ws.worldline.state.nodes.keys() {
                                        ui.selectable_value(
                                            &mut ws.akashi_node_id,
                                            nid.clone(),
                                            nid,
                                        );
                                    }
                                });
                        }
                    });

                    cols[1].label(RichText::new("Provenance").size(12.0).color(TEXT_MUTED));
                    let current_prov_label = PROVENANCES[ws.akashi_provenance_idx].1;
                    egui::ComboBox::from_id_salt("akashi_provenance")
                        .selected_text(current_prov_label)
                        .show_ui(&mut cols[1], |ui| {
                            for (idx, (_, label)) in PROVENANCES.iter().enumerate() {
                                ui.selectable_value(&mut ws.akashi_provenance_idx, idx, *label);
                            }
                        });
                });

                if let Some(receipt) = &ws.last_blackout_receipt {
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.checkbox(
                            &mut ws.akashi_attach_blackout,
                            format!(
                                "Attach Blackout Receipt #{} ({} blocked, {} forwarded)",
                                receipt.window_id,
                                receipt.blocked_attempts,
                                receipt.forwarded_requests
                            ),
                        );
                        if receipt.signature_hex.is_some() {
                            badge(ui, "Signed", GREEN, GREEN_BG);
                        }
                    });
                }
            });

            ui.add_space(8.0);

            match ws.akashi_method {
                AkashiMethod::CommandResult => show_command_result_card(ui, ws),
                AkashiMethod::WrittenArtifact => show_written_proof_card(ui, ws),
                AkashiMethod::PerturbationSuite => show_perturbation_card(ui, ws),
                AkashiMethod::BundleTransfer => show_bundle_card(ui, ws),
            }

            // Recent verifications list
            ui.add_space(12.0);
            let mut recent = ws.worldline.state.verifications.clone();
            recent.reverse();
            if recent.is_empty() {
                empty_state(
                    ui,
                    "No verifications recorded yet",
                    "Verified capabilities promote Worldline nodes and credit H when unassisted.",
                );
            } else {
                ui.label(RichText::new("Recent Verifications").size(13.5).strong());
                ui.add_space(4.0);
                for v in recent.into_iter().take(12) {
                    card(ui, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            badge(ui, &v.node_id, ACCENT, ACCENT_BG);
                            badge(ui, v.operator.as_str(), GREEN, GREEN_BG);
                            badge(ui, v.provenance.as_str(), TEXT_MUTED, BG_NESTED);
                            if v.proxy_blackout_verified {
                                badge(ui, "Blackout Attested", GREEN, GREEN_BG);
                            }
                        });
                        ui.add_space(3.0);
                        ui.label(RichText::new(&v.summary).size(13.0));
                    });
                    ui.add_space(6.0);
                }
            }
        });
}

fn show_operator_picker(ui: &mut egui::Ui, ws: &mut WorkspaceData) {
    ui.label(RichText::new("Proof Operator").size(12.0).color(TEXT_MUTED));
    ui.horizontal_wrapped(|ui| {
        for (idx, op) in PROOF_OPERATORS.iter().enumerate() {
            if pill_toggle(ui, ws.akashi_operator_idx == idx, op.as_str()).clicked() {
                ws.akashi_operator_idx = idx;
            }
        }
    });
}

fn show_command_result_card(ui: &mut egui::Ui, ws: &mut WorkspaceData) {
    card(ui, |ui| {
        ui.label(RichText::new("Verify from Crux Command Evidence").size(14.0).strong());
        ui.add_space(4.0);
        show_operator_picker(ui, ws);
        ui.add_space(4.0);

        ui.label(RichText::new("Recorded Command Result").size(12.0).color(TEXT_MUTED));
        if ws.crux.command_results.is_empty() {
            ui.colored_label(
                AMBER,
                "No command results in Crux yet. Run a test on a Crux card first.",
            );
        } else {
            let selected_label = ws
                .akashi_selected_result_id
                .and_then(|sel| {
                    ws.crux
                        .command_results
                        .iter()
                        .find(|(id, _, _)| *id == sel)
                        .map(|(id, prop, ev)| {
                            format!("#{id} (Proposal #{prop}: {} → {})", ev.program, ev.artifact)
                        })
                })
                .unwrap_or_else(|| "Select result…".into());

            egui::ComboBox::from_id_salt("akashi_cmd_result")
                .selected_text(selected_label)
                .show_ui(ui, |ui| {
                    for (id, prop, ev) in &ws.crux.command_results {
                        let ok = !ev.timed_out && ev.exit_code == Some(ev.expected_exit);
                        let tag = if ok { "OK" } else { "FAIL" };
                        let text = format!(
                            "#{id} [{tag}] Proposal #{prop}: {} ({})",
                            ev.program, ev.artifact
                        );
                        ui.selectable_value(&mut ws.akashi_selected_result_id, Some(*id), text);
                    }
                });
        }

        text_field(
            ui,
            "Summary (optional)",
            "Concise statement of what this run demonstrated",
            &mut ws.akashi_summary,
        );
        ui.add_space(4.0);
        if primary_button(ui, "Verify & Record in Worldline").clicked() {
            ws.akashi_verify_command_result();
        }
    });
}

fn show_written_proof_card(ui: &mut egui::Ui, ws: &mut WorkspaceData) {
    card(ui, |ui| {
        ui.label(
            RichText::new("Verify Written Derivation / Explanation / Critique")
                .size(14.0)
                .strong(),
        );
        ui.add_space(4.0);
        show_operator_picker(ui, ws);
        ui.add_space(4.0);

        ui.label(RichText::new("Written Proof Artifact").size(12.0).color(TEXT_MUTED));
        ui.add(
            egui::TextEdit::multiline(&mut ws.akashi_written_text)
                .hint_text("Write your unassisted derivation, invariant proof, or critique…")
                .desired_rows(5)
                .desired_width(f32::INFINITY),
        );
        text_field(
            ui,
            "Summary (optional)",
            "One-line summary for Worldline commit",
            &mut ws.akashi_summary,
        );
        ui.add_space(4.0);
        if primary_button(ui, "Hash & Record Verification").clicked() {
            ws.akashi_verify_written();
        }
    });
}

fn show_perturbation_card(ui: &mut egui::Ui, ws: &mut WorkspaceData) {
    card(ui, |ui| {
        ui.label(
            RichText::new("Perturbation Suite (PredictFailure)")
                .size(14.0)
                .strong(),
        );
        ui.add_space(4.0);
        ui.columns(2, |cols| {
            text_field(
                &mut cols[0],
                "Cases JSON Path",
                "perturb.json",
                &mut ws.akashi_perturb_cases_path,
            );
            text_field(
                &mut cols[1],
                "Project Directory",
                ".",
                &mut ws.akashi_perturb_project_dir,
            );
        });
        text_field(
            ui,
            "Summary (optional)",
            "Boundary failure prediction summary",
            &mut ws.akashi_summary,
        );

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let can_run = ws.running_task.is_none();
            if ui
                .add_enabled(
                    can_run,
                    egui::Button::new(
                        RichText::new("1. Run Perturbation Suite")
                            .color(egui::Color32::WHITE)
                            .strong(),
                    )
                    .fill(crate::theme::ACCENT_FILL),
                )
                .clicked()
            {
                ws.akashi_run_perturbation();
            }

            if ws.akashi_last_perturb.is_some()
                && primary_button(ui, "2. Promote to PredictFailure").clicked()
            {
                ws.akashi_verify_from_last_perturb();
            }
        });

        if let Some(report) = &ws.akashi_last_perturb {
            ui.add_space(6.0);
            nested_card(ui, |ui| {
                let all_accurate = report.accurate_predictions == report.outcomes.len()
                    && !report.outcomes.is_empty();
                ui.horizontal(|ui| {
                    if all_accurate {
                        badge(ui, "100% Predicted", GREEN, GREEN_BG);
                    } else {
                        badge(ui, "Prediction Gap", AMBER, AMBER_BG);
                    }
                    ui.label(format!(
                        "{}/{} cases matched prediction · {} failure(s) exposed",
                        report.accurate_predictions,
                        report.outcomes.len(),
                        report.exposed_failures.len()
                    ));
                });
            });
        }
    });
}

fn show_bundle_card(ui: &mut egui::Ui, ws: &mut WorkspaceData) {
    card(ui, |ui| {
        ui.label(RichText::new("Portable Capability Bundle (.hcap)").size(14.0).strong());
        ui.add_space(4.0);
        text_field(
            ui,
            "Bundle File Path",
            "capability.hcap",
            &mut ws.akashi_bundle_path,
        );
        text_field(
            ui,
            "Explicit Scope Limits (for export)",
            "Conditions tested and known boundaries",
            &mut ws.akashi_bundle_scope,
        );
        ui.checkbox(
            &mut ws.akashi_sign_bundle,
            "Sign exported bundle with active Ed25519 identity",
        );

        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            if primary_button(ui, "Export Node").clicked() {
                ws.akashi_export_bundle();
            }
            if ui.button("Inspect Bundle").clicked() {
                ws.akashi_inspect_bundle();
            }
            if ui.button("Import Peer Bundle (External)").clicked() {
                ws.akashi_import_peer_bundle();
            }
        });

        if let Some(info) = &ws.akashi_last_inspected_bundle {
            ui.add_space(6.0);
            nested_card(ui, |ui| {
                ui.label(RichText::new(info).size(12.5));
            });
        }
    });
}
