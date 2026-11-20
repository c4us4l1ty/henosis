//! Minimalist Worldline Merkle-DAG view: branches, nodes, contracts, quarantine, failures, commits.
use crate::state::{WorldlineSubtab, WorkspaceData, ENTITY_KINDS};
use crate::theme::{
    badge, card, empty_state, nested_card, pill_toggle, primary_button, text_field, ACCENT,
    ACCENT_BG, AMBER, AMBER_BG, BG_NESTED, GREEN, GREEN_BG, RED, RED_BG, TEXT_MUTED,
};
use eframe::egui::{self, Layout, RichText};
use henosis_dag::{AssistanceProvenance, EpistemicStatus};

pub fn show(ui: &mut egui::Ui, ws: &mut WorkspaceData) {
    if let Some(err) = &ws.worldline.load_error {
        card(ui, |ui| {
            ui.colored_label(RED, format!("Cannot load {}: {err}", ws.worldline_path));
        });
        return;
    }

    if !ws.worldline.exists {
        ui.add_space(28.0);
        ui.vertical_centered(|ui| {
            ui.label(
                RichText::new("No Worldline initialized")
                    .size(16.0)
                    .strong(),
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new(format!(
                    "Create a content-addressed capability graph at '{}'.",
                    ws.worldline_path
                ))
                .color(TEXT_MUTED),
            );
            ui.add_space(10.0);
            if primary_button(ui, "Create Worldline").clicked() {
                ws.init_worldline();
            }
        });
        return;
    }

    let Some(wl) = ws.worldline.worldline.clone() else {
        return;
    };

    // Compact summary & branch strip
    let h_count = ws.worldline.state.unassisted_capabilities().len();
    let assisted_count = ws.worldline.state.assisted_verified_nodes().len();
    let quarantine_open = ws.worldline.state.unresolved_quarantine().len();
    let failure_count = ws.worldline.state.failures.len();

    ui.horizontal_wrapped(|ui| {
        badge(ui, format!("Branch: {}", wl.head_branch), ACCENT, ACCENT_BG);
        badge(ui, format!("{h_count} Unassisted (H)"), GREEN, GREEN_BG);
        if assisted_count > 0 {
            badge(ui, format!("{assisted_count} Assisted"), ACCENT, ACCENT_BG);
        }
        if quarantine_open > 0 {
            badge(ui, format!("{quarantine_open} Quarantine"), AMBER, AMBER_BG);
        }
        if failure_count > 0 {
            badge(ui, format!("{failure_count} Failures"), RED, RED_BG);
        }

        // Branch switcher when multiple branches exist
        if wl.branches.len() > 1 {
            let mut next_branch = wl.head_branch.clone();
            egui::ComboBox::from_id_salt("wl_branch_switch")
                .selected_text(format!("Switch ({})", wl.branches.len()))
                .show_ui(ui, |ui| {
                    for b in wl.branches.keys() {
                        ui.selectable_value(&mut next_branch, b.clone(), b);
                    }
                });
            if next_branch != wl.head_branch {
                ws.checkout_branch(&next_branch);
            }
        }
    });

    ui.add_space(6.0);

    // Subtab bar + "+ Add" toggle
    ui.horizontal_wrapped(|ui| {
        for (tab, label) in [
            (
                WorldlineSubtab::Nodes,
                format!("Nodes ({})", ws.worldline.state.nodes.len()),
            ),
            (
                WorldlineSubtab::Contracts,
                format!("Contracts ({})", ws.worldline.state.contracts.len()),
            ),
            (
                WorldlineSubtab::Quarantine,
                format!("Quarantine ({})", ws.worldline.state.quarantine.len()),
            ),
            (
                WorldlineSubtab::Failures,
                format!("Failures ({})", ws.worldline.state.failures.len()),
            ),
            (
                WorldlineSubtab::History,
                format!("History ({})", ws.worldline.commits.len()),
            ),
        ] {
            if pill_toggle(ui, ws.wl_subtab == tab, label).clicked() {
                ws.wl_subtab = tab;
                ws.wl_add_open = false;
            }
        }

        if ws.wl_subtab != WorldlineSubtab::History {
            ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                let add_label = if ws.wl_add_open { "Close" } else { "+ Add" };
                if primary_button(ui, add_label).clicked() {
                    ws.wl_add_open = !ws.wl_add_open;
                }
            });
        }
    });

    if ws.wl_add_open {
        ui.add_space(6.0);
        render_add_drawer(ui, ws);
    }

    ui.add_space(8.0);
    egui::ScrollArea::vertical()
        .id_salt("worldline_main_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| match ws.wl_subtab {
            WorldlineSubtab::Nodes => render_nodes(ui, ws),
            WorldlineSubtab::Contracts => render_contracts(ui, ws),
            WorldlineSubtab::Quarantine => render_quarantine(ui, ws),
            WorldlineSubtab::Failures => render_failures(ui, ws),
            WorldlineSubtab::History => render_history(ui, ws, &wl),
        });
}

fn render_add_drawer(ui: &mut egui::Ui, ws: &mut WorkspaceData) {
    card(ui, |ui| match ws.wl_subtab {
        WorldlineSubtab::Nodes => {
            ui.label(RichText::new("Add Node").size(14.0).strong());
            ui.columns(3, |cols| {
                text_field(&mut cols[0], "ID", "cap-raft-log", &mut ws.wl_node_id);
                cols[1].label(RichText::new("Kind").size(12.0).color(TEXT_MUTED));
                egui::ComboBox::from_id_salt("wl_node_kind")
                    .selected_text(ENTITY_KINDS[ws.wl_node_kind_idx].as_str())
                    .show_ui(&mut cols[1], |ui| {
                        for (idx, kind) in ENTITY_KINDS.iter().enumerate() {
                            ui.selectable_value(&mut ws.wl_node_kind_idx, idx, kind.as_str());
                        }
                    });
                text_field(&mut cols[2], "Domain", "systems", &mut ws.wl_node_domain);
            });
            text_field(
                &mut *ui,
                "Title",
                "Human-readable name",
                &mut ws.wl_node_title,
            );
            text_field(
                &mut *ui,
                "Summary",
                "Concise statement of capability or claim",
                &mut ws.wl_node_summary,
            );
            ui.horizontal(|ui| {
                if primary_button(ui, "Commit Node").clicked() {
                    ws.add_worldline_node();
                }
                if ui.button("Cancel").clicked() {
                    ws.wl_add_open = false;
                }
            });
        }
        WorldlineSubtab::Contracts => {
            ui.label(
                RichText::new("Add Realization Contract")
                    .size(14.0)
                    .strong(),
            );
            ui.columns(3, |cols| {
                text_field(
                    &mut cols[0],
                    "Contract ID",
                    "ctr-build-parser",
                    &mut ws.wl_contract_id,
                );
                text_field(
                    &mut cols[1],
                    "Output Node ID",
                    "cap-parser",
                    &mut ws.wl_contract_output,
                );
                text_field(&mut cols[2], "Cost Units", "2", &mut ws.wl_contract_cost);
            });
            text_field(
                &mut *ui,
                "Title",
                "Contract title",
                &mut ws.wl_contract_title,
            );
            text_field(
                &mut *ui,
                "Prerequisites (comma-separated capability IDs)",
                "cap-lexer, cap-ast",
                &mut ws.wl_contract_prereqs,
            );
            text_field(
                &mut *ui,
                "Verification Criteria",
                "Passes deterministic suite without assistance",
                &mut ws.wl_contract_verification,
            );
            ui.horizontal(|ui| {
                if primary_button(ui, "Commit Contract").clicked() {
                    ws.add_worldline_contract();
                }
                if ui.button("Cancel").clicked() {
                    ws.wl_add_open = false;
                }
            });
        }
        WorldlineSubtab::Quarantine => {
            ui.label(
                RichText::new("Quarantine Unverified Exposure")
                    .size(14.0)
                    .strong(),
            );
            ui.columns(2, |cols| {
                text_field(
                    &mut cols[0],
                    "Exposure ID",
                    "exp-paper-1",
                    &mut ws.wl_expose_id,
                );
                text_field(
                    &mut cols[1],
                    "Source",
                    "ai-chat / paper",
                    &mut ws.wl_expose_source,
                );
            });
            text_field(
                &mut *ui,
                "Topic",
                "Subject area exposed to",
                &mut ws.wl_expose_topic,
            );
            text_field(
                &mut *ui,
                "Notes",
                "Context before verification",
                &mut ws.wl_expose_notes,
            );
            ui.horizontal(|ui| {
                if primary_button(ui, "Enqueue in Quarantine").clicked() {
                    ws.add_worldline_exposure();
                }
                if ui.button("Cancel").clicked() {
                    ws.wl_add_open = false;
                }
            });
        }
        WorldlineSubtab::Failures => {
            ui.label(RichText::new("Record Failure Boundary").size(14.0).strong());
            ui.columns(2, |cols| {
                text_field(&mut cols[0], "Failure ID", "fail-oom-1", &mut ws.wl_fail_id);
                text_field(
                    &mut cols[1],
                    "Target Node / Contract ID",
                    "cap-parser",
                    &mut ws.wl_fail_target,
                );
            });
            text_field(
                &mut *ui,
                "Violated Assumption",
                "Input fits in L1 buffer",
                &mut ws.wl_fail_assumption,
            );
            text_field(
                &mut *ui,
                "Trigger",
                "Payload > 64 KiB",
                &mut ws.wl_fail_trigger,
            );
            ui.columns(2, |cols| {
                text_field(
                    &mut cols[0],
                    "Predicted Effect",
                    "Graceful error",
                    &mut ws.wl_fail_predicted,
                );
                text_field(
                    &mut cols[1],
                    "Observed Effect",
                    "Truncated frame",
                    &mut ws.wl_fail_observed,
                );
            });
            ui.horizontal(|ui| {
                if primary_button(ui, "Commit Failure").clicked() {
                    ws.add_worldline_failure();
                }
                if ui.button("Cancel").clicked() {
                    ws.wl_add_open = false;
                }
            });
        }
        WorldlineSubtab::History => {}
    });
}

fn render_nodes(ui: &mut egui::Ui, ws: &mut WorkspaceData) {
    let nodes: Vec<_> = ws.worldline.state.nodes.values().cloned().collect();
    if nodes.is_empty() {
        empty_state(
            ui,
            "No nodes in this branch yet",
            "Click '+ Add' to define a capability or verify one directly in Akashi.",
        );
        return;
    }

    let mut verify_target = None;
    for node in nodes {
        card(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                badge(ui, node.kind.as_str(), ACCENT, ACCENT_BG);
                let (st_fg, st_bg) = match node.status {
                    EpistemicStatus::Reproduced | EpistemicStatus::Observed => (GREEN, GREEN_BG),
                    EpistemicStatus::Hypothesized
                    | EpistemicStatus::Inferred
                    | EpistemicStatus::Unknown => (AMBER, AMBER_BG),
                    EpistemicStatus::Contested | EpistemicStatus::Refuted => (RED, RED_BG),
                };
                badge(ui, node.status.as_str(), st_fg, st_bg);

                let prov_label = match node.provenance {
                    AssistanceProvenance::UnassistedHuman => "Unassisted",
                    AssistanceProvenance::JointHumanAi => "Joint AI",
                    AssistanceProvenance::External => "External",
                    AssistanceProvenance::AiGenerated => "AI Generated",
                };
                badge(ui, prov_label, TEXT_MUTED, BG_NESTED);

                ui.label(
                    RichText::new(&node.id)
                        .monospace()
                        .size(12.0)
                        .color(TEXT_MUTED),
                );

                ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.small_button("Verify in Akashi →").clicked() {
                        verify_target = Some(node.id.clone());
                    }
                });
            });

            ui.add_space(4.0);
            ui.label(RichText::new(&node.title).size(14.5).strong());
            if !node.summary.is_empty() {
                ui.label(RichText::new(&node.summary).size(13.0).color(TEXT_MUTED));
            }
            if !node.proof_operators.is_empty() {
                let ops: Vec<&str> = node.proof_operators.iter().map(|o| o.as_str()).collect();
                ui.label(
                    RichText::new(format!("Proof operators: {}", ops.join(", ")))
                        .size(12.0)
                        .color(GREEN),
                );
            }
        });
        ui.add_space(8.0);
    }

    if let Some(nid) = verify_target {
        ws.jump_to_akashi(Some(&nid), None);
    }
}

fn render_contracts(ui: &mut egui::Ui, ws: &mut WorkspaceData) {
    let contracts: Vec<_> = ws.worldline.state.contracts.values().cloned().collect();
    if contracts.is_empty() {
        empty_state(
            ui,
            "No realization contracts yet",
            "Contracts link prerequisite capabilities to new unlocked outputs.",
        );
        return;
    }

    let h_set = ws.worldline.state.unassisted_capabilities();
    for ctr in contracts {
        let ready = ctr.prerequisites.iter().all(|p| h_set.contains(p));
        card(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                badge(ui, &ctr.id, ACCENT, ACCENT_BG);
                if ready {
                    badge(ui, "Executable", GREEN, GREEN_BG);
                } else {
                    badge(ui, "Needs Prerequisites", AMBER, AMBER_BG);
                }
                ui.label(
                    RichText::new(format!("Output: {} · Cost: {}", ctr.output, ctr.cost_units))
                        .size(12.0)
                        .color(TEXT_MUTED),
                );
                ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                    let inspecting =
                        ws.wl_selected_goal_contract.as_deref() == Some(ctr.output.as_str());
                    if ui
                        .small_button(if inspecting { "Hide Cone" } else { "Light-Cone" })
                        .clicked()
                    {
                        ws.wl_selected_goal_contract = if inspecting {
                            None
                        } else {
                            Some(ctr.output.clone())
                        };
                    }
                });
            });

            ui.add_space(4.0);
            ui.label(RichText::new(&ctr.title).size(14.5).strong());
            ui.label(
                RichText::new(format!("Criteria: {}", ctr.verification))
                    .size(12.5)
                    .color(TEXT_MUTED),
            );
            if !ctr.prerequisites.is_empty() {
                ui.label(
                    RichText::new(format!("Requires: {}", ctr.prerequisites.join(", ")))
                        .size(12.0),
                );
            }

            if ws.wl_selected_goal_contract.as_deref() == Some(ctr.output.as_str()) {
                if let Some(hg) = &ws.worldline.hypergraph {
                    if let Ok(cone) = hg.backward_light_cone(&ctr.output, &h_set) {
                        ui.add_space(6.0);
                        nested_card(ui, |ui| {
                            ui.label(
                                RichText::new(format!(
                                    "Light-Cone for '{}' — missing cost: {} unit(s)",
                                    cone.target, cone.total_missing_cost_units
                                ))
                                .size(12.5)
                                .strong(),
                            );
                            if !cone.missing_capabilities.is_empty() {
                                ui.label(
                                    RichText::new(format!(
                                        "Missing: {}",
                                        cone.missing_capabilities.join(", ")
                                    ))
                                    .size(12.0)
                                    .color(AMBER),
                                );
                            }
                            if !cone.verified_foundations.is_empty() {
                                ui.label(
                                    RichText::new(format!(
                                        "Verified foundations: {}",
                                        cone.verified_foundations.join(", ")
                                    ))
                                    .size(12.0)
                                    .color(GREEN),
                                );
                            }
                        });
                    }
                }
            }
        });
        ui.add_space(8.0);
    }
}

fn render_quarantine(ui: &mut egui::Ui, ws: &mut WorkspaceData) {
    let items: Vec<_> = ws.worldline.state.quarantine.values().cloned().collect();
    if items.is_empty() {
        empty_state(
            ui,
            "Quarantine queue is clear",
            "AI exposures and unverified external ideas wait here until verified.",
        );
        return;
    }

    let node_ids: Vec<String> = ws.worldline.state.nodes.keys().cloned().collect();
    let mut resolve_action = None;

    for item in items {
        card(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                badge(ui, &item.id, ACCENT, ACCENT_BG);
                if let Some(by) = &item.resolved_by_node {
                    badge(ui, format!("Resolved → {by}"), GREEN, GREEN_BG);
                } else {
                    badge(ui, "Unverified Exposure", AMBER, AMBER_BG);
                }
                ui.label(
                    RichText::new(format!("Source: {}", item.source))
                        .size(12.0)
                        .color(TEXT_MUTED),
                );
            });
            ui.add_space(4.0);
            ui.label(RichText::new(&item.topic).size(14.0).strong());
            if !item.notes.is_empty() {
                ui.label(RichText::new(&item.notes).size(12.5).color(TEXT_MUTED));
            }

            if item.resolved_by_node.is_none() && !node_ids.is_empty() {
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    let selected = ws
                        .wl_resolve_targets
                        .entry(item.id.clone())
                        .or_insert_with(|| node_ids[0].clone());
                    egui::ComboBox::from_id_salt(format!("resolve_{}", item.id))
                        .selected_text(selected.as_str())
                        .show_ui(ui, |ui| {
                            for nid in &node_ids {
                                ui.selectable_value(selected, nid.clone(), nid);
                            }
                        });
                    if ui.small_button("Resolve").clicked() {
                        resolve_action = Some(item.id.clone());
                    }
                });
            }
        });
        ui.add_space(8.0);
    }

    if let Some(eid) = resolve_action {
        ws.resolve_quarantine(&eid);
    }
}

fn render_failures(ui: &mut egui::Ui, ws: &mut WorkspaceData) {
    let failures: Vec<_> = ws.worldline.state.failures.values().cloned().collect();
    if failures.is_empty() {
        empty_state(
            ui,
            "Failure Atlas is empty",
            "Perturbation suites and recorded boundary failures appear here.",
        );
        return;
    }

    for f in failures {
        card(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                badge(ui, &f.id, RED, RED_BG);
                badge(ui, format!("Target: {}", f.target_id), ACCENT, ACCENT_BG);
            });
            ui.add_space(4.0);
            ui.label(
                RichText::new(format!("Trigger: {}", f.trigger))
                    .size(14.0)
                    .strong(),
            );
            ui.label(
                RichText::new(format!("Violated assumption: {}", f.broken_assumption))
                    .size(12.5)
                    .color(TEXT_MUTED),
            );
            ui.label(
                RichText::new(format!(
                    "Predicted: {}  |  Observed: {}",
                    f.predicted, f.observed
                ))
                .size(12.5),
            );
        });
        ui.add_space(8.0);
    }
}

fn render_history(ui: &mut egui::Ui, ws: &mut WorkspaceData, wl: &henosis_dag::Worldline) {
    // Compact branch management card
    card(ui, |ui| {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Branches").strong());
            if !wl.commits.is_empty() {
                ui.add(
                    egui::TextEdit::singleline(&mut ws.wl_new_branch)
                        .hint_text("new-branch-name")
                        .desired_width(150.0),
                );
                if ui.small_button("Create Branch").clicked() {
                    ws.create_branch();
                }
            }

            let other_branches: Vec<String> = wl
                .branches
                .keys()
                .filter(|b| *b != &wl.head_branch)
                .cloned()
                .collect();
            if !other_branches.is_empty() {
                if ws.wl_merge_source.is_empty() || !other_branches.contains(&ws.wl_merge_source) {
                    ws.wl_merge_source = other_branches[0].clone();
                }
                ui.separator();
                egui::ComboBox::from_id_salt("wl_merge_src")
                    .selected_text(format!("Merge {}", ws.wl_merge_source))
                    .show_ui(ui, |ui| {
                        for b in &other_branches {
                            ui.selectable_value(&mut ws.wl_merge_source, b.clone(), b);
                        }
                    });
                if ui.small_button(format!("Merge into {}", wl.head_branch)).clicked() {
                    ws.merge_branch();
                }
            }
        });
    });

    ui.add_space(8.0);
    if ws.worldline.commits.is_empty() {
        empty_state(
            ui,
            "No commits yet",
            "Add a node, contract, or verification to create the genesis commit.",
        );
        return;
    }

    for commit in &ws.worldline.commits {
        card(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                badge(ui, format!("seq {}", commit.seq), ACCENT, ACCENT_BG);
                ui.label(
                    RichText::new(&commit.id[..12.min(commit.id.len())])
                        .monospace()
                        .size(12.0)
                        .color(TEXT_MUTED),
                );
                if let Some(fp) = &commit.author_fingerprint {
                    badge(ui, format!("Signed ({fp})"), GREEN, GREEN_BG);
                } else {
                    badge(ui, "Unsigned", TEXT_MUTED, BG_NESTED);
                }
                ui.label(
                    RichText::new(format!("{} op(s)", commit.ops.len()))
                        .size(12.0)
                        .color(TEXT_MUTED),
                );
            });
            ui.add_space(3.0);
            ui.label(RichText::new(&commit.message).size(13.5).strong());
        });
        ui.add_space(6.0);
    }
}
