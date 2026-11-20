//! Minimalist Identity/Vault & loopback AI Proxy controls.
use crate::state::{AUTH_SCHEMES, WorkspaceData};
use crate::theme::{
    ACCENT, ACCENT_BG, AMBER, AMBER_BG, BG_NESTED, GREEN, GREEN_BG, RED, RED_BG, TEXT_MUTED,
    badge, card, empty_state, nested_card, pill_toggle, primary_button, secret_field, text_field,
};
use eframe::egui::{self, Layout, RichText};
use henosis_proxy::{ProxyDecision, impedance::ImpedanceMode};

pub fn show(ui: &mut egui::Ui, ws: &mut WorkspaceData) {
    egui::ScrollArea::vertical()
        .id_salt("vault_proxy_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            show_identity_and_vault(ui, ws);
            ui.add_space(12.0);
            show_ai_proxy(ui, ws);
        });
}

fn show_identity_and_vault(ui: &mut egui::Ui, ws: &mut WorkspaceData) {
    card(ui, |ui| {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("Identity & Encrypted Vault").size(14.5).strong());
            if let Some(id) = &ws.active_identity {
                badge(
                    ui,
                    format!("Signer: {}", id.fingerprint()),
                    GREEN,
                    GREEN_BG,
                );
            } else {
                badge(ui, "No Signer Loaded", TEXT_MUTED, BG_NESTED);
            }
            if ws.vault.is_some() {
                badge(ui, "Vault Unlocked", ACCENT, ACCENT_BG);
            }
        });

        // One-time 12-word recovery phrase backup banner
        let mut clear_backup = false;
        if let Some(phrase) = &ws.pending_backup_mnemonic {
            ui.add_space(6.0);
            nested_card(ui, |ui| {
                ui.horizontal(|ui| {
                    badge(ui, "Back Up Now", AMBER, AMBER_BG);
                    ui.label(RichText::new("12-Word Recovery Phrase (shown once)").strong());
                });
                ui.add_space(4.0);
                ui.label(RichText::new(phrase.as_str()).monospace().size(13.0));
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    if ui.small_button("Copy Phrase").clicked() {
                        ui.ctx().copy_text(phrase.as_str().to_owned());
                    }
                    if ui.small_button("I Saved It — Clear").clicked() {
                        clear_backup = true;
                    }
                });
            });
        }
        if clear_backup {
            ws.pending_backup_mnemonic = None;
        }

        ui.add_space(6.0);
        ui.columns(3, |cols| {
            text_field(&mut cols[0], "Vault File", "vault.hnv", &mut ws.vault_path);
            secret_field(
                &mut cols[1],
                "Vault Password",
                "Encryption password",
                &mut ws.vault_password,
            );
            secret_field(
                &mut cols[2],
                "Key Passphrase (optional)",
                "BIP-39 passphrase",
                &mut ws.vault_passphrase,
            );
        });

        ui.horizontal_wrapped(|ui| {
            if ws.vault.is_none() {
                if primary_button(ui, "Unlock Vault").clicked() {
                    ws.open_vault();
                }
                if ui.button("Create New Vault").clicked() {
                    ws.create_vault();
                }
            } else if ui.button("Lock Vault").clicked() {
                ws.lock_vault();
            }
        });

        // Session-only recovery phrase option when no vault is open
        if ws.vault.is_none() && ws.active_identity.is_none() {
            ui.add_space(6.0);
            ui.collapsing("Recover signing key from 12-word phrase (session only)", |ui| {
                secret_field(
                    ui,
                    "12-Word Phrase",
                    "twelve lowercase words…",
                    &mut ws.session_mnemonic_input,
                );
                if ui.button("Load Session Identity").clicked() {
                    ws.load_session_mnemonic();
                }
            });
        }

        // Provider credentials inside unlocked vault
        if let Some(vault) = &ws.vault {
            let creds = vault.list_credentials();
            ui.add_space(8.0);
            ui.separator();
            ui.label(RichText::new("Provider Credentials").size(13.5).strong());

            let mut to_remove = None;
            for c in &creds {
                nested_card(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        badge(ui, &c.name, ACCENT, ACCENT_BG);
                        badge(ui, c.auth_scheme.as_str(), TEXT_MUTED, BG_NESTED);
                        if let Some(url) = &c.base_url {
                            ui.label(RichText::new(url).monospace().size(12.0));
                        }
                        ui.label(
                            RichText::new(format!("({} bytes)", c.secret_len))
                                .size(11.5)
                                .color(TEXT_MUTED),
                        );
                        ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("Remove").clicked() {
                                to_remove = Some(c.name.clone());
                            }
                        });
                    });
                });
                ui.add_space(4.0);
            }
            if let Some(name) = to_remove {
                ws.remove_vault_credential(&name);
            }

            ui.add_space(4.0);
            ui.columns(2, |cols| {
                text_field(
                    &mut cols[0],
                    "Provider Name",
                    "ollama-local",
                    &mut ws.cred_name,
                );
                cols[1].label(RichText::new("Auth Scheme").size(12.0).color(TEXT_MUTED));
                egui::ComboBox::from_id_salt("vault_cred_scheme")
                    .selected_text(AUTH_SCHEMES[ws.cred_scheme_idx].1)
                    .show_ui(&mut cols[1], |ui| {
                        for (idx, (_, label)) in AUTH_SCHEMES.iter().enumerate() {
                            ui.selectable_value(&mut ws.cred_scheme_idx, idx, *label);
                        }
                    });
            });
            ui.columns(2, |cols| {
                text_field(
                    &mut cols[0],
                    "Upstream HTTP URL (optional)",
                    "http://127.0.0.1:11434",
                    &mut ws.cred_url,
                );
                secret_field(
                    &mut cols[1],
                    "API Key / Secret",
                    "Never shown after saving",
                    &mut ws.cred_secret,
                );
            });
            if primary_button(ui, "Save Credential").clicked() {
                ws.save_vault_credential();
            }
        }
    });
}

fn show_ai_proxy(ui: &mut egui::Ui, ws: &mut WorkspaceData) {
    card(ui, |ui| {
        let current_mode = ws.current_impedance();
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("AI Proxy Gateway").size(14.5).strong());

            for (mode, label) in [
                (ImpedanceMode::Open, "Open"),
                (ImpedanceMode::Socratic, "Socratic"),
                (ImpedanceMode::Blackout, "Blackout"),
            ] {
                if pill_toggle(ui, current_mode == Some(mode), label).clicked() {
                    ws.select_impedance(mode);
                }
            }

            if let Some(proxy) = &ws.proxy {
                let url = proxy.base_url();
                ui.label(RichText::new(&url).monospace().size(12.0).color(GREEN));
                if ui.small_button("Copy URL").clicked() {
                    ui.ctx().copy_text(url);
                }
                if ui.small_button("Stop").clicked() {
                    ws.stop_proxy();
                }
            } else if ui.small_button("Start Proxy").clicked() {
                ws.select_impedance(ImpedanceMode::Socratic);
            }
        });

        let Some(proxy_status) = ws.proxy.as_ref().map(|p| p.status()) else {
            empty_state(
                ui,
                "AI Proxy is stopped",
                "Click Open, Socratic, or Blackout above to launch the local 127.0.0.1 gateway.",
            );
            return;
        };

        // Mint ephemeral session capability token
        ui.add_space(6.0);
        ui.separator();
        ui.label(RichText::new("Ephemeral Capability Sessions").size(13.5).strong());

        if !proxy_status.provider_names.contains(&ws.session_provider_input)
            && !proxy_status.provider_names.is_empty()
        {
            ws.session_provider_input = proxy_status.provider_names[0].clone();
        }

        ui.columns(3, |cols| {
            text_field(
                &mut cols[0],
                "Session Label",
                "agent-1",
                &mut ws.session_label_input,
            );
            cols[1].label(RichText::new("Provider").size(12.0).color(TEXT_MUTED));
            egui::ComboBox::from_id_salt("proxy_provider_select")
                .selected_text(&ws.session_provider_input)
                .show_ui(&mut cols[1], |ui| {
                    for p in &proxy_status.provider_names {
                        ui.selectable_value(&mut ws.session_provider_input, p.clone(), p);
                    }
                });
            text_field(
                &mut cols[2],
                "Max Requests",
                "64",
                &mut ws.session_max_requests,
            );
        });
        if primary_button(ui, "Mint Capability Token").clicked() {
            ws.mint_proxy_token();
        }

        let mut clear_token = false;
        if let Some(token) = &ws.last_minted_token {
            ui.add_space(6.0);
            nested_card(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    badge(ui, "Shown Once", AMBER, AMBER_BG);
                    ui.label(RichText::new(token.as_str()).monospace().size(12.0));
                    if ui.small_button("Copy Token").clicked() {
                        ui.ctx().copy_text(token.as_str().to_owned());
                    }
                    if ui.small_button("Dismiss").clicked() {
                        clear_token = true;
                    }
                });
            });
        }
        if clear_token {
            ws.last_minted_token = None;
        }

        // Active sessions list
        let sessions = ws
            .proxy
            .as_ref()
            .map(|p| p.sessions())
            .unwrap_or_default();
        let mut revoke_id = None;
        for s in sessions {
            ui.add_space(4.0);
            nested_card(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    badge(ui, format!("#{}", s.id), ACCENT, ACCENT_BG);
                    ui.label(RichText::new(&s.label).strong());
                    ui.label(
                        RichText::new(format!(
                            "→ {} ({}/{} reqs)",
                            s.provider, s.used_requests, s.budget.max_requests
                        ))
                        .size(12.0)
                        .color(TEXT_MUTED),
                    );
                    if s.revoked {
                        badge(ui, "Revoked", RED, RED_BG);
                    } else {
                        ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("Revoke").clicked() {
                                revoke_id = Some(s.id);
                            }
                        });
                    }
                });
            });
        }
        if let Some(id) = revoke_id {
            ws.revoke_proxy_session(id);
        }

        // Live hash-chained exposure log
        let mut exposures = ws
            .proxy
            .as_ref()
            .map(|p| p.exposures())
            .unwrap_or_default();
        exposures.reverse();
        if !exposures.is_empty() {
            ui.add_space(8.0);
            ui.separator();
            ui.label(RichText::new("Intercepted AI Telemetry").size(13.5).strong());
            let mut to_quarantine = None;
            for rec in exposures.into_iter().take(15) {
                ui.add_space(4.0);
                nested_card(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        badge(ui, format!("seq {}", rec.seq), ACCENT, ACCENT_BG);
                        let (dec_label, fg, bg) = match &rec.decision {
                            ProxyDecision::Forwarded => ("Forwarded", GREEN, GREEN_BG),
                            ProxyDecision::ForwardedSocratic => ("Socratic", ACCENT, ACCENT_BG),
                            ProxyDecision::BlockedBlackout => ("Blackout Blocked", AMBER, AMBER_BG),
                            ProxyDecision::BlockedDlp { .. } => ("DLP Blocked", RED, RED_BG),
                            _ => ("Blocked", RED, RED_BG),
                        };
                        badge(ui, dec_label, fg, bg);
                        ui.label(RichText::new(&rec.endpoint).monospace().size(12.0));
                        ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("Quarantine →").clicked() {
                                to_quarantine = Some(rec.clone());
                            }
                        });
                    });
                });
            }
            if let Some(rec) = to_quarantine {
                ws.quarantine_proxy_record(&rec);
            }
        }
    });
}
