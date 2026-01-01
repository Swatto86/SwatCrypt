#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process,
    sync::mpsc::{self, Receiver, TryRecvError},
    thread,
};

use anyhow::{anyhow, bail, Context, Result};
use clap::{Args as ClapArgs, Parser, Subcommand, ValueHint};
use eframe::egui::ViewportBuilder;
use eframe::{egui, egui::Vec2};
use egui::viewport::IconData;
use humansize::{format_size, BINARY};
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use rpassword::prompt_password;
use single_instance::SingleInstance;
use tempfile::tempdir;
use swatcrypt::{
    decrypt, encrypt, inspect_header, secure_wipe_paths, DecryptRequest, DecryptResult,
    EncryptRequest, EncryptResult, KdfConfig, ProgressCallback, ProgressStage, ProgressUpdate,
    EXTENSION,
};

fn main() -> eframe::Result<()> {
    match cli::parse_mode() {
        cli::LaunchMode::Cli(command) => {
            let code = match cli::run_command(command) {
                Ok(()) => 0,
                Err(err) => {
                    eprintln!("error: {err}");
                    1
                }
            };
            process::exit(code);
        }
        cli::LaunchMode::Gui {
            open_paths,
            launch_dir,
        } => run_gui(open_paths, launch_dir),
    }
}

fn run_gui(initial_inputs: Vec<PathBuf>, launch_dir: Option<PathBuf>) -> eframe::Result<()> {
    let base_dir = launch_dir.or_else(|| std::env::current_dir().ok());
    let resolved_inputs: Vec<PathBuf> = initial_inputs
        .into_iter()
        .map(|p| {
            if p.is_absolute() {
                p
            } else if let Some(base) = &base_dir {
                base.join(p)
            } else {
                p
            }
        })
        .collect();

    let instance = match SingleInstance::new("swatcrypt-single-instance") {
        Ok(g) => g,
        Err(_) => return Ok(()),
    };
    if !instance.is_single() {
        let handoff_paths = resolved_inputs.clone();
        let handoff_result = enqueue_launch_request(&handoff_paths);
        match handoff_result {
            Ok(()) if !handoff_paths.is_empty() => {
            }
            Ok(()) => {
                #[cfg(windows)]
                rfd::MessageDialog::new()
                    .set_title("SwatCrypt is already running")
                    .set_description(
                        "Close the existing SwatCrypt window and try again. \n(Explorer launches are ignored while an instance is active.)",
                    )
                    .set_buttons(rfd::MessageButtons::Ok)
                    .show();
            }
            Err(_) => {
                #[cfg(windows)]
                rfd::MessageDialog::new()
                    .set_title("SwatCrypt is already running")
                    .set_description(
                        "Close the existing SwatCrypt window and try again. \n(Explorer launches are ignored while an instance is active.)",
                    )
                    .set_buttons(rfd::MessageButtons::Ok)
                    .show();
            }
        }
        return Ok(());
    }

    let mut viewport = ViewportBuilder::default().with_inner_size(Vec2::new(900.0, 720.0));
    if let Some(icon) = load_icon() {
        viewport = viewport.with_icon(icon);
    }
    let options = eframe::NativeOptions {
        default_theme: eframe::Theme::Dark,
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "SwatCrypt",
        options,
        Box::new(move |cc| {
            Box::new(SwatCryptApp::new(cc, resolved_inputs.clone(), Some(instance)))
        }),
    )
}

const GUI_IPC_QUEUE: &str = "swatcrypt_gui_launch_queue.jsonl";

#[derive(Serialize, Deserialize)]
struct LaunchRequest {
    paths: Vec<PathBuf>,
}

fn queue_file_path() -> PathBuf {
    std::env::temp_dir().join(GUI_IPC_QUEUE)
}

fn enqueue_launch_request(paths: &[PathBuf]) -> Result<()> {
    if paths.is_empty() {
        return Ok(());
    }
    let msg = LaunchRequest {
        paths: paths.to_vec(),
    };
    let line = serde_json::to_string(&msg)?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(queue_file_path())?;
    writeln!(file, "{line}")?;
    Ok(())
}

fn take_queued_launches() -> Result<Vec<LaunchRequest>> {
    let path = queue_file_path();
    if !path.exists() {
        return Ok(Vec::new());
    }
    let drain_path = path.with_extension("drain");
    match fs::rename(&path, &drain_path) {
        Ok(()) => {}
        Err(err) => {
            if path.exists() {
                bail!("failed to rotate launch queue: {err}");
            } else {
                return Ok(Vec::new());
            }
        }
    }
    let data = fs::read_to_string(&drain_path)?;
    let _ = fs::remove_file(&drain_path);
    let mut launches = Vec::new();
    for line in data.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<LaunchRequest>(line) {
            Ok(msg) => launches.push(msg),
            Err(_) => {}
        }
    }
    Ok(launches)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Encrypt,
    Decrypt,
}

enum WorkerMsg {
    Encrypt(Result<EncryptResult, String>),
    Decrypt(Result<DecryptResult, String>),
    Progress { fraction: Option<f32>, note: String },
}

struct SwatCryptApp {
    mode: Mode,
    inputs: Vec<PathBuf>,
    output: Option<PathBuf>,
    passphrase: String,
    passphrase_confirm: String,
    compress: bool,
    wipe: bool,
    verify_after_encrypt: bool,
    chunk_size: String,
    force: bool,
    busy: bool,
    progress_fraction: Option<f32>,
    progress_note: Option<String>,
    worker_rx: Option<Receiver<WorkerMsg>>,
    #[cfg(windows)]
    context_menu_installed: Option<bool>,
    #[cfg(windows)]
    context_menu_note: Option<String>,
    #[cfg(windows)]
    context_menu_busy: bool,
    instance_guard: Option<SingleInstance>,
}

impl Default for SwatCryptApp {
    fn default() -> Self {
        Self {
            mode: Mode::Encrypt,
            inputs: Vec::new(),
            output: None,
            passphrase: String::new(),
            passphrase_confirm: String::new(),
            compress: false,
            wipe: false,
            verify_after_encrypt: true,
            chunk_size: String::new(),
            force: false,
            busy: false,
            progress_fraction: None,
            progress_note: None,
            worker_rx: None,
            #[cfg(windows)]
            context_menu_installed: None,
            #[cfg(windows)]
            context_menu_note: None,
            #[cfg(windows)]
            context_menu_busy: false,
            instance_guard: None,
        }
    }
}

impl SwatCryptApp {
    fn new(
        cc: &eframe::CreationContext<'_>,
        initial_inputs: Vec<PathBuf>,
        instance_guard: Option<SingleInstance>,
    ) -> Self {
        // Force a high-contrast dark theme for readability across OS themes.
        let mut visuals = egui::Visuals::dark();
        visuals.override_text_color = Some(egui::Color32::from_rgb(235, 235, 235));
        visuals.panel_fill = egui::Color32::from_rgb(18, 18, 22);
        visuals.extreme_bg_color = egui::Color32::from_rgb(30, 30, 36);
        visuals.widgets.noninteractive.fg_stroke.color = egui::Color32::from_rgb(235, 235, 235);
        visuals.widgets.inactive.fg_stroke.color = egui::Color32::from_rgb(235, 235, 235);
        visuals.widgets.active.fg_stroke.color = egui::Color32::from_rgb(255, 255, 255);
        visuals.widgets.hovered.fg_stroke.color = egui::Color32::from_rgb(255, 255, 255);
        cc.egui_ctx.set_visuals(visuals);
        let mut app = Self::default();
        app.instance_guard = instance_guard;
        let added = app.apply_initial_inputs(initial_inputs);
        app.note_inputs_added(added, "launch args");
        #[cfg(windows)]
        app.refresh_context_menu_status();
        app
    }

    fn apply_initial_inputs(&mut self, initial: Vec<PathBuf>) -> usize {
        if initial.is_empty() {
            return 0;
        }
        let mut accepted = Vec::new();
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        for path in initial {
            let candidate = if path.is_absolute() {
                path
            } else {
                cwd.join(path)
            };
            if candidate.exists() {
                accepted.push(candidate);
            } else {
                self.set_status(format!("Skipped missing path: {}", candidate.display()));
            }
        }
        if accepted.is_empty() {
            return 0;
        }
        self.inputs.extend(accepted.clone());
        if accepted.len() == 1 {
            let is_cipher = accepted[0]
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case(EXTENSION))
                .unwrap_or(false);
            if is_cipher {
                self.mode = Mode::Decrypt;
            }
        }
        accepted.len()
    }

    fn note_inputs_added(&mut self, count: usize, source: &str) {
        if count > 0 {
            self.set_status(format!("Loaded {count} file(s) into Inputs ({source})."));
        }
    }

    fn poll_launch_queue(&mut self) {
        if self.instance_guard.is_none() {
            return;
        }
        match take_queued_launches() {
            Ok(launches) => {
                let mut total_added = 0usize;
                for launch in launches {
                    total_added += self.apply_initial_inputs(launch.paths);
                }
                self.note_inputs_added(total_added, "Explorer");
            }
            Err(err) => self.set_status(format!("Failed to load queued inputs: {err}")),
        }
    }
}

impl eframe::App for SwatCryptApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_worker();
        self.poll_launch_queue();

        let prev_mode = self.mode;
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.heading("SwatCrypt");
            ui.horizontal(|ui| {
                ui.label("Mode:");
                ui.selectable_value(&mut self.mode, Mode::Encrypt, "Encrypt");
                ui.selectable_value(&mut self.mode, Mode::Decrypt, "Decrypt");
                if self.busy {
                    if let Some(f) = self.progress_fraction {
                        ui.add(egui::ProgressBar::new(f).desired_width(200.0));
                    }
                    if let Some(note) = &self.progress_note {
                        ui.label(note);
                    } else {
                        ui.label(egui::RichText::new("Working...").strong());
                    }
                }
            });
        });
        if self.mode != prev_mode {
            let mode = match self.mode {
                Mode::Encrypt => "Encrypt",
                Mode::Decrypt => "Decrypt",
            };
            self.set_status(format!("Mode set to {mode}."));
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.set_enabled(!self.busy);
            ui.spacing_mut().item_spacing = Vec2::new(10.0, 8.0);
            ui.spacing_mut().indent = 12.0;

            ui.heading("Inputs");
            self.inputs_ui(ui);
            ui.separator();

            ui.heading("Options");
            match self.mode {
                Mode::Encrypt => self.encrypt_options_ui(ui),
                Mode::Decrypt => self.decrypt_options_ui(ui),
            }
            ui.separator();

            self.actions_ui(ui);
            ui.separator();

            self.integration_ui(ui);
            ui.separator();

            self.status_ui(ui);
        });
    }
}

impl SwatCryptApp {
    fn inputs_ui(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("Add files").clicked() {
                if let Some(files) = rfd::FileDialog::new()
                    .set_title("Select files")
                    .pick_files()
                {
                    let added = self.apply_initial_inputs(files);
                    self.note_inputs_added(added, "picker");
                }
            }
            if ui.button("Add folder").clicked() {
                if let Some(folder) = rfd::FileDialog::new()
                    .set_title("Select folder")
                    .pick_folder()
                {
                    let added = self.apply_initial_inputs(vec![folder]);
                    self.note_inputs_added(added, "picker");
                }
            }
            if ui.button("Clear").clicked() {
                let removed = self.inputs.len();
                if removed > 0 {
                    self.set_status(format!("Cleared {removed} input(s)."));
                }
                self.inputs.clear();
            }
        });

        egui::ScrollArea::vertical()
            .id_source("inputs_scroll")
            .max_height(120.0)
            .show(ui, |ui| {
                if self.inputs.is_empty() {
                    ui.label("No inputs selected");
                } else {
                    for path in &self.inputs {
                        ui.label(path.display().to_string());
                    }
                }
            });

        ui.horizontal(|ui| {
            ui.label("Output path (optional):");
            let mut output_text = self
                .output
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default();
            let edited = ui.add(
                egui::TextEdit::singleline(&mut output_text)
                    .hint_text("leave empty to use default"),
            );
            if edited.changed() {
                if output_text.trim().is_empty() {
                    self.output = None;
                } else {
                    self.output = Some(PathBuf::from(output_text.trim()));
                }
            }
            if ui.button("Browse").clicked() {
                match self.mode {
                    Mode::Encrypt => {
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter("SwatCrypt", &[EXTENSION])
                            .save_file()
                        {
                            self.output = Some(path);
                            if let Some(out) = &self.output {
                                self.set_status(format!("Output path set to {}.", out.display()));
                            }
                        }
                    }
                    Mode::Decrypt => {
                        if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                            self.output = Some(folder);
                            if let Some(out) = &self.output {
                                self.set_status(format!("Output path set to {}.", out.display()));
                            }
                        }
                    }
                }
            }
            if ui.button("Use default").clicked() {
                self.output = None;
                self.set_status("Output path reset to default.");
            }
        });
    }

    fn encrypt_options_ui(&mut self, ui: &mut egui::Ui) {
        ui.checkbox(
            &mut self.compress,
            "Gzip before encrypting (off by default)",
        );
        ui.checkbox(
            &mut self.wipe,
            "Secure-wipe originals after successful encrypt (best effort)",
        );
        ui.horizontal(|ui| {
            ui.add_enabled_ui(self.wipe, |ui| {
                ui.checkbox(
                    &mut self.verify_after_encrypt,
                    "Verify decrypt before wiping originals",
                );
            });
            if self.wipe && !self.verify_after_encrypt {
                ui.label(egui::RichText::new("(risk of data loss)").weak());
            }
        });
        ui.horizontal(|ui| {
            ui.label("Chunk size (bytes, optional):");
            ui.add(
                egui::TextEdit::singleline(&mut self.chunk_size)
                    .hint_text("e.g. 65536")
                    .desired_width(120.0),
            );
        });
        ui.horizontal(|ui| {
            ui.label("Passphrase:");
            ui.add(
                egui::TextEdit::singleline(&mut self.passphrase)
                    .password(true)
                    .hint_text("required"),
            );
            ui.label("Confirm:");
            ui.add(
                egui::TextEdit::singleline(&mut self.passphrase_confirm)
                    .password(true)
                    .hint_text("repeat"),
            );
        });
    }

    fn decrypt_options_ui(&mut self, ui: &mut egui::Ui) {
        ui.checkbox(
            &mut self.force,
            "Allow writing into existing output directory",
        );
        ui.horizontal(|ui| {
            ui.label("Passphrase:");
            ui.add(
                egui::TextEdit::singleline(&mut self.passphrase)
                    .password(true)
                    .hint_text("required"),
            );
        });
    }

    #[cfg(windows)]
    fn integration_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Integration");
        let status = match self.context_menu_installed {
            Some(true) => "Installed",
            Some(false) => "Not installed",
            None => "Unknown",
        };
        ui.label(format!("Explorer context menus: {status}"));
        ui.horizontal(|ui| {
            let install_btn = ui.add_enabled(!self.context_menu_busy, egui::Button::new("Install"));
            if install_btn.clicked() {
                self.install_context_menus();
            }
            let remove_btn = ui.add_enabled(!self.context_menu_busy, egui::Button::new("Remove"));
            if remove_btn.clicked() {
                self.uninstall_context_menus();
            }
            let refresh_btn =
                ui.add_enabled(!self.context_menu_busy, egui::Button::new("Refresh status"));
            if refresh_btn.clicked() {
                self.refresh_context_menu_status();
            }
        });
        if let Some(note) = &self.context_menu_note {
            ui.label(note);
        }
    }

    #[cfg(not(windows))]
    fn integration_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Integration");
        ui.label("Explorer context menu toggle is available on Windows only.");
    }

    fn actions_ui(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| match self.mode {
            Mode::Encrypt => {
                if ui.button("Encrypt").clicked() {
                    self.start_encrypt();
                }
            }
            Mode::Decrypt => {
                if ui.button("Decrypt").clicked() {
                    self.start_decrypt();
                }
            }
        });
    }

    fn status_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Status");
        ui.horizontal(|ui| {
            if let Some(f) = self.progress_fraction {
                ui.add(egui::ProgressBar::new(f).desired_width(200.0));
            }
            if let Some(note) = &self.progress_note {
                ui.label(note);
            } else {
                ui.label("Ready.");
            }
        });
    }

    fn start_encrypt(&mut self) {
        if self.busy {
            return;
        }
        if self.inputs.is_empty() {
            self.set_status("Select at least one file or folder.");
            return;
        }
        if self.passphrase.is_empty() {
            self.set_status("Passphrase is required.");
            return;
        }
        if self.passphrase != self.passphrase_confirm {
            self.set_status("Passphrase confirmation does not match.");
            return;
        }
        let chunk_size = if self.chunk_size.trim().is_empty() {
            None
        } else {
            match self.chunk_size.trim().parse::<usize>() {
                Ok(v) => Some(v),
                Err(_) => {
                    self.set_status("Chunk size must be a number.");
                    return;
                }
            }
        };

        let inputs = self.inputs.clone();
        let output = self
            .output
            .clone()
            .unwrap_or_else(|| infer_encrypt_output(&inputs));
        let passphrase = Some(self.passphrase.clone());
        let compress = self.compress;
        let kdf = KdfConfig::default();
        let verify_before_wipe = self.wipe && self.verify_after_encrypt;

        let (tx, rx) = mpsc::channel();
        self.worker_rx = Some(rx);
        self.busy = true;
        self.progress_fraction = Some(0.0);
        self.progress_note = Some("Starting...".into());
        self.set_status(format!("Encrypting into {} ...", output.display()));

        thread::spawn(move || {
            let progress_tx = tx.clone();
            let hook_tx = tx.clone();
            let progress_hook = Box::new(move |update: ProgressUpdate| {
                let frac = update
                    .total
                    .map(|t| (update.processed as f32 / t as f32).min(1.0));
                let stage = match update.stage {
                    ProgressStage::Encrypt => "Encrypting",
                    ProgressStage::Decrypt => "Decrypting",
                };
                let note = match frac {
                    Some(f) => format!("{stage} {:.1}%", f * 100.0),
                    None => stage.to_string(),
                };
                let _ = hook_tx.send(WorkerMsg::Progress {
                    fraction: frac,
                    note,
                });
            });

            let res = (|| {
                let enc_res = encrypt(EncryptRequest {
                    inputs,
                    output: output.clone(),
                    passphrase: passphrase.clone(),
                    keyfile: None,
                    compression: compress,
                    chunk_size,
                    kdf,
                    progress: Some(progress_hook),
                })
                .map_err(|e| e.to_string())?;

                if verify_before_wipe {
                    let _ = progress_tx.send(WorkerMsg::Progress {
                        fraction: Some(0.95),
                        note: "Self-check decrypt...".into(),
                    });
                    let tmp = tempdir().map_err(|e| e.to_string())?;
                    let verify_out = tmp.path().join("verify");
                    decrypt(DecryptRequest {
                        input: output.clone(),
                        output_dir: verify_out,
                        passphrase: passphrase.clone(),
                        keyfile: None,
                        overwrite: true,
                        progress: None,
                    })
                    .map_err(|e| format!("self-check decrypt failed: {e}"))?;
                }

                Ok(enc_res)
            })();

            let _ = tx.send(WorkerMsg::Encrypt(res));
        });
    }

    fn start_decrypt(&mut self) {
        if self.busy {
            return;
        }
        if self.inputs.len() != 1 {
            self.set_status("Pick exactly one .swc file to decrypt.");
            return;
        }
        let input = self.inputs[0].clone();
        let (output_dir, output_note) = sanitize_decrypt_output(&input, self.output.clone());
        if let Some(note) = output_note {
            self.set_status(note);
        }
        let passphrase = if self.passphrase.is_empty() {
            None
        } else {
            Some(self.passphrase.clone())
        };
        let overwrite = self.force;
        if passphrase.is_none() {
            self.set_status("Passphrase is required.");
            return;
        }

        let (tx, rx) = mpsc::channel();
        self.worker_rx = Some(rx);
        self.busy = true;
        self.progress_fraction = Some(0.0);
        self.progress_note = Some("Starting...".into());
        self.set_status(format!(
            "Decrypting {} -> {} ...",
            input.display(),
            output_dir.display()
        ));

        thread::spawn(move || {
            let progress_tx = tx.clone();
            let progress_hook = Box::new(move |update: ProgressUpdate| {
                let frac = update
                    .total
                    .map(|t| (update.processed as f32 / t as f32).min(1.0));
                let stage = match update.stage {
                    ProgressStage::Encrypt => "Encrypting",
                    ProgressStage::Decrypt => "Decrypting",
                };
                let note = match frac {
                    Some(f) => format!("{stage} {:.1}%", f * 100.0),
                    None => stage.to_string(),
                };
                let _ = progress_tx.send(WorkerMsg::Progress {
                    fraction: frac,
                    note,
                });
            });

            let res = decrypt(DecryptRequest {
                input,
                output_dir,
                passphrase,
                keyfile: None,
                overwrite,
                progress: Some(progress_hook),
            })
            .map_err(|e| e.to_string());
            let _ = tx.send(WorkerMsg::Decrypt(res));
        });
    }

    fn poll_worker(&mut self) {
        if let Some(rx) = &self.worker_rx {
            match rx.try_recv() {
                Ok(WorkerMsg::Encrypt(res)) => {
                    self.busy = false;
                    self.progress_fraction = None;
                    self.progress_note = None;
                    self.worker_rx = None;
                    match res {
                        Ok(done) => {
                            self.set_status(format!(
                                "Encrypted {} entries -> {}",
                                done.manifest_entries,
                                done.output.display()
                            ));
                            if self.wipe {
                                match secure_wipe_paths(&self.inputs) {
                                    Ok(_) => self.set_status("Originals wiped."),
                                    Err(err) => self.set_status(format!(
                                        "Wipe failed (files may remain): {err}"
                                    )),
                                }
                            }
                            self.reset_after_success();
                        }
                        Err(err) => self.set_status(format!("Encrypt failed: {err}")),
                    }
                }
                Ok(WorkerMsg::Decrypt(res)) => {
                    self.busy = false;
                    self.progress_fraction = None;
                    self.progress_note = None;
                    self.worker_rx = None;
                    let success = match res {
                        Ok(done) => {
                            self.set_status(format!(
                                "Decrypted {} entries into {}",
                                done.manifest_entries,
                                done.output_dir.display()
                            ));
                            true
                        }
                        Err(err) => {
                            if err == "decryption failed" {
                                self.set_status(
                                    "Decrypt failed: likely wrong passphrase or corrupted file.",
                                );
                            } else {
                                self.set_status(format!("Decrypt failed: {err}"));
                            }
                            false
                        }
                    };
                    if success {
                        self.reset_after_success();
                    }
                }
                Ok(WorkerMsg::Progress { fraction, note }) => {
                    self.progress_fraction = fraction.or(self.progress_fraction);
                    self.progress_note = Some(note);
                }
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    self.busy = false;
                    self.progress_fraction = None;
                    self.progress_note = None;
                    self.worker_rx = None;
                    self.set_status("Worker thread disconnected.");
                }
            }
        }
    }

    fn set_status(&mut self, msg: impl Into<String>) {
        self.progress_note = Some(msg.into());
    }

    fn reset_after_success(&mut self) {
        self.inputs.clear();
        self.output = None;
        self.passphrase.clear();
        self.passphrase_confirm.clear();
        self.chunk_size.clear();
        self.progress_fraction = None;
        self.progress_note = None;
    }

    #[cfg(windows)]
    fn install_context_menus(&mut self) {
        self.context_menu_busy = true;
        self.set_status("Installing Explorer context menus...");
        let result = (|| -> Result<()> {
            let exe = std::env::current_exe().context("resolve current executable")?;
            context_menu::install(&exe)
        })();
        match result {
            Ok(()) => {
                self.context_menu_note = Some("Context menus installed.".into());
                self.context_menu_installed = Some(true);
                self.set_status("Explorer context menus installed.");
            }
            Err(err) => {
                self.context_menu_note = Some(format!("Install failed: {err}"));
                self.set_status(format!("Context menu install failed: {err}"));
            }
        }
        self.context_menu_busy = false;
    }

    #[cfg(windows)]
    fn uninstall_context_menus(&mut self) {
        self.context_menu_busy = true;
        self.set_status("Removing Explorer context menus...");
        match context_menu::uninstall() {
            Ok(()) => {
                self.context_menu_note = Some("Context menus removed.".into());
                self.context_menu_installed = Some(false);
                self.set_status("Explorer context menus removed.");
            }
            Err(err) => {
                self.context_menu_note = Some(format!("Remove failed: {err}"));
                self.set_status(format!("Context menu removal failed: {err}"));
            }
        }
        self.context_menu_busy = false;
    }

    #[cfg(windows)]
    fn refresh_context_menu_status(&mut self) {
        let installed = context_menu::is_installed();
        self.context_menu_installed = Some(installed);
        self.context_menu_note = None;
        self.set_status(if installed {
            "Explorer context menus are installed."
        } else {
            "Explorer context menus are not installed."
        });
    }
}

mod cli {
    use super::*;

    #[derive(Parser)]
    #[command(
        name = "swatcrypt",
        about = "SwatCrypt: GUI or CLI (pass args for CLI, none for GUI)",
        disable_help_subcommand = true,
        arg_required_else_help = false
    )]
    pub struct Cli {
        /// Open the GUI and pre-load these paths (skips CLI commands)
        #[arg(
            long,
            value_name = "PATH",
            value_hint = ValueHint::AnyPath,
            num_args = 0..
        )]
        open_gui: Vec<PathBuf>,

        /// Optional launch directory (internal, set by shell verb)
        #[arg(long, hide = true, value_hint = ValueHint::DirPath)]
        launch_dir: Option<PathBuf>,

        #[command(subcommand)]
        command: Option<Command>,
    }

    pub enum LaunchMode {
        Gui {
            open_paths: Vec<PathBuf>,
            launch_dir: Option<PathBuf>,
        },
        Cli(Command),
    }

    #[derive(Subcommand)]
    pub enum Command {
        Encrypt(EncryptArgs),
        Decrypt(DecryptArgs),
        Info(InfoArgs),
    }

    #[derive(ClapArgs, Debug)]
    pub struct EncryptArgs {
        /// Files or folders to encrypt
        #[arg(required = true, value_hint = ValueHint::AnyPath)]
        pub inputs: Vec<PathBuf>,

        /// Output .swc file
        #[arg(short, long, value_hint = ValueHint::AnyPath)]
        pub output: Option<PathBuf>,

        /// Enable gzip compression before encrypting
        #[arg(long)]
        pub compress: bool,

        /// Secure-wipe originals after successful encryption
        #[arg(long)]
        pub wipe: bool,

        /// Passphrase (prompted if missing)
        #[arg(long)]
        pub passphrase: Option<String>,

        /// Chunk size used for streaming encryption (bytes)
        #[arg(long)]
        pub chunk_size: Option<usize>,

        /// Overwrite existing output file
        #[arg(long)]
        pub force: bool,
    }

    #[derive(ClapArgs, Debug)]
    pub struct DecryptArgs {
        /// Encrypted .swc file
        #[arg(value_hint = ValueHint::AnyPath)]
        pub input: PathBuf,

        /// Output folder to restore into
        #[arg(short, long, value_hint = ValueHint::DirPath)]
        pub output: Option<PathBuf>,

        /// Passphrase (prompted if missing)
        #[arg(long)]
        pub passphrase: Option<String>,

        /// Allow writing into a non-empty output directory
        #[arg(long)]
        pub force: bool,
    }

    #[derive(ClapArgs, Debug)]
    pub struct InfoArgs {
        /// Encrypted .swc file
        #[arg(value_hint = ValueHint::AnyPath)]
        pub input: PathBuf,
    }

    pub fn parse_mode() -> LaunchMode {
        let cli = Cli::parse();
        if !cli.open_gui.is_empty() && cli.command.is_some() {
            eprintln!("--open-gui cannot be combined with subcommands");
            std::process::exit(2);
        }
        match cli.command {
            Some(command) => LaunchMode::Cli(command),
            None => LaunchMode::Gui {
                open_paths: cli.open_gui,
                launch_dir: cli.launch_dir,
            },
        }
    }

    pub fn run_command(command: Command) -> Result<()> {
        match command {
            Command::Encrypt(args) => run_encrypt(args),
            Command::Decrypt(args) => run_decrypt(args),
            Command::Info(args) => run_info(args),
        }
    }

    fn run_encrypt(args: EncryptArgs) -> Result<()> {
        let output = args
            .output
            .clone()
            .unwrap_or_else(|| infer_encrypt_output(&args.inputs));

        if output.exists() && !args.force {
            bail!(
                "output {} already exists (pass --force to overwrite)",
                output.display()
            );
        }

        let passphrase = resolve_passphrase(args.passphrase.as_ref(), true)?;
        let (pb, progress) = make_progress(ProgressStage::Encrypt);
        let req = EncryptRequest {
            inputs: args.inputs.clone(),
            output: output.clone(),
            passphrase: Some(passphrase),
            keyfile: None,
            compression: args.compress,
            chunk_size: args.chunk_size,
            kdf: KdfConfig::default(),
            progress: Some(progress),
        };

        match encrypt(req) {
            Ok(result) => {
                pb.finish_with_message("Encrypt done");
                println!(
                    "Encrypted {} items -> {} (compressed: {}, size ~{} KiB)",
                    result.manifest_entries,
                    result.output.display(),
                    result.compressed,
                    result.bytes_written / 1024
                );
                if args.wipe {
                    secure_wipe_paths(&args.inputs).context("secure wipe failed")?;
                    println!("Original files wiped.");
                }
                Ok(())
            }
            Err(err) => {
                pb.abandon_with_message("Encrypt failed");
                Err(anyhow!("encryption failed: {err}"))
            }
        }
    }

    fn run_decrypt(args: DecryptArgs) -> Result<()> {
        let output = args
            .output
            .clone()
            .unwrap_or_else(|| infer_decrypt_output(&args.input));

        if output.exists() && !args.force {
            if output.is_dir() && std::fs::read_dir(&output)?.next().is_some() {
                bail!(
                    "output directory {} is not empty (pass --force to continue)",
                    output.display()
                );
            } else if output.is_file() {
                bail!(
                    "output path {} exists and is not a directory (pass --force to overwrite)",
                    output.display()
                );
            }
        }

        let passphrase = resolve_passphrase(args.passphrase.as_ref(), false)?;
        let (pb, progress) = make_progress(ProgressStage::Decrypt);
        let req = DecryptRequest {
            input: args.input.clone(),
            output_dir: output.clone(),
            passphrase: Some(passphrase),
            keyfile: None,
            overwrite: args.force,
            progress: Some(progress),
        };

        match decrypt(req) {
            Ok(result) => {
                pb.finish_with_message("Decrypt done");
                println!(
                    "Decrypted {} entries into {}",
                    result.manifest_entries,
                    result.output_dir.display()
                );
                Ok(())
            }
            Err(err) => {
                pb.abandon_with_message("Decrypt failed");
                Err(anyhow!("decryption failed: {err}"))
            }
        }
    }

    fn run_info(args: InfoArgs) -> Result<()> {
        let info = inspect_header(&args.input).context("failed to read header")?;
        println!("File: {}", args.input.display());
        println!("Cipher: {:?}", info.cipher);
        println!(
            "KDF: {:?} (mem {} MiB, iters {}, parallelism {})",
            info.kdf, info.kdf_params.mem_mib, info.kdf_params.iterations, info.kdf_params.parallelism
        );
        println!(
            "Flags: bundle={}, compressed={}",
            (info.flags & 0x01) != 0,
            (info.flags & 0x02) != 0
        );
        println!(
            "Chunk size: {} (plaintext), salt: {} bytes, nonce: {} bytes",
            format_size(info.chunk_size, BINARY),
            info.salt_len,
            info.nonce_len
        );
        Ok(())
    }

    fn resolve_passphrase(from_arg: Option<&String>, confirm: bool) -> Result<String> {
        if let Some(p) = from_arg {
            if p.is_empty() {
                bail!("passphrase cannot be empty");
            }
            return Ok(p.clone());
        }
        let first = prompt_password("Passphrase: ")?;
        if first.is_empty() {
            bail!("passphrase cannot be empty");
        }
        if confirm {
            let second = prompt_password("Confirm passphrase: ")?;
            if first != second {
                bail!("passphrases did not match");
            }
        }
        Ok(first)
    }

    fn make_progress(stage: ProgressStage) -> (ProgressBar, ProgressCallback) {
        let label = match stage {
            ProgressStage::Encrypt => "Encrypting",
            ProgressStage::Decrypt => "Decrypting",
        };
        let pb = ProgressBar::new(1);
        pb.set_style(
            ProgressStyle::with_template("{msg} [{bar:40.cyan/blue}] {percent:>3}%")
                .unwrap()
                .progress_chars("=>-"),
        );
        pb.set_message(label);
        let pb_clone = pb.clone();
        let cb: ProgressCallback = Box::new(move |update: ProgressUpdate| {
            if let Some(total) = update.total {
                if pb_clone.length().unwrap_or(0) != total {
                    pb_clone.set_length(total);
                }
            }
            pb_clone.set_position(update.processed);
        });
        (pb, cb)
    }
}

fn infer_encrypt_output(inputs: &[PathBuf]) -> PathBuf {
    if inputs.len() == 1 {
        let p = &inputs[0];
        let parent = p.parent().unwrap_or_else(|| Path::new("."));
        let stem = p
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("swatcrypt");
        parent.join(format!("{stem}.{EXTENSION}"))
    } else {
        PathBuf::from(format!("bundle.{EXTENSION}"))
    }
}

fn infer_decrypt_output(input: &Path) -> PathBuf {
    let parent = input.parent().unwrap_or_else(|| Path::new("."));
    let stem = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("swatcrypt");
    parent.join(format!("{stem}_dec"))
}

fn sanitize_decrypt_output(input: &Path, requested: Option<PathBuf>) -> (PathBuf, Option<String>) {
    let default_path = infer_decrypt_output(input);
    let Some(out) = requested else {
        return (default_path, None);
    };

    let is_ext = out
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case(EXTENSION))
        .unwrap_or(false);

    if is_ext {
        let note = Some(format!(
            "Output path looked like an .{EXTENSION} file; using {} instead.",
            default_path.display()
        ));
        return (default_path, note);
    }

    if out.exists() && out.is_file() {
        let note = Some(format!(
            "Output path {} is a file; using {} instead.",
            out.display(),
            default_path.display()
        ));
        return (default_path, note);
    }

    (out, None)
}

fn load_icon() -> Option<IconData> {
    let (w, h) = (64u32, 64u32);
    let mut rgba = vec![0u8; (w * h * 4) as usize];

    let mut put_rect = |x0: u32, y0: u32, x1: u32, y1: u32, r: u8, g: u8, b: u8, a: u8| {
        for y in y0..y1 {
            for x in x0..x1 {
                let idx = ((y * w + x) * 4) as usize;
                rgba[idx] = r;
                rgba[idx + 1] = g;
                rgba[idx + 2] = b;
                rgba[idx + 3] = a;
            }
        }
    };

    // Body of lock
    put_rect(18, 28, 46, 52, 200, 16, 16, 255);
    // Shackle
    put_rect(22, 16, 42, 28, 220, 40, 40, 255);
    put_rect(26, 12, 38, 16, 220, 40, 40, 255);
    // Keyhole
    put_rect(30, 36, 34, 44, 0, 0, 0, 255);
    put_rect(30, 44, 34, 48, 0, 0, 0, 180);

    Some(IconData {
        rgba,
        width: w,
        height: h,
    })
}

#[cfg(windows)]
mod context_menu {
    use std::path::Path;

    use anyhow::{Context, Result};
    use winreg::{enums::HKEY_CURRENT_USER, RegKey};

    const ENCRYPT_KEY: &str = r"Software\Classes\*\shell\SwatCryptEncrypt";
    const ENCRYPT_CMD_KEY: &str = r"Software\Classes\*\shell\SwatCryptEncrypt\command";
    const DECRYPT_KEY: &str = r"Software\Classes\SystemFileAssociations\.swc\shell\SwatCryptDecrypt";
    const DECRYPT_CMD_KEY: &str = r"Software\Classes\SystemFileAssociations\.swc\shell\SwatCryptDecrypt\command";
    const GUI_KEY: &str = r"Software\Classes\*\shell\SwatCryptGui";
    const GUI_CMD_KEY: &str = r"Software\Classes\*\shell\SwatCryptGui\command";

    pub fn install(bin: &Path) -> Result<()> {
        let bin_str = normalize_path(bin)?;
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);

        // Clean up any legacy encrypt verb so it disappears from Explorer.
        let _ = hkcu.delete_subkey_all(ENCRYPT_KEY);
        let _ = hkcu.delete_subkey_all(ENCRYPT_CMD_KEY);

        write_entry(
            &hkcu,
            DECRYPT_KEY,
            DECRYPT_CMD_KEY,
            "Decrypt with SwatCrypt",
            "Document",
            &bin_str,
            &format!("\"{bin_str}\" decrypt \"%1\""),
        )?;
        write_entry(
            &hkcu,
            GUI_KEY,
            GUI_CMD_KEY,
            "Open in SwatCrypt",
            "Document",
            &bin_str,
            &format!("\"{bin_str}\" --open-gui \"%1\""),
        )?;
        Ok(())
    }

    pub fn uninstall() -> Result<()> {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        for key in [ENCRYPT_KEY, ENCRYPT_CMD_KEY, DECRYPT_KEY, GUI_KEY] {
            let _ = hkcu.delete_subkey_all(key);
        }
        Ok(())
    }

    pub fn is_installed() -> bool {
        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        for key in [DECRYPT_CMD_KEY, GUI_CMD_KEY] {
            if hkcu.open_subkey(key).is_err() {
                return false;
            }
        }
        true
    }

    fn write_entry(
        hkcu: &RegKey,
        verb_key: &str,
        cmd_key: &str,
        label: &str,
        multi_model: &str,
        icon_path: &str,
        command: &str,
    ) -> Result<()> {
        let (verb, _) = hkcu.create_subkey(verb_key)?;
        verb.set_value("MUIVerb", &label)?;
        verb.set_value("Icon", &icon_path)?;
        verb.set_value("MultiSelectModel", &multi_model)?;

        let (cmd, _) = hkcu.create_subkey(cmd_key)?;
        cmd.set_value("", &command)?;
        Ok(())
    }

    fn normalize_path(path: &Path) -> Result<String> {
        let raw = path
            .to_str()
            .context("executable path must be valid UTF-8 for registry")?;
        // Avoid the verbatim \?\ prefix; some shell verbs refuse it.
        let trimmed = raw.strip_prefix(r"\\?\").unwrap_or(raw);
        Ok(trimmed.to_string())
    }

}

#[cfg(not(windows))]
mod context_menu {
    use std::path::Path;

    use anyhow::{anyhow, Result};

    pub fn install(_: &Path) -> Result<()> {
        Err(anyhow!("Explorer context menus are available on Windows only"))
    }

    pub fn uninstall() -> Result<()> {
        Err(anyhow!("Explorer context menus are available on Windows only"))
    }

    pub fn is_installed() -> bool {
        false
    }
}
