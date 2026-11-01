//! Uses the system's own UI fonts instead of bundling fonts in the exe,
//! which keeps the binary small and makes the window look native.

use eframe::egui::{self, FontData, FontDefinitions, FontFamily};
use std::sync::Arc;

fn candidates() -> (Vec<std::path::PathBuf>, Vec<std::path::PathBuf>) {
    #[cfg(windows)]
    {
        let fonts = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into()))
            .join("Fonts");
        (
            vec![
                fonts.join("segoeui.ttf"),
                fonts.join("tahoma.ttf"),
                fonts.join("arial.ttf"),
                fonts.join("seguisym.ttf"),
            ],
            vec![fonts.join("consola.ttf"), fonts.join("cour.ttf")],
        )
    }
    #[cfg(not(windows))]
    {
        let base = std::path::Path::new("/usr/share/fonts/truetype");
        (
            vec![
                base.join("dejavu/DejaVuSans.ttf"),
                base.join("liberation/LiberationSans-Regular.ttf"),
            ],
            vec![
                base.join("dejavu/DejaVuSansMono.ttf"),
                base.join("liberation/LiberationMono-Regular.ttf"),
            ],
        )
    }
}

pub fn install(ctx: &egui::Context) {
    let mut defs = FontDefinitions::empty();
    let (prop, mono) = candidates();
    let load = |paths: Vec<std::path::PathBuf>, family: FontFamily, defs: &mut FontDefinitions| {
        for (i, p) in paths.iter().enumerate() {
            if let Ok(bytes) = std::fs::read(p) {
                let name = format!("{family:?}-{i}");
                defs.font_data
                    .insert(name.clone(), Arc::new(FontData::from_owned(bytes)));
                defs.families.entry(family.clone()).or_default().push(name);
            }
        }
    };
    load(prop, FontFamily::Proportional, &mut defs);
    load(mono, FontFamily::Monospace, &mut defs);
    // Each family falls back to the other so text always renders.
    let p = defs
        .families
        .get(&FontFamily::Proportional)
        .cloned()
        .unwrap_or_default();
    let m = defs.families.get(&FontFamily::Monospace).cloned().unwrap_or_default();
    defs.families
        .entry(FontFamily::Monospace)
        .or_default()
        .extend(p.clone());
    defs.families.entry(FontFamily::Proportional).or_default().extend(m);
    if !p.is_empty() {
        ctx.set_fonts(defs);
    }
    ctx.global_style_mut(|s| {
        s.spacing.item_spacing = egui::vec2(8.0, 6.0);
        s.spacing.button_padding = egui::vec2(10.0, 4.0);
    });
}
