use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn find_webview2_loader_for_arch(build_dir: &Path, arch_subdir: &str) -> Option<PathBuf> {
    let entries = fs::read_dir(build_dir).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.starts_with("webview2-com-sys-") {
            let candidate = entry
                .path()
                .join("out")
                .join(arch_subdir)
                .join("WebView2Loader.dll");
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    None
}

fn find_windres_executable(home_dirs: &[PathBuf], mingw_triple: &str) -> Option<PathBuf> {
    let prefixed = format!("{mingw_triple}-windres.exe");
    let mut search_dirs: Vec<PathBuf> = Vec::new();
    for home_path in home_dirs {
        search_dirs.push(home_path.join(".llvm-mingw").join("bin"));
        search_dirs.push(
            home_path
                .join(".llvm-mingw")
                .join(mingw_triple)
                .join("bin"),
        );
    }
    if let Some(path_os) = env::var_os("PATH") {
        search_dirs.extend(env::split_paths(&path_os));
    }

    for bin_name in [prefixed.as_str(), "llvm-windres.exe", "windres.exe"] {
        for dir in &search_dirs {
            let candidate = dir.join(bin_name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn find_mingw_clang_executable(
    home_dirs: &[PathBuf],
    mingw_triple: &str,
) -> Option<(PathBuf, bool)> {
    let prefixed_clang = format!("{mingw_triple}-clang.exe");
    let prefixed_gcc = format!("{mingw_triple}-gcc.exe");
    let mut search_dirs: Vec<PathBuf> = Vec::new();
    for home_path in home_dirs {
        search_dirs.push(home_path.join(".llvm-mingw").join("bin"));
        search_dirs.push(
            home_path
                .join(".llvm-mingw")
                .join(mingw_triple)
                .join("bin"),
        );
    }
    if let Some(path_os) = env::var_os("PATH") {
        search_dirs.extend(env::split_paths(&path_os));
    }

    for (bin_name, needs_target_flag) in [
        (prefixed_clang.as_str(), false),
        (prefixed_gcc.as_str(), false),
        ("clang.exe", true),
    ] {
        for dir in &search_dirs {
            let candidate = dir.join(bin_name);
            if candidate.is_file() {
                return Some((candidate, needs_target_flag));
            }
        }
    }
    None
}

fn find_mingw_static_libunwind(home_dirs: &[PathBuf], mingw_triple: &str) -> Option<PathBuf> {
    for home_path in home_dirs {
        let candidate = home_path
            .join(".llvm-mingw")
            .join(mingw_triple)
            .join("lib")
            .join("libunwind.a");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    if let Some(path_os) = env::var_os("PATH") {
        for dir in env::split_paths(&path_os) {
            if let Some(root) = dir.parent() {
                let candidate = root.join(mingw_triple).join("lib").join("libunwind.a");
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

fn configure_mingw_static_unwind_and_delayload(
    out_path: &Path,
    home_dirs: &[PathBuf],
    mingw_triple: &str,
) {
    // 1. Statically link `libunwind` by shadowing `libunwind.dll.a` in `OUT_DIR` so standalone
    // `.exe` binaries (`alluse-setup.exe`, `alluse-uninstall.exe`, `alluse.exe`) never fail with
    // `0xC0000135 STATUS_DLL_NOT_FOUND` on `libunwind.dll`.
    if let Some(static_unwind) = find_mingw_static_libunwind(home_dirs, mingw_triple) {
        let shadow_unwind = out_path.join("libunwind.dll.a");
        if fs::copy(&static_unwind, &shadow_unwind).is_ok() {
            println!("cargo:rustc-link-search=native={}", out_path.display());
        }
    }

    // 2. Delay-load `WebView2Loader.dll` via a custom `__delayLoadHelper2` that checks
    // `GetModuleHandleA` first (allowing `alluse-setup` GUI to preload an embedded `%TEMP%` copy)
    // and falls back to `LoadLibraryA` (allowing `alluse.exe` to load its sibling DLL).
    let delayhelper_c = concat!(
        "#include <windows.h>\n",
        "#include <delayimp.h>\n",
        "#include <stddef.h>\n",
        "\n",
        "extern IMAGE_DOS_HEADER __ImageBase;\n",
        "\n",
        "FARPROC WINAPI __delayLoadHelper2(PCImgDelayDescr pidd, FARPROC *ppfnIATEntry) {\n",
        "    LPCSTR dllName = (LPCSTR)((const BYTE *)&__ImageBase + pidd->rvaDLLName);\n",
        "    HMODULE hMod = GetModuleHandleA(dllName);\n",
        "    if (!hMod) {\n",
        "        hMod = LoadLibraryA(dllName);\n",
        "    }\n",
        "    if (!hMod) {\n",
        "        return NULL;\n",
        "    }\n",
        "    PIMAGE_THUNK_DATA pINT = (PIMAGE_THUNK_DATA)((const BYTE *)&__ImageBase + pidd->rvaINT);\n",
        "    PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)((const BYTE *)&__ImageBase + pidd->rvaIAT);\n",
        "    SIZE_T idx = (SIZE_T)(ppfnIATEntry - (FARPROC *)pIAT);\n",
        "    PIMAGE_THUNK_DATA pThunk = &pINT[idx];\n",
        "    FARPROC pfn = NULL;\n",
        "    if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal)) {\n",
        "        pfn = GetProcAddress(hMod, MAKEINTRESOURCEA(IMAGE_ORDINAL(pThunk->u1.Ordinal)));\n",
        "    } else {\n",
        "        PIMAGE_IMPORT_BY_NAME pibn = (PIMAGE_IMPORT_BY_NAME)((const BYTE *)&__ImageBase + pThunk->u1.AddressOfData);\n",
        "        pfn = GetProcAddress(hMod, (LPCSTR)pibn->Name);\n",
        "    }\n",
        "    if (pfn) {\n",
        "        *ppfnIATEntry = pfn;\n",
        "    }\n",
        "    return pfn;\n",
        "}\n",
    );

    let c_path = out_path.join("delayhelper.c");
    let obj_path = out_path.join("delayhelper.o");
    if fs::write(&c_path, delayhelper_c.as_bytes()).is_err() {
        return;
    }

    if let Some((cc_bin, needs_target_flag)) = find_mingw_clang_executable(home_dirs, mingw_triple)
    {
        let mut cmd = Command::new(&cc_bin);
        cmd.current_dir(out_path);
        if needs_target_flag {
            cmd.arg(format!("--target={mingw_triple}"));
        }
        let status = cmd
            .args(["-O2", "-c", "delayhelper.c", "-o", "delayhelper.o"])
            .status();
        if status.is_ok_and(|s| s.success()) && obj_path.is_file() {
            println!("cargo:rustc-link-arg={}", obj_path.display());
            println!("cargo:rustc-link-arg=-Wl,-delayload,WebView2Loader.dll");
        }
    }
}

fn is_valid_ico_bytes(bytes: &[u8]) -> bool {
    if bytes.len() < 22 || &bytes[0..4] != &[0, 0, 1, 0] {
        return false;
    }
    let count = u16::from_le_bytes([bytes[4], bytes[5]]) as usize;
    count > 0 && 6 + count * 16 <= bytes.len()
}

fn build_png_fallback_ico_bytes(png_bytes: &[u8]) -> Option<Vec<u8>> {
    const PNG_SIG: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
    if png_bytes.len() < 24 || !png_bytes.starts_with(PNG_SIG) || &png_bytes[12..16] != b"IHDR" {
        return None;
    }
    let width = u32::from_be_bytes([png_bytes[16], png_bytes[17], png_bytes[18], png_bytes[19]]);
    let height = u32::from_be_bytes([png_bytes[20], png_bytes[21], png_bytes[22], png_bytes[23]]);
    let ico_w = if width >= 256 || width == 0 {
        0u8
    } else {
        width.min(255) as u8
    };
    let ico_h = if height >= 256 || height == 0 {
        0u8
    } else {
        height.min(255) as u8
    };
    let len_u32 = u32::try_from(png_bytes.len()).ok()?;
    let mut out = Vec::with_capacity(22 + png_bytes.len());
    out.extend_from_slice(&[0, 0, 1, 0, 1, 0]);
    out.extend_from_slice(&[ico_w, ico_h, 0, 0]);
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&32u16.to_le_bytes());
    out.extend_from_slice(&len_u32.to_le_bytes());
    out.extend_from_slice(&22u32.to_le_bytes());
    out.extend_from_slice(png_bytes);
    Some(out)
}

fn resolve_windows_ico_bytes(manifest_dir: &Path) -> Option<Vec<u8>> {
    let candidates = [
        manifest_dir
            .join("target")
            .join("installer-icons")
            .join("alluse.ico"),
        manifest_dir.join("assets").join("alluse.ico"),
    ];
    for path in candidates {
        if let Ok(bytes) = fs::read(&path) {
            if is_valid_ico_bytes(&bytes) {
                return Some(bytes);
            }
        }
    }
    let png_path = manifest_dir.join("assets").join("cheapai_logo_icon.png");
    let png_bytes = fs::read(png_path).ok()?;
    build_png_fallback_ico_bytes(&png_bytes)
}

fn push_win32_res_entry(
    out: &mut Vec<u8>,
    res_type: u16,
    res_id: u16,
    memory_flags: u16,
    data: &[u8],
) -> Option<()> {
    let data_size = u32::try_from(data.len()).ok()?;
    out.extend_from_slice(&data_size.to_le_bytes()); // DataSize
    out.extend_from_slice(&32u32.to_le_bytes()); // HeaderSize
    out.extend_from_slice(&0xFFFFu16.to_le_bytes()); // Type ordinal marker
    out.extend_from_slice(&res_type.to_le_bytes());
    out.extend_from_slice(&0xFFFFu16.to_le_bytes()); // Name ordinal marker
    out.extend_from_slice(&res_id.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // DataVersion
    out.extend_from_slice(&memory_flags.to_le_bytes()); // MemoryFlags
    out.extend_from_slice(&0x0409u16.to_le_bytes()); // LanguageId (en-US)
    out.extend_from_slice(&0u32.to_le_bytes()); // Version
    out.extend_from_slice(&0u32.to_le_bytes()); // Characteristics
    out.extend_from_slice(data);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    Some(())
}

/// Pure-Rust Win32 `.res` serializer (`RT_ICON` 1..=N + `RT_GROUP_ICON` id 1) so
/// MSVC (`link.exe`) embeds multi-resolution PE icons deterministically without requiring `rc.exe` on `PATH`.
fn build_win32_icon_res(ico: &[u8]) -> Option<Vec<u8>> {
    if !is_valid_ico_bytes(ico) {
        return None;
    }
    let count = u16::from_le_bytes([ico[4], ico[5]]);
    let mut out = Vec::with_capacity(64 + ico.len());
    // Standard 32-byte null Win32 RES file header
    out.extend_from_slice(&[
        0, 0, 0, 0, 32, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0,
    ]);

    let mut grp = Vec::with_capacity(6 + usize::from(count) * 14);
    grp.extend_from_slice(&0u16.to_le_bytes()); // idReserved
    grp.extend_from_slice(&1u16.to_le_bytes()); // idType = ICON
    grp.extend_from_slice(&count.to_le_bytes()); // idCount

    for idx in 0..usize::from(count) {
        let off = 6 + idx * 16;
        let entry = &ico[off..off + 16];
        let size_in_res = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]) as usize;
        let img_off = u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]) as usize;
        let end = img_off.checked_add(size_in_res)?;
        if end > ico.len() || size_in_res == 0 {
            return None;
        }
        let icon_id = u16::try_from(idx + 1).ok()?;
        push_win32_res_entry(&mut out, 3, icon_id, 0x1010, &ico[img_off..end])?;
        grp.extend_from_slice(&entry[0..12]);
        grp.extend_from_slice(&icon_id.to_le_bytes());
    }
    push_win32_res_entry(&mut out, 14, 1, 0x1030, &grp)?;
    Some(out)
}

fn embed_windows_manifest_and_icon(
    out_path: &Path,
    manifest_dir: &Path,
    target_env: &str,
    home_dirs: &[PathBuf],
    mingw_triple: &str,
) {
    let ico_bytes = resolve_windows_ico_bytes(manifest_dir);
    let ico_out = out_path.join("alluse.ico");
    let has_ico_file = ico_bytes
        .as_ref()
        .is_some_and(|b| fs::write(&ico_out, b).is_ok());

    if target_env == "msvc" {
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg=/MANIFESTUAC:level='asInvoker' uiAccess='false'");
        let ico = ico_bytes.expect("Windows icon bytes must resolve for MSVC PE embedding");
        let res_bytes =
            build_win32_icon_res(&ico).expect("build_win32_icon_res failed for MSVC icon");
        let res_path = out_path.join("alluse_icon.res");
        fs::write(&res_path, &res_bytes).expect("failed to write alluse_icon.res");
        println!("cargo:rustc-link-arg={}", res_path.display());
        return;
    }

    // BOM-free UTF-8 `RT_MANIFEST` (`1 24`) declaring `asInvoker` so Windows 11 UAC Installer
    // Detection heuristics never block `alluse-setup.exe`, `alluse-uninstall.exe`, or unit-test
    // executables containing `setup` in their filename with `os error 740`.
    let manifest_xml = concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n",
        "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\n",
        "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">\n",
        "    <security>\n",
        "      <requestedPrivileges>\n",
        "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>\n",
        "      </requestedPrivileges>\n",
        "    </security>\n",
        "  </trustInfo>\n",
        "  <compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">\n",
        "    <application>\n",
        "      <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>\n",
        "    </application>\n",
        "  </compatibility>\n",
        "</assembly>\n",
    );
    let manifest_path = out_path.join("alluse.manifest");
    let rc_path = out_path.join("alluse_resources.rc");
    let obj_path = out_path.join("alluse_resources.o");

    if fs::write(&manifest_path, manifest_xml.as_bytes()).is_err() {
        return;
    }
    let rc_script = if has_ico_file {
        "1 ICON \"alluse.ico\"\n1 24 \"alluse.manifest\"\n"
    } else {
        "1 24 \"alluse.manifest\"\n"
    };
    if fs::write(&rc_path, rc_script.as_bytes()).is_err() {
        return;
    }

    if let Some(windres) = find_windres_executable(home_dirs, mingw_triple) {
        let status = Command::new(&windres)
            .current_dir(out_path)
            .args([
                "-i",
                "alluse_resources.rc",
                "-O",
                "coff",
                "-o",
                "alluse_resources.o",
            ])
            .status();
        if status.is_ok_and(|s| s.success()) && obj_path.is_file() {
            println!("cargo:rustc-link-arg={}", obj_path.display());
            return;
        }
        panic!(
            "windres ({}) failed compiling alluse_resources.rc",
            windres.display()
        );
    }

    panic!("No windres executable found to embed Windows PE icon and manifest");
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/alluse.ico");
    println!("cargo:rerun-if-changed=assets/cheapai_logo_icon.png");
    println!("cargo:rerun-if-changed=assets/cheapai-logo.webp");
    println!("cargo:rerun-if-changed=target/installer-icons/alluse.ico");

    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();

    // Windows-specific runtime DLL placement (`WebView2Loader.dll` for arm64 / x64, plus MinGW `libunwind.dll`)
    if target_os != "windows" {
        return;
    }

    let Ok(out_dir) = env::var("OUT_DIR") else {
        return;
    };
    let out_path = PathBuf::from(&out_dir);
    // OUT_DIR is `<target>/<profile>/build/alluse-<hash>/out`
    let Some(build_dir) = out_path.parent().and_then(|p| p.parent()) else {
        return;
    };
    let Some(profile_dir) = build_dir.parent() else {
        return;
    };
    let manifest_dir = env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));

    let wv2_arch_dir = match target_arch.as_str() {
        "aarch64" => "arm64",
        "x86_64" => "x64",
        "x86" => "x86",
        _ => "x64",
    };

    // 1. Ensure matching architecture WebView2Loader.dll is next to alluse.exe in profile_dir,
    // and stage `OUT_DIR/embedded_wv2_loader.bin` (`0` bytes on MSVC where WebView2LoaderStatic.lib
    // is linked; full target-arch DLL bytes on MinGW/gnullvm for standalone `alluse-setup.exe`).
    let bak_wv2 = manifest_dir
        .join("data")
        .join("backups")
        .join("dlls")
        .join("WebView2Loader.dll");
    let root_wv2 = manifest_dir.join("WebView2Loader.dll");
    let resolved_wv2_dll = find_webview2_loader_for_arch(build_dir, wv2_arch_dir)
        .or_else(|| bak_wv2.exists().then_some(bak_wv2))
        .or_else(|| root_wv2.exists().then_some(root_wv2));

    if let Some(ref wv2_dll) = resolved_wv2_dll {
        let _ = fs::copy(wv2_dll, profile_dir.join("WebView2Loader.dll"));
    }

    let embedded_wv2_bin = out_path.join("embedded_wv2_loader.bin");
    if target_env == "msvc" {
        let _ = fs::write(&embedded_wv2_bin, b"");
    } else if let Some(ref wv2_dll) = resolved_wv2_dll {
        let _ = fs::copy(wv2_dll, &embedded_wv2_bin);
    } else {
        let _ = fs::write(&embedded_wv2_bin, b"");
    }
    println!(
        "cargo:rustc-env=ALLUSE_WV2_LOADER_DLL_PATH={}",
        embedded_wv2_bin.display()
    );

    // 2. Ensure MinGW/LLVM libunwind.dll is next to alluse.exe when present
    let bak_unwind = manifest_dir
        .join("data")
        .join("backups")
        .join("dlls")
        .join("libunwind.dll");
    let root_unwind = manifest_dir.join("libunwind.dll");
    let mut unwind_candidates = Vec::new();
    let mingw_triple = if target_arch == "aarch64" {
        "aarch64-w64-mingw32"
    } else {
        "x86_64-w64-mingw32"
    };
    let mut home_dirs = Vec::new();
    if let Ok(home) = env::var("USERPROFILE").or_else(|_| env::var("HOME")) {
        home_dirs.push(PathBuf::from(home));
    }
    if let Ok(uname) = env::var("USERNAME") {
        home_dirs.push(PathBuf::from(format!(r"C:\Users\{uname}")));
    }
    if let Ok(entries) = fs::read_dir(r"C:\Users") {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                home_dirs.push(p);
            }
        }
    }
    for home_path in &home_dirs {
        unwind_candidates.push(
            home_path
                .join(".llvm-mingw")
                .join(mingw_triple)
                .join("bin")
                .join("libunwind.dll"),
        );
        unwind_candidates.push(
            home_path
                .join(".llvm-mingw")
                .join("bin")
                .join("libunwind.dll"),
        );
    }
    unwind_candidates.push(bak_unwind);
    unwind_candidates.push(root_unwind);

    for p in &unwind_candidates {
        if p.exists() {
            let _ = fs::copy(p, profile_dir.join("libunwind.dll"));
            break;
        }
    }

    // 3. On non-MSVC Windows (`gnu`/`gnullvm`), link `libunwind` statically and delay-load
    // `WebView2Loader.dll` so standalone setup/uninstall binaries require 0 external DLLs.
    if target_env != "msvc" {
        configure_mingw_static_unwind_and_delayload(&out_path, &home_dirs, mingw_triple);
    }

    // 4. Embed Windows UAC `asInvoker` RT_MANIFEST (`1 24`) and multi-resolution RT_GROUP_ICON
    embed_windows_manifest_and_icon(
        &out_path,
        &manifest_dir,
        &target_env,
        &home_dirs,
        mingw_triple,
    );
}
