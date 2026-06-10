use std::path::PathBuf;

use anyhow::Result;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LauncherProcess {
    pub pid: u32,
    pub parent_pid: u32,
    pub name: String,
    pub executable_path: Option<PathBuf>,
}

#[cfg(windows)]
pub fn find_processes(process_name: &str) -> Result<Vec<LauncherProcess>> {
    windows_process_env::find_processes(process_name)
}

#[cfg(not(windows))]
pub fn find_processes(_process_name: &str) -> Result<Vec<LauncherProcess>> {
    Ok(Vec::new())
}

#[cfg(windows)]
pub fn process_environment_value(pid: u32, name: &str) -> Result<Option<String>> {
    windows_process_env::process_environment_value(pid, name)
}

#[cfg(not(windows))]
pub fn process_environment_value(_pid: u32, _name: &str) -> Result<Option<String>> {
    Ok(None)
}

#[cfg(windows)]
mod windows_process_env {
    use std::ffi::{c_void, OsString};
    use std::mem::{size_of, zeroed};
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;

    use anyhow::{anyhow, Context, Result};

    use super::LauncherProcess;

    const MAX_PATH: usize = 260;
    const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
    const INVALID_HANDLE_VALUE: isize = -1;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const PROCESS_VM_READ: u32 = 0x0010;
    const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;
    const PEB_PROCESS_PARAMETERS_OFFSET_X64: usize = 0x20;
    const RTL_USER_PROCESS_PARAMETERS_ENVIRONMENT_OFFSET_X64: usize = 0x80;
    const MAX_ENVIRONMENT_BYTES: usize = 512 * 1024;

    pub fn find_processes(process_name: &str) -> Result<Vec<LauncherProcess>> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(last_error("creating process snapshot"));
        }
        let snapshot = Handle(snapshot);

        let mut entry: ProcessEntry32W = unsafe { zeroed() };
        entry.dw_size = size_of::<ProcessEntry32W>() as u32;
        let mut processes = Vec::new();
        let mut ok = unsafe { Process32FirstW(snapshot.0, &mut entry) };

        while ok != 0 {
            let name = wide_array_to_string(&entry.sz_exe_file);
            if name.eq_ignore_ascii_case(process_name) {
                processes.push(LauncherProcess {
                    pid: entry.th32_process_id,
                    parent_pid: entry.th32_parent_process_id,
                    executable_path: query_process_path(entry.th32_process_id).ok(),
                    name,
                });
            }
            ok = unsafe { Process32NextW(snapshot.0, &mut entry) };
        }

        Ok(processes)
    }

    pub fn process_environment_value(pid: u32, name: &str) -> Result<Option<String>> {
        let environment = read_process_environment(pid)?;
        Ok(environment.into_iter().find_map(|entry| {
            let (entry_name, value) = entry.split_once('=')?;
            entry_name
                .eq_ignore_ascii_case(name)
                .then(|| value.to_string())
        }))
    }

    fn read_process_environment(pid: u32) -> Result<Vec<String>> {
        let handle = open_process(pid)?;
        if is_wow64_process(handle.0)? {
            return Err(anyhow!(
                "32-bit launcher process inspection is not supported yet"
            ));
        }

        let pbi = query_basic_information(handle.0)?;
        let process_parameters = read_usize(
            handle.0,
            pbi.peb_base_address + PEB_PROCESS_PARAMETERS_OFFSET_X64,
        )
        .context("reading process parameters pointer")?;
        if process_parameters == 0 {
            return Err(anyhow!("launcher process has no process parameters"));
        }

        let environment = read_usize(
            handle.0,
            process_parameters + RTL_USER_PROCESS_PARAMETERS_ENVIRONMENT_OFFSET_X64,
        )
        .context("reading environment pointer")?;
        if environment == 0 {
            return Ok(Vec::new());
        }

        let bytes = read_environment_bytes(handle.0, environment)?;
        Ok(parse_environment_block(&bytes))
    }

    fn open_process(pid: u32) -> Result<Handle> {
        let handle =
            unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 0, pid) };
        if handle == 0 {
            return Err(last_error("opening launcher process"));
        }
        Ok(Handle(handle))
    }

    fn query_process_path(pid: u32) -> Result<PathBuf> {
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle == 0 {
            return Err(last_error("opening process for path"));
        }
        let handle = Handle(handle);
        let mut buffer = vec![0u16; 32_768];
        let mut size = buffer.len() as u32;
        let ok = unsafe { QueryFullProcessImageNameW(handle.0, 0, buffer.as_mut_ptr(), &mut size) };
        if ok == 0 {
            return Err(last_error("reading process path"));
        }
        buffer.truncate(size as usize);
        Ok(PathBuf::from(OsString::from_wide(&buffer)))
    }

    fn query_basic_information(handle: isize) -> Result<ProcessBasicInformation> {
        let mut info: ProcessBasicInformation = unsafe { zeroed() };
        let mut return_length = 0u32;
        let status = unsafe {
            NtQueryInformationProcess(
                handle,
                PROCESS_BASIC_INFORMATION_CLASS,
                (&mut info as *mut ProcessBasicInformation).cast::<c_void>(),
                size_of::<ProcessBasicInformation>() as u32,
                &mut return_length,
            )
        };
        if status < 0 {
            return Err(anyhow!(
                "querying launcher process failed with NTSTATUS {status:#x}"
            ));
        }
        if info.peb_base_address == 0 {
            return Err(anyhow!("launcher process has no PEB"));
        }
        Ok(info)
    }

    fn is_wow64_process(handle: isize) -> Result<bool> {
        let mut wow64 = 0i32;
        let ok = unsafe { IsWow64Process(handle, &mut wow64) };
        if ok == 0 {
            return Err(last_error("checking launcher process architecture"));
        }
        Ok(wow64 != 0)
    }

    fn read_usize(handle: isize, address: usize) -> Result<usize> {
        let mut value = 0usize;
        read_memory(handle, address, any_as_mut_bytes(&mut value))?;
        Ok(value)
    }

    fn read_environment_bytes(handle: isize, address: usize) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        let mut offset = 0usize;
        while output.len() < MAX_ENVIRONMENT_BYTES {
            let mut chunk = vec![0u8; 4096];
            let read = read_memory_partial(handle, address + offset, &mut chunk)?;
            if read == 0 {
                break;
            }
            chunk.truncate(read);
            output.extend_from_slice(&chunk);

            if has_double_utf16_nul(&output) {
                return Ok(output);
            }

            offset += read;
            if read < 4096 {
                break;
            }
        }

        Ok(output)
    }

    fn has_double_utf16_nul(bytes: &[u8]) -> bool {
        bytes
            .windows(4)
            .step_by(2)
            .any(|window| window == [0, 0, 0, 0])
    }

    fn read_memory(handle: isize, address: usize, buffer: &mut [u8]) -> Result<()> {
        let read = read_memory_partial(handle, address, buffer)?;
        if read != buffer.len() {
            return Err(anyhow!(
                "launcher memory read was incomplete: expected {}, got {}",
                buffer.len(),
                read
            ));
        }
        Ok(())
    }

    fn read_memory_partial(handle: isize, address: usize, buffer: &mut [u8]) -> Result<usize> {
        let mut read = 0usize;
        let ok = unsafe {
            ReadProcessMemory(
                handle,
                address as *const c_void,
                buffer.as_mut_ptr().cast::<c_void>(),
                buffer.len(),
                &mut read,
            )
        };
        if ok == 0 {
            return Err(last_error("reading launcher process memory"));
        }
        Ok(read)
    }

    fn parse_environment_block(bytes: &[u8]) -> Vec<String> {
        let wide = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect::<Vec<_>>();
        let mut entries = Vec::new();
        let mut start = 0usize;
        let mut index = 0usize;

        while index < wide.len() {
            if wide[index] == 0 {
                if index == start {
                    break;
                }
                entries.push(String::from_utf16_lossy(&wide[start..index]));
                start = index + 1;
            }
            index += 1;
        }

        entries
    }

    fn any_as_mut_bytes<T>(value: &mut T) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut((value as *mut T).cast::<u8>(), size_of::<T>()) }
    }

    fn wide_array_to_string(value: &[u16]) -> String {
        let len = value.iter().position(|ch| *ch == 0).unwrap_or(value.len());
        OsString::from_wide(&value[..len])
            .to_string_lossy()
            .to_string()
    }

    fn last_error(action: &str) -> anyhow::Error {
        let error = unsafe { GetLastError() };
        anyhow!("{action} failed with Windows error {error}")
    }

    struct Handle(isize);

    impl Drop for Handle {
        fn drop(&mut self) {
            if self.0 != 0 && self.0 != INVALID_HANDLE_VALUE {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    #[repr(C)]
    struct ProcessBasicInformation {
        exit_status: i32,
        peb_base_address: usize,
        affinity_mask: usize,
        base_priority: i32,
        unique_process_id: usize,
        inherited_from_unique_process_id: usize,
    }

    #[repr(C)]
    struct ProcessEntry32W {
        dw_size: u32,
        cnt_usage: u32,
        th32_process_id: u32,
        th32_default_heap_id: usize,
        th32_module_id: u32,
        cnt_threads: u32,
        th32_parent_process_id: u32,
        pc_pri_class_base: i32,
        dw_flags: u32,
        sz_exe_file: [u16; MAX_PATH],
    }

    #[link(name = "Kernel32")]
    extern "system" {
        fn CreateToolhelp32Snapshot(flags: u32, process_id: u32) -> isize;
        fn Process32FirstW(snapshot: isize, entry: *mut ProcessEntry32W) -> i32;
        fn Process32NextW(snapshot: isize, entry: *mut ProcessEntry32W) -> i32;
        fn OpenProcess(desired_access: u32, inherit_handle: i32, process_id: u32) -> isize;
        fn QueryFullProcessImageNameW(
            process: isize,
            flags: u32,
            exe_name: *mut u16,
            size: *mut u32,
        ) -> i32;
        fn IsWow64Process(process: isize, wow64_process: *mut i32) -> i32;
        fn ReadProcessMemory(
            process: isize,
            base_address: *const c_void,
            buffer: *mut c_void,
            size: usize,
            number_of_bytes_read: *mut usize,
        ) -> i32;
        fn CloseHandle(handle: isize) -> i32;
        fn GetLastError() -> u32;
    }

    #[link(name = "Ntdll")]
    extern "system" {
        fn NtQueryInformationProcess(
            process: isize,
            process_information_class: u32,
            process_information: *mut c_void,
            process_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
    }
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    #[test]
    fn reads_current_process_environment_value() {
        std::env::set_var("ARCTRACKER_SYNC_ENV_TEST", "present");

        let value =
            super::process_environment_value(std::process::id(), "ARCTRACKER_SYNC_ENV_TEST")
                .expect("read current process environment");

        assert_eq!(value.as_deref(), Some("present"));
    }
}
