//! Windows Firewall helper for the raw-socket backend.
//!
//! The default Windows Defender Firewall blocks INBOUND packets from reaching a
//! raw-socket sniffer, which drops the TLS `ServerHello` and prevents key
//! establishment (decryption never starts). The app runs elevated, so we add an
//! inbound "allow" rule scoped to our own executable — equivalent to turning the
//! firewall off, but only for this program.

#[cfg(windows)]
const RULE_NAME: &str = "ARCTracker Sync (capture)";

#[cfg(windows)]
pub fn ensure_capture_allowed() -> anyhow::Result<()> {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let exe = std::env::current_exe()?;
    let name_arg = format!("name={RULE_NAME}");
    let program_arg = format!("program={}", exe.display());

    // Drop any stale rule first (e.g. the exe moved) so the path stays current.
    let _ = Command::new("netsh")
        .args(["advfirewall", "firewall", "delete", "rule", &name_arg])
        .creation_flags(CREATE_NO_WINDOW)
        .output();

    let output = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            &name_arg,
            "dir=in",
            "action=allow",
            &program_arg,
            "enable=yes",
            "profile=any",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()?;

    if !output.status.success() {
        anyhow::bail!(
            "netsh could not add the inbound firewall rule: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

/// Delete the rule added by `ensure_capture_allowed`, so the firewall
/// allowance does not outlive the app. netsh exits non-zero when the rule is
/// already gone; that is ignored.
#[cfg(windows)]
pub fn remove_capture_rule() {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    let name_arg = format!("name={RULE_NAME}");
    let _ = Command::new("netsh")
        .args(["advfirewall", "firewall", "delete", "rule", &name_arg])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
}

#[cfg(not(windows))]
pub fn ensure_capture_allowed() -> anyhow::Result<()> {
    Ok(())
}

#[cfg(not(windows))]
pub fn remove_capture_rule() {}
