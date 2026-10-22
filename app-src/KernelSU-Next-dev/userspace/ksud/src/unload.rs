use anyhow::Result;
use log::{info, warn};
use std::fs;
use std::process::Command;

use crate::utils;

/// Find PIDs of processes running in the XiaoFeng su domain (u:r:xfg:s0).
/// Returns a list of PIDs excluding our own.
fn find_su_domain_pids() -> Vec<i32> {
    let my_pid = std::process::id() as i32;
    let mut pids = Vec::new();

    let Ok(entries) = fs::read_dir("/proc") else {
        return pids;
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        if pid == my_pid {
            continue;
        }

        let attr_path = format!("/proc/{pid}/attr/current");
        if let Ok(context) = fs::read_to_string(&attr_path) {
            let context = context.trim().trim_end_matches('\0');
            if context == "u:r:xfg:s0" {
                pids.push(pid);
            }
        }
    }

    pids
}

/// Find PIDs of processes holding xfg_driver or xfg_fdwrapper file descriptors.
/// Returns a list of PIDs excluding our own.
fn find_xfg_fd_holders() -> Vec<i32> {
    let my_pid = std::process::id() as i32;
    let mut pids = Vec::new();

    let Ok(entries) = fs::read_dir("/proc") else {
        return pids;
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        if pid == my_pid {
            continue;
        }

        let fd_dir = format!("/proc/{pid}/fd");
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            continue;
        };

        for fd_entry in fds.flatten() {
            let link_path = fd_entry.path();
            if let Ok(target) = fs::read_link(&link_path) {
                let target_str = target.to_string_lossy();
                if target_str.contains("[xfg_driver") || target_str.contains("[xfg_fdwrapper]") {
                    pids.push(pid);
                    break;
                }
            }
        }
    }

    pids
}

fn kill_pids(pids: &[i32], signal: i32) {
    for &pid in pids {
        unsafe {
            libc::kill(pid, signal);
        }
    }
}

/// Close all xfg_driver and xfg_fdwrapper fds held by the current process.
fn close_xfg_fds() {
    let Ok(entries) = fs::read_dir("/proc/self/fd") else {
        return;
    };

    for entry in entries.flatten() {
        let Ok(fd) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        if let Ok(target) = fs::read_link(entry.path()) {
            let target_str = target.to_string_lossy();
            if target_str.contains("[xfg_driver") || target_str.contains("[xfg_fdwrapper]") {
                info!("unload: closing fd {fd} -> {target_str}");
                unsafe {
                    libc::close(fd);
                }
            }
        }
    }
}

pub fn unload() -> Result<()> {
    info!("unload: starting XiaoFeng unload sequence");

    // 0. Switch cgroups so we don't get killed along with our parent shell
    utils::switch_cgroups();

    // 1. stop (Android init stop command - stops all services)
    info!("unload: stopping Android services...");
    let _ = Command::new("stop").status();

    // 2. Kill all su domain processes and processes holding xfg fds (except ourselves)
    info!("unload: killing su domain processes...");
    let su_pids = find_su_domain_pids();
    if !su_pids.is_empty() {
        info!(
            "unload: found {} su domain processes, sending SIGKILL",
            su_pids.len()
        );
        kill_pids(&su_pids, libc::SIGKILL);
    }

    info!("unload: killing processes holding xfg fds...");
    let fd_pids = find_xfg_fd_holders();
    if !fd_pids.is_empty() {
        info!(
            "unload: found {} processes holding xfg fds, sending SIGKILL",
            fd_pids.len()
        );
        kill_pids(&fd_pids, libc::SIGKILL);
    }

    // 3. Close all our own xfg_driver and xfg_fdwrapper fds
    info!("unload: closing all xfg fds...");
    close_xfg_fds();

    // 4. delete_module("xiaofeng")
    info!("unload: removing kernel module...");
    if let Err(e) = rustix::system::delete_module(c"xiaofeng", 0) {
        warn!("unload: delete_module failed: {e}");
    }

    // 5. start (Android init start command - restarts all services)
    info!("unload: restarting Android services...");
    let _ = Command::new("start").status();

    // 6. Exit
    info!("unload: done, exiting xfgd");
    std::process::exit(0);
}
