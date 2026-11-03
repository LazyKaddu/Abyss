//! Interface validation and XDP program attachment lifecycle management.

use anyhow::{bail, Context, Result};
use aya::programs::xdp::XdpLinkId;
use aya::programs::{Xdp, XdpMode as AyaXdpMode};
use aya::Ebpf;
use std::ffi::CString;
use std::path::Path;
use tracing::{info, warn};

use crate::config::XdpMode;

/// Checks if an interface is likely a wireless or primary physical link.
pub fn is_sensitive_interface(iface: &str) -> bool {
    // Common wireless prefixes (wlan, wlp, wlo, etc.)
    if iface.starts_with("wl") {
        return true;
    }

    // Check if this interface is the wireless type in sysfs
    let wireless_path = format!("/sys/class/net/{}/wireless", iface);
    if Path::new(&wireless_path).exists() {
        return true;
    }

    false
}

/// Validates that the network interface exists in the system and is safe to use.
pub fn validate_interface(iface: &str, allow_primary: bool) -> Result<()> {
    let sysfs_path = format!("/sys/class/net/{}", iface);
    if !Path::new(&sysfs_path).exists() {
        bail!(
            "Network interface '{}' does not exist in /sys/class/net/.\n\
             Tip: You can create a test veth pair using: ./scripts/setup_veth.sh",
            iface
        );
    }

    if is_sensitive_interface(iface) && !allow_primary {
        bail!(
            "SAFETY GUARD: Refusing to attach XDP to wireless/sensitive interface '{}'.\n\
             Attaching early XDP rules to active Wi-Fi or primary uplinks may interrupt connectivity.\n\
             To test safely, use the test veth pair (veth-abyss) or explicitly pass --allow-primary-iface.",
            iface
        );
    }

    Ok(())
}

/// Manages an attached XDP program and its detachment lifecycle.
pub struct XdpAttachment {
    pub iface: String,
    pub link_id: XdpLinkId,
}

impl XdpAttachment {
    /// Detaches the XDP program from the interface.
    pub fn detach(self, ebpf: &mut Ebpf) -> Result<()> {
        let program: &mut Xdp = ebpf
            .program_mut("abyss_dispatcher")
            .context("XDP program 'abyss_dispatcher' not found during detach")?
            .try_into()
            .context("Program 'abyss_dispatcher' is not an XDP program")?;

        info!(iface = %self.iface, "Detaching XDP program from network interface");
        program
            .detach(self.link_id)
            .with_context(|| format!("Failed to detach XDP link from interface '{}'", self.iface))?;

        info!(iface = %self.iface, "Successfully detached XDP program");
        Ok(())
    }
}

/// Attaches the `abyss_dispatcher` XDP program from the loaded eBPF object to `iface`.
pub fn attach_xdp(ebpf: &mut Ebpf, iface: &str, mode: XdpMode) -> Result<XdpAttachment> {
    let program: &mut Xdp = ebpf
        .program_mut("abyss_dispatcher")
        .context("XDP program 'abyss_dispatcher' not found in loaded eBPF object")?
        .try_into()
        .context("Program 'abyss_dispatcher' is not an XDP program")?;

    if program.fd().is_err() {
        info!("Loading 'abyss_dispatcher' XDP program into kernel");
        program
            .load()
            .context("Failed to load 'abyss_dispatcher' program into the kernel")?;
    }

    let aya_mode = match mode {
        XdpMode::Skb => {
            info!("Attaching in SKB (Generic) mode");
            AyaXdpMode::Skb
        }
        XdpMode::Drv => {
            info!("Attaching in DRV (Native Driver) mode");
            AyaXdpMode::Driver
        }
    };

    let c_iface = CString::new(iface)
        .with_context(|| format!("Interface name '{}' contains invalid null bytes", iface))?;

    let link_id = match program.attach(c_iface.as_c_str(), aya_mode) {
        Ok(id) => id,
        Err(e) if mode == XdpMode::Drv => {
            warn!("Native DRV mode failed ({e}), falling back to SKB (Generic) mode...");
            program
                .attach(c_iface.as_c_str(), AyaXdpMode::Skb)
                .with_context(|| format!("Failed to attach XDP to '{iface}' in SKB fallback mode"))?
        }
        Err(e) => {
            return Err(e).with_context(|| {
                format!(
                    "Failed to attach XDP program to interface '{}' with mode {:?}",
                    iface, mode
                )
            });
        }
    };

    info!(
        iface = %iface,
        mode = ?mode,
        "XDP Root Dispatcher attached and actively filtering Ring 0 ingress"
    );

    Ok(XdpAttachment {
        iface: iface.to_string(),
        link_id,
    })
}
