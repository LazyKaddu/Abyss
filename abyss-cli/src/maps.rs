//! Hybrid eBPF map resolution and typed accessors for `abyssctl`.

use anyhow::{Context, Result};
use aya::maps::{Array, HashMap, Map, MapData, PerCpuArray};
use abyss_common::{
    dispatcher::ModuleStatus,
    dpi::DpiSignature,
    rate_limit::RateLimitConfig,
    telemetry::PacketCounters,
};
use std::path::{Path, PathBuf};

/// Resolves active eBPF maps managed by `abyss-daemon` using a two-tier strategy:
/// 1. Pinned map file in bpffs (`<bpf_dir>/<MAP_NAME>`).
/// 2. Active kernel map search by name via `aya::maps::loaded_maps()`.
pub struct MapResolver {
    bpf_dir: PathBuf,
}

impl MapResolver {
    pub fn new<P: AsRef<Path>>(bpf_dir: P) -> Self {
        Self {
            bpf_dir: bpf_dir.as_ref().to_path_buf(),
        }
    }

    /// Resolves a raw `MapData` handle by name.
    pub fn resolve_map(&self, name: &str) -> Result<MapData> {
        let pin_path = self.bpf_dir.join(name);
        if pin_path.exists() {
            if let Ok(map_data) = MapData::from_pin(&pin_path) {
                return Ok(map_data);
            }
        }

        // Fallback: search loaded kernel maps by name
        for item in aya::maps::loaded_maps() {
            if let Ok(info) = item {
                if let Some(map_name) = info.name_as_str() {
                    if map_name == name {
                        return MapData::from_id(info.id())
                            .with_context(|| format!("Failed to open eBPF map '{name}' (ID {}) from kernel", info.id()));
                    }
                }
            }
        }

        anyhow::bail!(
            "Could not locate active eBPF map '{name}'.\n\
             Checked pinned path '{}' and scanned active kernel maps.\n\
             Please verify that abyss-daemon is running with root privileges.",
            pin_path.display()
        );
    }

    /// Resolves a generic `Map` enum variant from the resolved `MapData`.
    pub fn resolve_typed_map(&self, name: &str) -> Result<Map> {
        let map_data = self.resolve_map(name)?;
        Map::from_map_data(map_data)
            .with_context(|| format!("Failed to create Map enum variant for '{name}'"))
    }

    /// Returns a handle to the `BLOCKED_IPS` hash map.
    pub fn blocked_ips(&self) -> Result<HashMap<MapData, u32, u8>> {
        let map = self.resolve_typed_map("BLOCKED_IPS")?;
        HashMap::try_from(map).context("Failed to cast map to HashMap for 'BLOCKED_IPS'")
    }

    /// Returns a handle to the `MODULE_STATUS` array map.
    pub fn module_status(&self) -> Result<Array<MapData, ModuleStatus>> {
        let map = self.resolve_typed_map("MODULE_STATUS")?;
        Array::try_from(map).context("Failed to cast map to Array for 'MODULE_STATUS'")
    }

    /// Returns a handle to the `PACKET_COUNTERS` per-cpu array map.
    pub fn packet_counters(&self) -> Result<PerCpuArray<MapData, PacketCounters>> {
        let map = self.resolve_typed_map("PACKET_COUNTERS")?;
        PerCpuArray::try_from(map).context("Failed to cast map to PerCpuArray for 'PACKET_COUNTERS'")
    }

    /// Returns a handle to the optional `TIDE_STATS` per-cpu array map.
    pub fn tide_stats(&self) -> Result<Option<PerCpuArray<MapData, PacketCounters>>> {
        match self.resolve_typed_map("TIDE_STATS") {
            Ok(map) => {
                let stats = PerCpuArray::try_from(map).context("Failed to cast map to 'TIDE_STATS'")?;
                Ok(Some(stats))
            }
            Err(_) => Ok(None),
        }
    }

    /// Returns a handle to the optional `GAZE_STATS` per-cpu array map.
    pub fn gaze_stats(&self) -> Result<Option<PerCpuArray<MapData, PacketCounters>>> {
        match self.resolve_typed_map("GAZE_STATS") {
            Ok(map) => {
                let stats = PerCpuArray::try_from(map).context("Failed to cast map to 'GAZE_STATS'")?;
                Ok(Some(stats))
            }
            Err(_) => Ok(None),
        }
    }

    /// Returns a handle to the optional `DPI_SIGNATURES` array map.
    pub fn dpi_signatures(&self) -> Result<Option<Array<MapData, DpiSignature>>> {
        match self.resolve_typed_map("DPI_SIGNATURES") {
            Ok(map) => {
                let sigs = Array::try_from(map).context("Failed to cast map to 'DPI_SIGNATURES'")?;
                Ok(Some(sigs))
            }
            Err(_) => Ok(None),
        }
    }

    /// Returns a handle to the optional `RATE_LIMIT_CFG` array map.
    pub fn rate_limit_cfg(&self) -> Result<Option<Array<MapData, RateLimitConfig>>> {
        match self.resolve_typed_map("RATE_LIMIT_CFG") {
            Ok(map) => {
                let cfg = Array::try_from(map).context("Failed to cast map to 'RATE_LIMIT_CFG'")?;
                Ok(Some(cfg))
            }
            Err(_) => Ok(None),
        }
    }
}
