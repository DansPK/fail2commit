//! Per-launch, package-scoped Windows Filtering Platform guard (FR-027).
//!
//! The initial guard installs deny filters only. It has no permit API, so
//! networked jobs remain unavailable until the constrained proxy path has
//! separately passed its probes.

#![allow(unsafe_code)]

#[cfg(windows)]
pub(crate) struct PackageGuard {
    engine: windows_sys::Win32::Foundation::HANDLE,
    package_sid: crate::sandbox::windows::ffi::OwnedSid,
    installed: usize,
}

#[cfg(windows)]
impl PackageGuard {
    /// Install and read back connect, listen and receive/accept deny filters
    /// for one AppContainer package SID across IPv4 and IPv6.
    pub(crate) fn install(package_sid: &str) -> crate::Result<Self> {
        use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform as wfp;
        use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

        let package_sid = crate::sandbox::windows::ffi::sid_from_string(package_sid)?;
        let mut session: wfp::FWPM_SESSION0 = unsafe { std::mem::zeroed() };
        session.flags = wfp::FWPM_SESSION_FLAG_DYNAMIC;
        let mut engine = std::ptr::null_mut();
        let status = unsafe {
            wfp::FwpmEngineOpen0(
                std::ptr::null(),
                RPC_C_AUTHN_WINNT,
                std::ptr::null(),
                &session,
                &mut engine,
            )
        };
        if status != 0 || engine.is_null() {
            return Err(wfp_error("FwpmEngineOpen0", status));
        }
        let mut guard = Self {
            engine,
            package_sid,
            installed: 0,
        };
        let layers = required_block_layers();
        for layer in layers {
            guard.add_package_block(layer)?;
        }
        if guard.installed != layers.len() {
            return Err(crate::Error::isolation_unavailable(
                "WFP package policy did not install every required filter",
            ));
        }
        Ok(guard)
    }

    fn add_package_block(&mut self, layer: windows_sys::core::GUID) -> crate::Result<()> {
        use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform as wfp;

        let key = fresh_filter_key()?;
        let mut sid_condition = wfp::FWPM_FILTER_CONDITION0 {
            fieldKey: wfp::FWPM_CONDITION_ALE_PACKAGE_ID,
            matchType: wfp::FWP_MATCH_EQUAL,
            conditionValue: wfp::FWP_CONDITION_VALUE0 {
                r#type: wfp::FWP_SID,
                Anonymous: wfp::FWP_CONDITION_VALUE0_0 {
                    sid: self.package_sid.as_psid().cast(),
                },
            },
        };
        let weight = 0x7fff_ffff_ffff_ffffu64;
        let name: Vec<u16> = "Fail2Commit per-job package deny\0"
            .encode_utf16()
            .collect();
        let mut filter = wfp::FWPM_FILTER0 {
            filterKey: key,
            displayData: wfp::FWPM_DISPLAY_DATA0 {
                name: name.as_ptr() as *mut u16,
                description: std::ptr::null_mut(),
            },
            layerKey: layer,
            subLayerKey: wfp::FWPM_SUBLAYER_UNIVERSAL,
            flags: wfp::FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT,
            weight: wfp::FWP_VALUE0 {
                r#type: wfp::FWP_UINT64,
                Anonymous: wfp::FWP_VALUE0_0 {
                    uint64: (&weight as *const u64).cast_mut(),
                },
            },
            numFilterConditions: 1,
            filterCondition: &mut sid_condition,
            action: wfp::FWPM_ACTION0 {
                r#type: wfp::FWP_ACTION_BLOCK,
                Anonymous: wfp::FWPM_ACTION0_0::default(),
            },
            ..Default::default()
        };
        let mut id = 0u64;
        let status =
            unsafe { wfp::FwpmFilterAdd0(self.engine, &mut filter, std::ptr::null_mut(), &mut id) };
        if status != 0 || id == 0 {
            return Err(wfp_error("FwpmFilterAdd0", status));
        }
        self.installed += 1;
        self.verify_filter(&key, layer)
    }

    fn verify_filter(
        &self,
        key: &windows_sys::core::GUID,
        layer: windows_sys::core::GUID,
    ) -> crate::Result<()> {
        use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform as wfp;
        let mut raw = std::ptr::null_mut();
        let status = unsafe { wfp::FwpmFilterGetByKey0(self.engine, key, &mut raw) };
        if status != 0 || raw.is_null() {
            return Err(wfp_error("FwpmFilterGetByKey0", status));
        }
        let filter = unsafe { &*raw };
        let valid = guid_equal(&filter.filterKey, key)
            && guid_equal(&filter.layerKey, &layer)
            && filter.action.r#type == wfp::FWP_ACTION_BLOCK
            && filter.numFilterConditions == 1
            && !filter.filterCondition.is_null()
            && unsafe {
                let condition = &*filter.filterCondition;
                guid_equal(&condition.fieldKey, &wfp::FWPM_CONDITION_ALE_PACKAGE_ID)
                    && condition.matchType == wfp::FWP_MATCH_EQUAL
                    && condition.conditionValue.r#type == wfp::FWP_SID
                    && !condition.conditionValue.Anonymous.sid.is_null()
                    && windows_sys::Win32::Security::EqualSid(
                        condition.conditionValue.Anonymous.sid.cast(),
                        self.package_sid.as_psid(),
                    ) != 0
            };
        unsafe { wfp::FwpmFreeMemory0(&mut raw.cast()) };
        if !valid {
            return Err(crate::Error::integrity(
                "WFP block filter read-back did not match its package and layer",
            ));
        }
        Ok(())
    }
}

#[cfg(windows)]
fn required_block_layers() -> [windows_sys::core::GUID; 6] {
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform as wfp;
    [
        wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        wfp::FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,
        wfp::FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6,
        wfp::FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
        wfp::FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
    ]
}

#[cfg(windows)]
impl Drop for PackageGuard {
    fn drop(&mut self) {
        if !self.engine.is_null() {
            unsafe {
                windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmEngineClose0(
                    self.engine,
                );
            }
            self.engine = std::ptr::null_mut();
        }
    }
}

#[cfg(windows)]
fn wfp_error(operation: &str, status: u32) -> crate::Error {
    crate::Error::isolation_unavailable(format!(
        "{operation} failed with Windows Filtering Platform status 0x{status:08X}"
    ))
}

#[cfg(windows)]
fn fresh_filter_key() -> crate::Result<windows_sys::core::GUID> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| {
        crate::Error::internal(format!("WFP filter key generation failed: {error}"))
    })?;
    Ok(windows_sys::core::GUID {
        data1: u32::from_le_bytes(bytes[0..4].try_into().expect("fixed width")),
        data2: u16::from_le_bytes(bytes[4..6].try_into().expect("fixed width")),
        data3: u16::from_le_bytes(bytes[6..8].try_into().expect("fixed width")),
        data4: bytes[8..16].try_into().expect("fixed width"),
    })
}

#[cfg(windows)]
fn guid_equal(left: &windows_sys::core::GUID, right: &windows_sys::core::GUID) -> bool {
    left.data1 == right.data1
        && left.data2 == right.data2
        && left.data3 == right.data3
        && left.data4 == right.data4
}

#[cfg(all(windows, test))]
#[test]
fn policy_covers_both_ip_families_for_connect_listen_and_accept() {
    let layers = required_block_layers();
    assert_eq!(layers.len(), 6);
    let unique = layers
        .iter()
        .map(|guid| (guid.data1, guid.data2, guid.data3, guid.data4))
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(unique.len(), layers.len());
}

/// Run only in the disposable elevated Windows guest: this exercises the real
/// WFP engine/session and each filter read-back, then drops the dynamic session
/// so no filters persist. It intentionally does not enable loopback or egress.
#[cfg(all(windows, test))]
#[test]
fn disposable_windows_dynamic_package_deny_filters_install_and_revoke() {
    let guard = PackageGuard::install("S-1-15-2-1-2-3-4-5-6-7-8-9-10-11-12").unwrap();
    assert_eq!(guard.installed, required_block_layers().len());
    drop(guard);
}
