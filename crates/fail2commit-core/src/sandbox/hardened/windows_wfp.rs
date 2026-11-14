//! Per-launch, package-scoped Windows Filtering Platform guard (FR-027).
//!
//! Per-launch package policy: deny all routes and optionally permit only the
//! exact TCP loopback proxy endpoint for the owned AppContainer SID.

#![allow(unsafe_code)]

#[cfg(windows)]
pub(crate) struct PackageGuard {
    engine: windows_sys::Win32::Foundation::HANDLE,
    package_sid: crate::sandbox::windows::ffi::OwnedSid,
    package_sid_text: String,
    exemption_added: bool,
    keep_pending_journal: bool,
    journal_created: bool,
    journal_path: Option<std::path::PathBuf>,
    installed_filters: Vec<windows_sys::core::GUID>,
    installed: usize,
}

#[cfg(windows)]
impl PackageGuard {
    /// Install deny filters for one package SID and, when `proxy_port` is
    /// present, a higher-weight permit for TCP to that exact loopback port.
    pub(crate) fn install(package_sid: &str, proxy_port: Option<u16>) -> crate::Result<Self> {
        use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform as wfp;
        use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;

        if proxy_port == Some(0) {
            return Err(crate::Error::rejected("proxy port zero is invalid"));
        }
        let package_sid = crate::sandbox::windows::ffi::sid_from_string(package_sid)?;
        let package_sid_text = crate::sandbox::windows::ffi::sid_to_string(package_sid.as_psid())?;
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
            package_sid_text,
            exemption_added: false,
            keep_pending_journal: false,
            journal_created: false,
            journal_path: None,
            installed_filters: Vec::new(),
            installed: 0,
        };
        let setup = (|| {
            if proxy_port.is_some() {
                if crate::sandbox::windows::ffi::loopback_exempt_sids()?
                    .iter()
                    .any(|sid| sid.eq_ignore_ascii_case(&guard.package_sid_text))
                {
                    return Err(crate::Error::integrity(
                        "new AppContainer already has a loopback exemption",
                    ));
                }
                let (journal_path, journal_file) =
                    create_exemption_journal(&guard.package_sid_text)?;
                // Track this exact newly-created path before any owner,
                // readback, write, or sync operation can fail.
                guard.journal_path = Some(journal_path.clone());
                guard.journal_created = true;
                if let Err(error) = initialize_exemption_journal(
                    &journal_path,
                    journal_file,
                    &guard.package_sid_text,
                ) {
                    guard.keep_pending_journal = error.message.contains("journal cleanup failed");
                    return Err(error);
                }
                if let Err(error) =
                    crate::sandbox::windows::ffi::add_loopback_exemption(&guard.package_sid_text)
                {
                    guard.keep_pending_journal =
                        error.message.contains("ambiguous machine-wide list change");
                    return Err(error);
                }
                guard.exemption_added = true;
                if let Some(path) = guard.journal_path.as_deref() {
                    mark_exemption_journal_owned(path, &guard.package_sid_text)?;
                }
            }
            let layers = required_block_layers();
            for layer in layers {
                guard.add_package_block(layer)?;
            }
            if let Some(port) = proxy_port {
                for layer in required_connect_layers() {
                    guard.add_proxy_permit(layer, port)?;
                }
            }
            let expected = layers.len() + usize::from(proxy_port.is_some());
            if guard.installed != expected {
                return Err(crate::Error::isolation_unavailable(
                    "WFP package policy did not install every required filter",
                ));
            }
            Ok(())
        })();
        match setup {
            Ok(()) => Ok(guard),
            Err(setup_error) => match guard.close() {
                Ok(()) => Err(setup_error),
                Err(cleanup_error) => Err(crate::Error::isolation_unavailable(format!(
                    "WFP rollback failed after setup error: {}; cleanup error: {}",
                    setup_error.message, cleanup_error.message
                ))),
            },
        }
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
        let weight = u64::MAX - 1;
        let name: Vec<u16> = "Fail2Commit per-job package deny\0"
            .encode_utf16()
            .collect();
        let filter = wfp::FWPM_FILTER0 {
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
            unsafe { wfp::FwpmFilterAdd0(self.engine, &filter, std::ptr::null_mut(), &mut id) };
        if status != 0 || id == 0 {
            return Err(wfp_error("FwpmFilterAdd0", status));
        }
        self.installed += 1;
        self.installed_filters.push(key);
        self.verify_filter(&key, layer)
    }

    fn add_proxy_permit(&mut self, layer: windows_sys::core::GUID, port: u16) -> crate::Result<()> {
        use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform as wfp;
        if !guid_equal(&layer, &wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V4) {
            return Err(crate::Error::integrity(
                "proxy permit layer must be the IPv4 connect layer used by the bound endpoint",
            ));
        }
        let key = fresh_filter_key()?;
        let mut address_v4 = wfp::FWP_V4_ADDR_AND_MASK {
            // WFP's FWP_V4_ADDR_AND_MASK uses host-order integers. Keep the
            // wire-order conversion explicit so little-endian hosts still
            // encode 127.0.0.1 as 0x7F000001.
            addr: proxy_loopback_address_host_order(),
            mask: u32::MAX,
        };
        // FWP_UINT16 port conditions are host order as well.
        let port_value = proxy_loopback_port_host_order(port);
        let protocol = 6u8;
        let package = wfp::FWPM_FILTER_CONDITION0 {
            fieldKey: wfp::FWPM_CONDITION_ALE_PACKAGE_ID,
            matchType: wfp::FWP_MATCH_EQUAL,
            conditionValue: wfp::FWP_CONDITION_VALUE0 {
                r#type: wfp::FWP_SID,
                Anonymous: wfp::FWP_CONDITION_VALUE0_0 {
                    sid: self.package_sid.as_psid().cast(),
                },
            },
        };
        let address = wfp::FWPM_FILTER_CONDITION0 {
            fieldKey: wfp::FWPM_CONDITION_IP_REMOTE_ADDRESS_V4,
            matchType: wfp::FWP_MATCH_EQUAL,
            conditionValue: wfp::FWP_CONDITION_VALUE0 {
                r#type: wfp::FWP_V4_ADDR_MASK,
                Anonymous: wfp::FWP_CONDITION_VALUE0_0 {
                    v4AddrMask: (&mut address_v4 as *mut wfp::FWP_V4_ADDR_AND_MASK),
                },
            },
        };
        let remote_port = wfp::FWPM_FILTER_CONDITION0 {
            fieldKey: wfp::FWPM_CONDITION_IP_REMOTE_PORT,
            matchType: wfp::FWP_MATCH_EQUAL,
            conditionValue: wfp::FWP_CONDITION_VALUE0 {
                r#type: wfp::FWP_UINT16,
                Anonymous: wfp::FWP_CONDITION_VALUE0_0 { uint16: port_value },
            },
        };
        let ip_protocol = wfp::FWPM_FILTER_CONDITION0 {
            fieldKey: wfp::FWPM_CONDITION_IP_PROTOCOL,
            matchType: wfp::FWP_MATCH_EQUAL,
            conditionValue: wfp::FWP_CONDITION_VALUE0 {
                r#type: wfp::FWP_UINT8,
                Anonymous: wfp::FWP_CONDITION_VALUE0_0 { uint8: protocol },
            },
        };
        let mut conditions = [package, address, remote_port, ip_protocol];
        let weight = u64::MAX;
        let name: Vec<u16> = "Fail2Commit exact proxy loopback permit\0"
            .encode_utf16()
            .collect();
        let filter = wfp::FWPM_FILTER0 {
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
            numFilterConditions: conditions.len() as u32,
            filterCondition: conditions.as_mut_ptr(),
            action: wfp::FWPM_ACTION0 {
                r#type: wfp::FWP_ACTION_PERMIT,
                Anonymous: wfp::FWPM_ACTION0_0::default(),
            },
            ..Default::default()
        };
        let mut id = 0u64;
        let status =
            unsafe { wfp::FwpmFilterAdd0(self.engine, &filter, std::ptr::null_mut(), &mut id) };
        if status != 0 || id == 0 {
            return Err(wfp_error("FwpmFilterAdd0(proxy permit)", status));
        }
        self.installed += 1;
        self.installed_filters.push(key);
        self.verify_proxy_permit(&key, layer, port)
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
            && guid_equal(&filter.subLayerKey, &wfp::FWPM_SUBLAYER_UNIVERSAL)
            && filter.action.r#type == wfp::FWP_ACTION_BLOCK
            && filter.flags & wfp::FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT != 0
            && filter.weight.r#type == wfp::FWP_UINT64
            && unsafe { !filter.weight.Anonymous.uint64.is_null() }
            && unsafe { *filter.weight.Anonymous.uint64 == u64::MAX - 1 }
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

    fn verify_proxy_permit(
        &self,
        key: &windows_sys::core::GUID,
        layer: windows_sys::core::GUID,
        port: u16,
    ) -> crate::Result<()> {
        use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform as wfp;
        let mut raw = std::ptr::null_mut();
        let status = unsafe { wfp::FwpmFilterGetByKey0(self.engine, key, &mut raw) };
        if status != 0 || raw.is_null() {
            return Err(wfp_error("FwpmFilterGetByKey0(proxy permit)", status));
        }
        let filter = unsafe { &*raw };
        let valid = guid_equal(&filter.filterKey, key)
            && guid_equal(&filter.layerKey, &layer)
            && guid_equal(&filter.subLayerKey, &wfp::FWPM_SUBLAYER_UNIVERSAL)
            && filter.action.r#type == wfp::FWP_ACTION_PERMIT
            && filter.flags & wfp::FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT != 0
            && filter.weight.r#type == wfp::FWP_UINT64
            && unsafe { !filter.weight.Anonymous.uint64.is_null() }
            && unsafe { *filter.weight.Anonymous.uint64 == u64::MAX }
            && filter.numFilterConditions == 4
            && !filter.filterCondition.is_null()
            && unsafe {
                let conditions = std::slice::from_raw_parts(
                    filter.filterCondition,
                    filter.numFilterConditions as usize,
                );
                let package = conditions.iter().find(|condition| {
                    guid_equal(&condition.fieldKey, &wfp::FWPM_CONDITION_ALE_PACKAGE_ID)
                });
                let address = conditions.iter().find(|condition| {
                    guid_equal(
                        &condition.fieldKey,
                        &wfp::FWPM_CONDITION_IP_REMOTE_ADDRESS_V4,
                    )
                });
                let remote_port = conditions.iter().find(|condition| {
                    guid_equal(&condition.fieldKey, &wfp::FWPM_CONDITION_IP_REMOTE_PORT)
                });
                let protocol = conditions.iter().find(|condition| {
                    guid_equal(&condition.fieldKey, &wfp::FWPM_CONDITION_IP_PROTOCOL)
                });
                let package_valid = package.is_some_and(|condition| {
                    condition.matchType == wfp::FWP_MATCH_EQUAL
                        && condition.conditionValue.r#type == wfp::FWP_SID
                        && !condition.conditionValue.Anonymous.sid.is_null()
                        && windows_sys::Win32::Security::EqualSid(
                            condition.conditionValue.Anonymous.sid.cast(),
                            self.package_sid.as_psid(),
                        ) != 0
                });
                let address_valid = address.is_some_and(|condition| {
                    if condition.matchType != wfp::FWP_MATCH_EQUAL {
                        return false;
                    }
                    condition.conditionValue.r#type == wfp::FWP_V4_ADDR_MASK
                        && !condition.conditionValue.Anonymous.v4AddrMask.is_null()
                        && (*condition.conditionValue.Anonymous.v4AddrMask).addr
                            == u32::from_be_bytes([127, 0, 0, 1])
                        && (*condition.conditionValue.Anonymous.v4AddrMask).mask == u32::MAX
                });
                let port_valid = remote_port.is_some_and(|condition| {
                    guid_equal(&condition.fieldKey, &wfp::FWPM_CONDITION_IP_REMOTE_PORT)
                        && condition.matchType == wfp::FWP_MATCH_EQUAL
                        && condition.conditionValue.r#type == wfp::FWP_UINT16
                        && condition.conditionValue.Anonymous.uint16 == port
                });
                let protocol_valid = protocol.is_some_and(|condition| {
                    condition.matchType == wfp::FWP_MATCH_EQUAL
                        && condition.conditionValue.r#type == wfp::FWP_UINT8
                        && condition.conditionValue.Anonymous.uint8 == 6
                });
                package_valid && address_valid && port_valid && protocol_valid
            };
        unsafe { wfp::FwpmFreeMemory0(&mut raw.cast()) };
        if !valid {
            return Err(crate::Error::integrity(
                "WFP proxy permit read-back did not match package, address, port, protocol and precedence",
            ));
        }
        Ok(())
    }

    /// Close the dynamic session and surface failure to the caller so it can
    /// retain the active-launch refusal marker until filter cleanup is known.
    pub(crate) fn close(&mut self) -> crate::Result<()> {
        if self.exemption_added {
            if let Err(error) =
                crate::sandbox::windows::ffi::remove_loopback_exemption(&self.package_sid_text)
            {
                // Do not retry a whole-list rewrite after an ambiguous result;
                // retain ownership evidence for restart recovery and lock the
                // service rather than risk overwriting a concurrent writer.
                self.exemption_added = false;
                self.keep_pending_journal = true;
                return Err(error);
            }
            self.exemption_added = false;
        }
        if self.engine.is_null() {
            verify_filters_removed(&self.installed_filters)?;
            self.finish_journal_cleanup()?;
            return Ok(());
        }
        let status = unsafe {
            windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmEngineClose0(
                self.engine,
            )
        };
        if status != 0 {
            return Err(wfp_error("FwpmEngineClose0", status));
        }
        self.engine = std::ptr::null_mut();
        verify_filters_removed(&self.installed_filters)?;
        self.finish_journal_cleanup()
    }

    fn finish_journal_cleanup(&mut self) -> crate::Result<()> {
        if self.keep_pending_journal {
            return Err(crate::Error::isolation_unavailable(
                "loopback exemption update was ambiguous; recovery journal retained and service must remain locked",
            ));
        }
        if !self.exemption_added && self.journal_path.is_some() {
            let present = crate::sandbox::windows::ffi::loopback_exempt_sids()?
                .iter()
                .any(|sid| sid.eq_ignore_ascii_case(&self.package_sid_text));
            if present {
                return Err(crate::Error::isolation_unavailable(
                    "pending loopback exemption ownership is ambiguous; recovery journal retained",
                ));
            }
        }
        if self.journal_created {
            self.clear_exemption_journal()?;
        }
        Ok(())
    }

    fn clear_exemption_journal(&mut self) -> crate::Result<()> {
        if self.journal_created {
            let path = self.journal_path.as_deref().ok_or_else(|| {
                crate::Error::integrity("created loopback journal path was not tracked")
            })?;
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(crate::Error::isolation_unavailable(format!(
                        "cannot clear loopback exemption recovery journal: {error}"
                    )));
                }
            }
            self.journal_created = false;
            self.journal_path = None;
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
fn required_connect_layers() -> [windows_sys::core::GUID; 1] {
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform as wfp;
    [wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V4]
}

#[cfg(windows)]
fn proxy_loopback_address_host_order() -> u32 {
    u32::from_be_bytes([127, 0, 0, 1])
}

#[cfg(windows)]
fn proxy_loopback_port_host_order(port: u16) -> u16 {
    port
}

#[cfg(windows)]
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ExemptionJournal {
    version: u32,
    package_sid: String,
    owned: bool,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExemptionJournalAction {
    RemoveOwned,
    ClearUnowned,
    PreserveAmbiguous,
}

#[cfg(windows)]
fn exemption_journal_action(owned: bool, sid_present: bool) -> ExemptionJournalAction {
    match (owned, sid_present) {
        (true, _) => ExemptionJournalAction::RemoveOwned,
        (false, false) => ExemptionJournalAction::ClearUnowned,
        (false, true) => ExemptionJournalAction::PreserveAmbiguous,
    }
}

#[cfg(windows)]
fn exemption_journal_path() -> crate::Result<std::path::PathBuf> {
    Ok(super::machine_state_path()?
        .parent()
        .ok_or_else(|| crate::Error::integrity("install state has no parent"))?
        .join("loopback-exemption.json"))
}

#[cfg(windows)]
fn validate_package_sid(sid: &str) -> bool {
    let mut parts = sid.split('-');
    if parts.next() != Some("S")
        || parts.next() != Some("1")
        || parts.next() != Some("15")
        || parts.next() != Some("2")
    {
        return false;
    }
    let components: Vec<_> = parts.collect();
    (1..=15).contains(&components.len())
        && components
            .iter()
            .all(|part| !part.is_empty() && part.parse::<u32>().is_ok())
}

#[cfg(windows)]
fn create_exemption_journal(
    package_sid: &str,
) -> crate::Result<(std::path::PathBuf, std::fs::File)> {
    use std::os::windows::fs::OpenOptionsExt;
    if !validate_package_sid(package_sid) {
        return Err(crate::Error::integrity(
            "refusing to journal a non-AppContainer package SID",
        ));
    }
    let path = exemption_journal_path()?;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .read(true)
        .create_new(true)
        .access_mode(
            windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ
                | windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_WRITE
                | windows_sys::Win32::Storage::FileSystem::WRITE_OWNER,
        )
        .open(&path)
        .map_err(|error| {
            crate::Error::isolation_unavailable(format!(
                "cannot create loopback exemption recovery journal: {error}"
            ))
        })?;
    Ok((path, file))
}

#[cfg(windows)]
fn initialize_exemption_journal(
    path: &std::path::Path,
    file: std::fs::File,
    package_sid: &str,
) -> crate::Result<()> {
    let record = ExemptionJournal {
        version: 2,
        package_sid: package_sid.to_owned(),
        owned: false,
    };
    let bytes = serde_json::to_vec(&record)
        .map_err(|_| crate::Error::internal("cannot encode loopback exemption journal"))?;
    let system = crate::ipc::winsec::sid_from_string("S-1-5-18")
        .ok_or_else(|| crate::Error::internal("SYSTEM SID constant is invalid"))?;
    initialize_created_journal_with(
        path,
        file,
        &bytes,
        |file| crate::ipc::winsec::set_owner_sid(file, &system),
        verify_journal_owner,
        |file, bytes| {
            use std::io::Write;
            file.write_all(bytes).map_err(Into::into)
        },
        |file| file.sync_all().map_err(Into::into),
        |path| std::fs::remove_file(path),
    )
}

#[cfg(windows)]
// Intentional dependency-injection seam for exercising journal setup and
// cleanup failures at each filesystem boundary without touching machine state.
#[allow(clippy::too_many_arguments)]
fn initialize_created_journal_with(
    path: &std::path::Path,
    mut file: std::fs::File,
    bytes: &[u8],
    set_owner: impl FnOnce(&std::fs::File) -> crate::Result<()>,
    verify_owner: impl FnOnce(&std::fs::File) -> crate::Result<()>,
    write: impl FnOnce(&mut std::fs::File, &[u8]) -> crate::Result<()>,
    sync: impl FnOnce(&std::fs::File) -> crate::Result<()>,
    delete: impl FnOnce(&std::path::Path) -> std::io::Result<()>,
) -> crate::Result<()> {
    let setup = (|| {
        set_owner(&file)?;
        verify_owner(&file)?;
        write(&mut file, bytes)?;
        sync(&file)
    })();
    drop(file);
    match setup {
        Ok(()) => Ok(()),
        Err(setup_error) => match delete(path) {
            Ok(()) => Err(setup_error),
            Err(cleanup_error) => Err(crate::Error::isolation_unavailable(format!(
                "journal cleanup failed after setup error ({}); retained recovery path: {} ({cleanup_error})",
                setup_error.message,
                path.display()
            ))),
        },
    }
}

#[cfg(windows)]
fn verify_journal_owner(file: &std::fs::File) -> crate::Result<()> {
    if crate::ipc::winsec::owner_sid(file)? != "S-1-5-18" {
        return Err(crate::Error::integrity(
            "loopback exemption journal is not SYSTEM-owned",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn mark_exemption_journal_owned(path: &std::path::Path, package_sid: &str) -> crate::Result<()> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        || metadata.len() > 1024
    {
        return Err(crate::Error::integrity(
            "loopback exemption journal is unsafe before ownership update",
        ));
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .truncate(true)
        .access_mode(
            windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ
                | windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_WRITE
                | windows_sys::Win32::Storage::FileSystem::WRITE_OWNER,
        )
        .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    verify_journal_owner(&file)?;
    let record = ExemptionJournal {
        version: 2,
        package_sid: package_sid.to_owned(),
        owned: true,
    };
    let bytes = serde_json::to_vec(&record)
        .map_err(|_| crate::Error::internal("cannot encode loopback exemption journal"))?;
    use std::io::Write;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Revoke only the package SID recorded by our protected intent journal. This
/// runs before the listener accepts jobs, including after a service restart.
#[cfg(windows)]
pub(crate) fn sweep_loopback_exemption() -> crate::Result<()> {
    use std::os::windows::fs::MetadataExt;
    let path = exemption_journal_path()?;
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file()
        || metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        || metadata.len() > 1024
    {
        return Err(crate::Error::integrity(
            "loopback exemption journal is unsafe or oversized",
        ));
    }
    let file = std::fs::OpenOptions::new().read(true).open(&path)?;
    if crate::ipc::winsec::owner_sid(&file)? != "S-1-5-18" {
        return Err(crate::Error::integrity(
            "loopback exemption journal is not SYSTEM-owned",
        ));
    }
    let record: ExemptionJournal = serde_json::from_reader(file)
        .map_err(|_| crate::Error::integrity("loopback exemption journal is malformed"))?;
    if record.version != 2 || !validate_package_sid(&record.package_sid) {
        return Err(crate::Error::integrity(
            "loopback exemption journal identity is invalid",
        ));
    }
    let sid_present = crate::sandbox::windows::ffi::loopback_exempt_sids()?
        .iter()
        .any(|sid| sid.eq_ignore_ascii_case(&record.package_sid));
    match exemption_journal_action(record.owned, sid_present) {
        ExemptionJournalAction::RemoveOwned => {
            crate::sandbox::windows::ffi::remove_loopback_exemption(&record.package_sid)?;
        }
        ExemptionJournalAction::ClearUnowned => {}
        ExemptionJournalAction::PreserveAmbiguous => {
            return Err(crate::Error::isolation_unavailable(
                "pending loopback exemption ownership is ambiguous; service remains locked",
            ));
        }
    }
    std::fs::remove_file(&path).map_err(|error| {
        crate::Error::isolation_unavailable(format!(
            "cannot clear loopback exemption recovery journal: {error}"
        ))
    })
}

#[cfg(windows)]
impl Drop for PackageGuard {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[cfg(windows)]
fn wfp_error(operation: &str, status: u32) -> crate::Error {
    crate::Error::isolation_unavailable(format!(
        "{operation} failed with Windows Filtering Platform status 0x{status:08X}"
    ))
}

/// Reopen WFP after the per-job dynamic session closes and independently
/// verify every filter key added by this guard has disappeared.
#[cfg(windows)]
fn verify_filters_removed(keys: &[windows_sys::core::GUID]) -> crate::Result<()> {
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform as wfp;
    use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
    let session: wfp::FWPM_SESSION0 = unsafe { std::mem::zeroed() };
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
        return Err(wfp_error("FwpmEngineOpen0(cleanup readback)", status));
    }
    let mut result = Ok(());
    for key in keys {
        let mut filter = std::ptr::null_mut();
        let status = unsafe { wfp::FwpmFilterGetByKey0(engine, key, &mut filter) };
        if status == windows_sys::Win32::Foundation::FWP_E_FILTER_NOT_FOUND as u32 {
            continue;
        }
        if status == 0 && !filter.is_null() {
            unsafe { wfp::FwpmFreeMemory0(&mut filter.cast()) };
            result = Err(crate::Error::isolation_unavailable(
                "a per-job WFP filter remained after its dynamic session closed",
            ));
            break;
        }
        result = Err(wfp_error("FwpmFilterGetByKey0(cleanup readback)", status));
        break;
    }
    let close_status = unsafe { wfp::FwpmEngineClose0(engine) };
    if close_status != 0 {
        return Err(wfp_error(
            "FwpmEngineClose0(cleanup readback)",
            close_status,
        ));
    }
    result
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
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform as wfp;
    let layers = required_block_layers();
    assert_eq!(layers.len(), 6);
    let unique = layers
        .iter()
        .map(|guid| (guid.data1, guid.data2, guid.data3, guid.data4))
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(unique.len(), layers.len());
    // The proxy is bound to IPv4 loopback only; there must be no AppContainer
    // exemption for IPv6 or another connect layer.
    let permit_layers = required_connect_layers();
    assert_eq!(permit_layers.len(), 1);
    assert!(guid_equal(
        &permit_layers[0],
        &wfp::FWPM_LAYER_ALE_AUTH_CONNECT_V4
    ));
    assert_eq!(proxy_loopback_address_host_order(), 0x7f00_0001);
    assert_ne!(proxy_loopback_address_host_order(), 0x0100_007f);
    assert_eq!(proxy_loopback_port_host_order(0x1234), 0x1234);
    assert_ne!(proxy_loopback_port_host_order(0x1234), 0x3412);
}

#[cfg(all(windows, test))]
#[test]
fn exemption_recovery_never_deletes_an_unowned_sid() {
    assert_eq!(
        exemption_journal_action(false, false),
        ExemptionJournalAction::ClearUnowned
    );
    assert_eq!(
        exemption_journal_action(false, true),
        ExemptionJournalAction::PreserveAmbiguous
    );
    assert_eq!(
        exemption_journal_action(true, true),
        ExemptionJournalAction::RemoveOwned
    );
    assert_eq!(
        exemption_journal_action(true, false),
        ExemptionJournalAction::RemoveOwned
    );
}

#[cfg(all(windows, test))]
#[test]
fn failed_journal_initialization_cleans_only_its_created_file() {
    let directory = tempfile::tempdir().unwrap();
    for stage in ["owner-set", "owner-readback", "write", "sync"] {
        let path = directory.path().join(format!("{stage}.json"));
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let result = initialize_created_journal_with(
            &path,
            file,
            b"partial",
            |_| {
                if stage == "owner-set" {
                    Err(crate::Error::integrity("injected owner-set failure"))
                } else {
                    Ok(())
                }
            },
            |_| {
                if stage == "owner-readback" {
                    Err(crate::Error::integrity("injected owner-readback failure"))
                } else {
                    Ok(())
                }
            },
            |file, bytes| {
                if stage == "write" {
                    Err(crate::Error::integrity("injected write failure"))
                } else {
                    use std::io::Write;
                    file.write_all(bytes).map_err(Into::into)
                }
            },
            |file| {
                if stage == "sync" {
                    Err(crate::Error::integrity("injected sync failure"))
                } else {
                    file.sync_all().map_err(Into::into)
                }
            },
            |path| std::fs::remove_file(path),
        );
        assert!(result.is_err(), "{stage} error was lost");
        assert!(!path.exists(), "{stage} left an untracked journal");
    }

    let existing = directory.path().join("pre-existing.json");
    std::fs::write(&existing, b"do not delete").unwrap();
    let create_new = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&existing);
    assert!(create_new.is_err());
    assert_eq!(std::fs::read(&existing).unwrap(), b"do not delete");
}

#[cfg(all(windows, test))]
#[test]
fn failed_journal_cleanup_retains_path_and_reports_refusal() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("pending.json");
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    let error = initialize_created_journal_with(
        &path,
        file,
        b"partial",
        |_| Err(crate::Error::integrity("injected owner setup failure")),
        |_| Ok(()),
        |_, _| Ok(()),
        |_| Ok(()),
        |_| Err(std::io::Error::other("injected delete failure")),
    )
    .unwrap_err();
    assert!(error.message.contains("journal cleanup failed"));
    assert!(
        path.exists(),
        "failed cleanup must retain recovery evidence"
    );
}

/// Run only in the disposable elevated Windows guest: this exercises the real
/// WFP engine/session and each filter read-back, then drops the dynamic session
/// so no filters persist. It intentionally does not enable loopback or egress.
#[cfg(all(windows, test))]
#[test]
#[ignore = "requires a disposable elevated Windows guest; never run against the host WFP engine"]
fn disposable_windows_dynamic_package_deny_filters_install_and_revoke() {
    let guard = PackageGuard::install("S-1-15-2-1-2-3-4-5-6-7-8-9-10-11-12", None).unwrap();
    assert_eq!(guard.installed, required_block_layers().len());
    drop(guard);
}

/// Runtime package-policy check for an isolated elevated guest only. It mutates
/// the app-container loopback exemption SID list transiently and proves the
/// list is restored after dynamic filter cleanup.
#[cfg(all(windows, test))]
#[test]
#[ignore = "requires a disposable elevated Windows guest; never run against the host WFP engine"]
fn disposable_windows_exact_proxy_permit_is_read_back_and_revoked() {
    let before = crate::sandbox::windows::ffi::loopback_exempt_sids().unwrap();
    let guard = PackageGuard::install("S-1-15-2-1-2-3-4-5-6-7-8-9-10-11-12", Some(32123)).unwrap();
    assert_eq!(guard.installed, required_block_layers().len() + 1);
    drop(guard);
    assert_eq!(
        crate::sandbox::windows::ffi::loopback_exempt_sids().unwrap(),
        before
    );
}
