//! Kill switch: while active, outbound traffic that does not go through the
//! VPN is blocked at the OS firewall, so a dead or restarting core can never
//! leak the user's real IP — in Proxy mode and in TUN mode alike.
//!
//! What stays allowed:
//!   * loopback (the app ↔ core, browsers ↔ mixed port);
//!   * the core binary itself (it is the tunnel: it must reach the VPN nodes);
//!   * traffic leaving through the TUN interface (in TUN mode everything is
//!     routed there while the core is up; when the core dies the adapter goes
//!     away and the same traffic hits the block filter instead);
//!   * DHCP, so the machine keeps its address;
//!   * optionally the local network (printers, NAS, the router's admin page).
//!
//! Windows implements it with WFP filters in a *dynamic* session owned by the
//! service: the filters disappear if the service process ends, so a crashed
//! service can never leave the machine permanently offline.

// The rule model is shared, but only the Windows backend consumes it so far.
#![cfg_attr(not(windows), allow(dead_code))]

use anyhow::{Result, bail};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

/// Request body of `PUT /killswitch`.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KillSwitchRequest {
    /// Allow private/link-local/multicast destinations (LAN devices).
    #[serde(default)]
    pub allow_lan: bool,
    /// Interface alias of the core's TUN adapter (e.g. "SlothClash"); empty in
    /// Proxy mode. Re-sent after every (re)connect: a recreated adapter gets a
    /// new LUID, and until the app re-binds it that traffic stays blocked.
    #[serde(default)]
    pub tun_interface: String,
}

/// Body of `GET /killswitch` (and the answer to PUT/DELETE).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct KillSwitchStatus {
    pub supported: bool,
    pub active: bool,
    pub allow_lan: bool,
    pub tun_interface: String,
    /// The TUN alias resolved to a live interface and is permitted.
    pub tun_bound: bool,
}

/// IPv4 destinations treated as "local network" (RFC 1918, link-local,
/// multicast, limited broadcast), as (address, prefix length).
pub const LAN_V4: &[([u8; 4], u8)] = &[
    ([10, 0, 0, 0], 8),
    ([172, 16, 0, 0], 12),
    ([192, 168, 0, 0], 16),
    ([169, 254, 0, 0], 16),
    ([224, 0, 0, 0], 4),
    ([255, 255, 255, 255], 32),
];

/// IPv6 "local network": link-local, unique-local, multicast.
pub const LAN_V6: &[([u8; 16], u8)] = &[
    ([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 10),
    ([0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 7),
    ([0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 8),
];

/// One firewall rule; the platform layer turns each into concrete filters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    PermitLoopback,
    PermitApp(String),
    PermitInterface(u64),
    PermitDhcp,
    PermitLan,
    BlockAll,
}

impl Rule {
    /// Filter weight inside our sublayer: every permit outranks the block.
    pub fn weight(&self) -> u8 {
        match self {
            Rule::PermitLoopback => 15,
            Rule::PermitApp(_) => 14,
            Rule::PermitInterface(_) => 13,
            Rule::PermitDhcp => 12,
            Rule::PermitLan => 11,
            Rule::BlockAll => 0,
        }
    }
}

/// Pure rule plan for a request; `tun_luid` is the resolved TUN interface.
pub fn plan(req: &KillSwitchRequest, core_path: &str, tun_luid: Option<u64>) -> Vec<Rule> {
    let mut rules = vec![
        Rule::PermitLoopback,
        Rule::PermitApp(core_path.to_string()),
        Rule::PermitDhcp,
    ];
    if let Some(luid) = tun_luid {
        rules.push(Rule::PermitInterface(luid));
    }
    if req.allow_lan {
        rules.push(Rule::PermitLan);
    }
    rules.push(Rule::BlockAll);
    rules
}

/// Path of the last core binary the service validated and started; the kill
/// switch permits exactly that file (the client cannot name other programs).
static TRUSTED_CORE_PATH: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

/// Called by the core manager after `validate_core_path` succeeded.
pub async fn remember_core_path(path: &str) {
    *TRUSTED_CORE_PATH.lock().await = Some(path.to_string());
}

struct State {
    request: Option<KillSwitchRequest>,
    tun_bound: bool,
    #[cfg(windows)]
    engine: Option<wfp::Engine>,
}

static STATE: Lazy<Mutex<State>> = Lazy::new(|| {
    Mutex::new(State {
        request: None,
        tun_bound: false,
        #[cfg(windows)]
        engine: None,
    })
});

fn status_of(state: &State) -> KillSwitchStatus {
    KillSwitchStatus {
        supported: cfg!(windows),
        active: state.request.is_some(),
        allow_lan: state.request.as_ref().is_some_and(|r| r.allow_lan),
        tun_interface: state
            .request
            .as_ref()
            .map(|r| r.tun_interface.clone())
            .unwrap_or_default(),
        tun_bound: state.tun_bound,
    }
}

pub async fn status() -> KillSwitchStatus {
    status_of(&*STATE.lock().await)
}

/// Turn the kill switch on, or rebind it (new TUN adapter, LAN toggle). The
/// filter set is replaced atomically, so there is no unblocked gap.
pub async fn enable(req: KillSwitchRequest) -> Result<KillSwitchStatus> {
    let core_path = TRUSTED_CORE_PATH.lock().await.clone();
    let Some(core_path) = core_path else {
        bail!("kill switch needs a running core: start the core first");
    };
    let mut state = STATE.lock().await;
    #[cfg(windows)]
    {
        let tun_luid = if req.tun_interface.trim().is_empty() {
            None
        } else {
            wfp::interface_luid(req.tun_interface.trim())
        };
        let rules = plan(&req, &core_path, tun_luid);
        if state.engine.is_none() {
            state.engine = Some(wfp::Engine::open()?);
        }
        let engine = state.engine.as_mut().expect("engine just opened");
        engine.replace(&rules)?;
        state.tun_bound = tun_luid.is_some();
        state.request = Some(req);
        tracing::info!(
            "kill switch active ({} rules, tun bound: {})",
            rules.len(),
            state.tun_bound
        );
        Ok(status_of(&state))
    }
    #[cfg(not(windows))]
    {
        let _ = (&core_path, &req, &mut state);
        bail!("kill switch is not supported on this platform yet")
    }
}

/// Turn the kill switch off and remove every filter.
pub async fn disable() -> Result<KillSwitchStatus> {
    let mut state = STATE.lock().await;
    #[cfg(windows)]
    {
        // Closing the dynamic session drops all of its filters at once.
        state.engine = None;
    }
    state.request = None;
    state.tun_bound = false;
    tracing::info!("kill switch disabled");
    Ok(status_of(&state))
}

#[cfg(windows)]
mod wfp {
    use super::{LAN_V4, LAN_V6, Rule};
    use anyhow::{Result, bail};
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceAliasToLuid;
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;
    use windows_sys::core::GUID;

    const RPC_C_AUTHN_WINNT: u32 = 10;
    const IPPROTO_UDP: u8 = 17;

    /// Our sublayer; filters in it are arbitrated against other providers'
    /// sublayers, and a block here wins over a permit elsewhere.
    const SUBLAYER_KEY: GUID = GUID::from_u128(0x6b1f4c2e_5d3a_4e7b_9c8d_2a1b0c9d8e7f);

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn check(code: u32, what: &str) -> Result<()> {
        if code != 0 {
            bail!("{what} failed: 0x{code:08x}");
        }
        Ok(())
    }

    pub fn interface_luid(alias: &str) -> Option<u64> {
        let name = wide(alias);
        let mut luid = NET_LUID_LH { Value: 0 };
        let rc = unsafe { ConvertInterfaceAliasToLuid(name.as_ptr(), &mut luid) };
        let value = unsafe { luid.Value };
        (rc == 0 && value != 0).then_some(value)
    }

    pub struct Engine {
        handle: HANDLE,
        filter_ids: Vec<u64>,
    }

    // The handle is only used behind the service's async mutex.
    unsafe impl Send for Engine {}

    impl Engine {
        pub fn open() -> Result<Self> {
            let mut name = wide("Kabosu kill switch");
            let mut session: FWPM_SESSION0 = unsafe { std::mem::zeroed() };
            session.displayData.name = name.as_mut_ptr();
            session.flags = FWPM_SESSION_FLAG_DYNAMIC;
            let mut handle: HANDLE = null_mut();
            check(
                unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), &session, &mut handle) },
                "FwpmEngineOpen0",
            )?;
            let mut engine = Engine { handle, filter_ids: Vec::new() };
            let mut sub_name = wide("Kabosu kill switch");
            let mut sublayer: FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
            sublayer.subLayerKey = SUBLAYER_KEY;
            sublayer.displayData.name = sub_name.as_mut_ptr();
            sublayer.weight = u16::MAX;
            if let Err(e) = check(
                unsafe { FwpmSubLayerAdd0(engine.handle, &sublayer, null_mut()) },
                "FwpmSubLayerAdd0",
            ) {
                engine.close();
                return Err(e);
            }
            Ok(engine)
        }

        /// Swap the whole filter set in one transaction.
        pub fn replace(&mut self, rules: &[Rule]) -> Result<()> {
            check(unsafe { FwpmTransactionBegin0(self.handle, 0) }, "FwpmTransactionBegin0")?;
            let result = (|| -> Result<Vec<u64>> {
                for id in &self.filter_ids {
                    check(
                        unsafe { FwpmFilterDeleteById0(self.handle, *id) },
                        "FwpmFilterDeleteById0",
                    )?;
                }
                let mut ids = Vec::new();
                for rule in rules {
                    for (layer, v6) in [
                        (FWPM_LAYER_ALE_AUTH_CONNECT_V4, false),
                        (FWPM_LAYER_ALE_AUTH_CONNECT_V6, true),
                    ] {
                        if let Some(id) = self.add_rule(rule, layer, v6)? {
                            ids.push(id);
                        }
                    }
                }
                Ok(ids)
            })();
            match result {
                Ok(ids) => {
                    check(unsafe { FwpmTransactionCommit0(self.handle) }, "FwpmTransactionCommit0")?;
                    self.filter_ids = ids;
                    Ok(())
                }
                Err(e) => {
                    unsafe { FwpmTransactionAbort0(self.handle) };
                    Err(e)
                }
            }
        }

        fn add_rule(&self, rule: &Rule, layer: GUID, v6: bool) -> Result<Option<u64>> {
            let mut conditions: Vec<FWPM_FILTER_CONDITION0> = Vec::new();
            // Storage the condition pointers refer to; must outlive FwpmFilterAdd0.
            let mut u64_store: Vec<Box<u64>> = Vec::new();
            let mut v4_store: Vec<Box<FWP_V4_ADDR_AND_MASK>> = Vec::new();
            let mut v6_store: Vec<Box<FWP_V6_ADDR_AND_MASK>> = Vec::new();
            let mut app_id: *mut FWP_BYTE_BLOB = null_mut();
            let action = if *rule == Rule::BlockAll { FWP_ACTION_BLOCK } else { FWP_ACTION_PERMIT };

            match rule {
                Rule::PermitLoopback => {
                    let mut c: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
                    c.fieldKey = FWPM_CONDITION_FLAGS;
                    c.matchType = FWP_MATCH_FLAGS_ALL_SET;
                    c.conditionValue.r#type = FWP_UINT32;
                    c.conditionValue.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
                    conditions.push(c);
                }
                Rule::PermitApp(path) => {
                    let p = wide(path);
                    check(
                        unsafe { FwpmGetAppIdFromFileName0(p.as_ptr(), &mut app_id) },
                        "FwpmGetAppIdFromFileName0",
                    )?;
                    let mut c: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
                    c.fieldKey = FWPM_CONDITION_ALE_APP_ID;
                    c.matchType = FWP_MATCH_EQUAL;
                    c.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
                    c.conditionValue.Anonymous.byteBlob = app_id;
                    conditions.push(c);
                }
                Rule::PermitInterface(luid) => {
                    u64_store.push(Box::new(*luid));
                    let mut c: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
                    c.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
                    c.matchType = FWP_MATCH_EQUAL;
                    c.conditionValue.r#type = FWP_UINT64;
                    c.conditionValue.Anonymous.uint64 = &mut **u64_store.last_mut().unwrap();
                    conditions.push(c);
                }
                Rule::PermitDhcp => {
                    let mut proto: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
                    proto.fieldKey = FWPM_CONDITION_IP_PROTOCOL;
                    proto.matchType = FWP_MATCH_EQUAL;
                    proto.conditionValue.r#type = FWP_UINT8;
                    proto.conditionValue.Anonymous.uint8 = IPPROTO_UDP;
                    conditions.push(proto);
                    let mut port: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
                    port.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT;
                    port.matchType = FWP_MATCH_EQUAL;
                    port.conditionValue.r#type = FWP_UINT16;
                    port.conditionValue.Anonymous.uint16 = if v6 { 547 } else { 67 };
                    conditions.push(port);
                }
                Rule::PermitLan => {
                    // Several conditions on the same field are ORed by WFP.
                    if v6 {
                        for (addr, prefix) in LAN_V6 {
                            v6_store.push(Box::new(FWP_V6_ADDR_AND_MASK {
                                addr: *addr,
                                prefixLength: *prefix,
                            }));
                            let mut c: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
                            c.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                            c.matchType = FWP_MATCH_EQUAL;
                            c.conditionValue.r#type = FWP_V6_ADDR_MASK;
                            c.conditionValue.Anonymous.v6AddrMask =
                                &mut **v6_store.last_mut().unwrap();
                            conditions.push(c);
                        }
                    } else {
                        for (addr, prefix) in LAN_V4 {
                            // WFP takes IPv4 address and mask in host byte order.
                            let mask = if *prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(*prefix)) };
                            v4_store.push(Box::new(FWP_V4_ADDR_AND_MASK {
                                addr: u32::from_be_bytes(*addr),
                                mask,
                            }));
                            let mut c: FWPM_FILTER_CONDITION0 = unsafe { std::mem::zeroed() };
                            c.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
                            c.matchType = FWP_MATCH_EQUAL;
                            c.conditionValue.r#type = FWP_V4_ADDR_MASK;
                            c.conditionValue.Anonymous.v4AddrMask =
                                &mut **v4_store.last_mut().unwrap();
                            conditions.push(c);
                        }
                    }
                }
                Rule::BlockAll => {}
            }

            let mut name = wide("Kabosu kill switch");
            let mut filter: FWPM_FILTER0 = unsafe { std::mem::zeroed() };
            filter.displayData.name = name.as_mut_ptr();
            filter.layerKey = layer;
            filter.subLayerKey = SUBLAYER_KEY;
            filter.weight.r#type = FWP_UINT8;
            filter.weight.Anonymous.uint8 = rule.weight();
            filter.numFilterConditions = conditions.len() as u32;
            filter.filterCondition = if conditions.is_empty() {
                null_mut()
            } else {
                conditions.as_mut_ptr()
            };
            filter.action.r#type = action;
            let mut id = 0u64;
            let rc = unsafe { FwpmFilterAdd0(self.handle, &filter, null_mut(), &mut id) };
            if !app_id.is_null() {
                unsafe { FwpmFreeMemory0(&mut app_id as *mut _ as *mut *mut core::ffi::c_void) };
            }
            check(rc, "FwpmFilterAdd0")?;
            Ok(Some(id))
        }

        fn close(&mut self) {
            if !self.handle.is_null() {
                unsafe { FwpmEngineClose0(self.handle) };
                self.handle = null_mut();
            }
        }
    }

    impl Drop for Engine {
        fn drop(&mut self) {
            // Dynamic session: closing it removes every filter it added.
            self.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_always_ends_with_block_and_permits_core() {
        let req = KillSwitchRequest::default();
        let rules = plan(&req, "C:\\core.exe", None);
        assert_eq!(rules.first(), Some(&Rule::PermitLoopback));
        assert!(rules.contains(&Rule::PermitApp("C:\\core.exe".into())));
        assert_eq!(rules.last(), Some(&Rule::BlockAll));
        assert!(!rules.contains(&Rule::PermitLan));
        assert!(!rules.iter().any(|r| matches!(r, Rule::PermitInterface(_))));
    }

    #[test]
    fn plan_binds_tun_and_lan_when_asked() {
        let req = KillSwitchRequest { allow_lan: true, tun_interface: "SlothClash".into() };
        let rules = plan(&req, "core", Some(42));
        assert!(rules.contains(&Rule::PermitInterface(42)));
        assert!(rules.contains(&Rule::PermitLan));
    }

    #[test]
    fn every_permit_outweighs_the_block() {
        let req = KillSwitchRequest { allow_lan: true, tun_interface: "t".into() };
        for rule in plan(&req, "core", Some(1)) {
            if rule != Rule::BlockAll {
                assert!(rule.weight() > Rule::BlockAll.weight(), "{rule:?}");
            }
        }
    }

    #[test]
    fn lan_ranges_cover_private_networks_only() {
        let prefixes: Vec<_> = LAN_V4.iter().map(|(a, p)| (a[0], *p)).collect();
        assert!(prefixes.contains(&(10, 8)));
        assert!(prefixes.contains(&(192, 16)));
        assert!(!LAN_V4.iter().any(|(_, p)| *p == 0), "no catch-all range");
        assert!(!LAN_V6.iter().any(|(_, p)| *p == 0), "no catch-all range");
    }

    #[tokio::test]
    async fn enable_refuses_without_a_trusted_core() {
        *TRUSTED_CORE_PATH.lock().await = None;
        assert!(enable(KillSwitchRequest::default()).await.is_err());
        let st = disable().await.unwrap();
        assert!(!st.active);
    }
}
