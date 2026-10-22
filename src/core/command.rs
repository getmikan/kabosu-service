use serde::{Deserialize, Serialize};
use strum_macros::{AsRefStr, EnumString};

#[derive(Debug, Clone, Serialize, Deserialize, EnumString, AsRefStr)]
pub enum IpcCommand {
    #[strum(serialize = "/version")]
    GetVersion,
    // #[strum(serialize = "/clash")]
    // GetClash,

    // 用于日志界面加载上一次日志内容
    #[strum(serialize = "/clash/logs")]
    GetClashLogs,

    #[strum(serialize = "/clash/start")]
    StartClash,
    #[strum(serialize = "/clash/stop")]
    StopClash,
    // Force-remove a stale wintun TUN adapter (Windows). A core force-killed
    // during an app update/crash never gets to delete its adapter, and a newer
    // wintun.dll cannot reopen an adapter created by an older one — either way
    // the next create fails with "access is denied" until the registered PnP
    // device is removed. The unprivileged app cannot do this; only the SYSTEM
    // service can. No-op on non-Windows and when no wintun adapter exists.
    #[strum(serialize = "/tun/remove")]
    RemoveTun,
    // Corporate-VPN coexistence (corp-vpn-coexistence): spawn/supervise a bundled
    // OpenConnect (Cisco AnyConnect protocol) as the privileged service, capturing
    // the routes/DNS the gateway pushes so the app can split traffic (corp subnets
    // via OpenConnect, everything else via mihomo). macOS-first. Only the SYSTEM
    // service can bring up the corp tun / set its routes.
    #[strum(serialize = "/corp/start")]
    StartCorpVpn,
    #[strum(serialize = "/corp/stop")]
    StopCorpVpn,
    #[strum(serialize = "/corp/status")]
    CorpVpnStatus,
    // Windows-only: install OpenVPN's signed TAP-Windows driver (+ one TAP0901
    // adapter) so OpenConnect runs on TAP instead of wintun — mihomo owns wintun,
    // and two wintun users collide ("Failed to register rings: already
    // initialized"). Idempotent: a no-op once the adapter exists. Only the SYSTEM
    // service can install a driver; the desktop just points it at the SHA-verified
    // component it unpacked. No-op on non-Windows (native tun needs no driver).
    #[strum(serialize = "/corp/ensure-driver")]
    EnsureCorpDriver,
    // Kill switch (leak protection): block every outbound connection that does
    // not go through the VPN — loopback, the trusted core binary, the TUN
    // adapter, DHCP and optionally the LAN stay allowed. PUT enables or
    // rebinds (new TUN adapter), DELETE disables, GET reports the state.
    // Windows (WFP, dynamic session) first.
    #[strum(serialize = "/killswitch")]
    KillSwitch,
    #[strum(serialize = "/writer")]
    UpdateWriter,
    #[strum(serialize = "/magic")]
    Magic,
}
