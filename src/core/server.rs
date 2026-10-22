use super::state::IpcState;
use crate::core::auth::ipc_request_context_to_auth_context;
use crate::core::logger::set_or_update_writer;
use crate::core::manager::{CORE_MANAGER, LOGGER_MANAGER};
use crate::core::killswitch::KillSwitchRequest;
use crate::core::structure::{CorpEnsureDriverRequest, CorpVpnStartRequest, Response};
use crate::{ClashConfig, IpcCommand, VERSION, WriterConfig};
use http::StatusCode;
use kode_bridge::{IpcHttpServer, Result, Router, ipc_http_server::HttpResponse};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{info, trace};

pub async fn run_ipc_server() -> Result<JoinHandle<Result<()>>> {
    make_ipc_dir().await?;
    cleanup_stale_ipc_socket().await?;
    init_ipc_state().await?;
    // Reap any corp-VPN resolver overrides a previous crashed run left behind, so
    // a stale corp-domain DNS entry never survives a service restart.
    super::corp_vpn::sweep_orphans().await;

    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let (done_tx, done_rx) = oneshot::channel::<()>();

    {
        let guard = IpcState::global().lock().await;
        guard.set_sender(shutdown_tx).await;
        guard.set_done(done_rx).await;
        drop(guard);
    }

    let server_arc = IpcState::global().lock().await.get_server();
    let mut guard = server_arc.lock().await;

    if let Some(mut server) = guard.take() {
        let handle = tokio::spawn(async move {
            #[cfg(unix)]
            let res = tokio::select! {
                res = unsafe{ platform_lib::umask(0o007); server.serve() } => res,
                _ = &mut shutdown_rx => Ok(()),
            };
            #[cfg(not(unix))]
            let res = tokio::select! {
                res = server.serve() => res,
                _ = &mut shutdown_rx => Ok(()),
            };

            let _ = done_tx.send(());
            res
        });
        #[cfg(unix)]
        {
            use crate::IPC_PATH;
            use std::fs::Permissions;
            use std::os::unix::fs::PermissionsExt;
            use std::time::Duration;
            use tokio::fs;

            tokio::time::sleep(Duration::from_millis(50)).await;
            // Layer-2 socket hardening. Linux: root-owned, group-accessible via the
            // setgid parent dir (0o660) — the non-admin GUI works through group
            // membership without world exposure. macOS: keep the original
            // world-accessible mode; the GUI connects through /tmp and group-scoping
            // there caused a reboot admin-prompt loop (base commit 6a63cda). The real
            // macOS boundary is Layer-3 caller auth (SecCode), not socket perms.
            #[cfg(target_os = "macos")]
            fs::set_permissions(IPC_PATH, Permissions::from_mode(0o777)).await?;
            #[cfg(not(target_os = "macos"))]
            fs::set_permissions(IPC_PATH, Permissions::from_mode(0o660)).await?;

            spawn_socket_dir_watchdog();
        }
        Ok(handle)
    } else {
        Err(kode_bridge::KodeBridgeError::configuration(
            "IPC server not initialized".to_string(),
        ))
    }
}

pub async fn stop_ipc_server() -> Result<()> {
    CORE_MANAGER.lock().await.stop_core().await.ok();

    if let Some(sender) = IpcState::global().lock().await.take_sender().await {
        let _ = sender.send(());
    }

    if let Some(done) = IpcState::global().lock().await.take_done().await {
        let _ = done.await;
    }

    {
        let server_arc = IpcState::global().lock().await.get_server();
        let mut guard = server_arc.lock().await;
        if let Some(server) = guard.as_mut() {
            server.shutdown();
        }
        *guard = None;
    }

    cleanup_ipc_path().await?;
    #[cfg(windows)]
    tokio::time::sleep(std::time::Duration::from_millis(70)).await;

    Ok(())
}

async fn make_ipc_dir() -> Result<()> {
    #[cfg(unix)]
    {
        use crate::IPC_PATH;
        use std::fs::Permissions;
        use std::os::unix::fs::PermissionsExt;
        use std::path::Path;
        use tokio::fs;

        let Some(dir_path) = Path::new(IPC_PATH).parent() else {
            return Ok(());
        };

        if !dir_path.exists() {
            fs::create_dir_all(dir_path).await?;
        }

        // We need to ensure compatibility with sudo GID through the terminal
        let gid = std::env::var("SUDO_GID")
            .ok()
            .and_then(|s| s.parse::<platform_lib::gid_t>().ok())
            .unwrap_or_else(|| unsafe { platform_lib::getgid() });

        if let Ok(c_path) = std::ffi::CString::new(dir_path.to_string_lossy().as_bytes()) {
            unsafe {
                if platform_lib::chown(c_path.as_ptr(), platform_lib::uid_t::MAX, gid) != 0 {
                    let err = std::io::Error::last_os_error();
                    log::warn!(
                        "Failed to chown directory {:?} to gid {}: {}",
                        dir_path,
                        gid,
                        err
                    );
                }
            }
        }

        // macOS app connects as an unprivileged GUI user through /tmp.
        // Keep the socket directory world-traversable with sticky bit to avoid
        // recurring "permission denied" after reboot (which forces osascript/admin prompt).
        #[cfg(target_os = "macos")]
        fs::set_permissions(dir_path, Permissions::from_mode(0o1777)).await?;

        // Linux keeps group-managed semantics for the service/user group pair.
        #[cfg(not(target_os = "macos"))]
        fs::set_permissions(dir_path, Permissions::from_mode(0o2770)).await?;
    }
    #[cfg(windows)]
    {
        // No directory creation needed for Windows named pipes
    }
    Ok(())
}

async fn cleanup_ipc_path() -> Result<()> {
    #[cfg(unix)]
    {
        use crate::IPC_PATH;
        use std::path::Path;
        use tokio::fs;

        if Path::new(IPC_PATH).exists() {
            fs::remove_file(IPC_PATH).await?;
        }
    }
    #[cfg(windows)]
    {
        // Named pipes on Windows are automatically cleaned up when the last handle is closed
        // No manual cleanup needed
    }
    Ok(())
}

async fn cleanup_stale_ipc_socket() -> Result<()> {
    #[cfg(unix)]
    {
        use crate::IPC_PATH;
        use std::path::Path;
        use tracing::warn;

        let socket_path = Path::new(IPC_PATH);
        if !socket_path.exists() {
            return Ok(());
        }

        match tokio::time::timeout(
            std::time::Duration::from_millis(500),
            tokio::net::UnixStream::connect(IPC_PATH),
        )
        .await
        {
            Ok(Ok(_stream)) => {
                warn!(
                    "Another instance listening on {}, removing stale socket",
                    IPC_PATH
                );
                tokio::fs::remove_file(IPC_PATH).await?;
            }
            _ => {
                info!("Cleaning up stale IPC socket: {}", IPC_PATH);
                tokio::fs::remove_file(IPC_PATH).await?;
            }
        }
    }
    #[cfg(windows)]
    {}
    Ok(())
}

#[cfg(unix)]
pub fn spawn_socket_dir_watchdog() {
    use crate::IPC_PATH;
    use std::path::Path;
    use tracing::warn;

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            interval.tick().await;

            let socket_path = Path::new(IPC_PATH);
            if let Some(dir) = socket_path.parent()
                && !dir.exists()
            {
                warn!("IPC socket directory {:?} was deleted, recreating", dir);
                if let Err(e) = tokio::fs::create_dir_all(dir).await {
                    warn!("Failed to recreate IPC socket directory: {}", e);
                    continue;
                }
                use std::fs::Permissions;
                use std::os::unix::fs::PermissionsExt;
                // Layer-2: Linux is group-scoped (setgid) instead of world-writable.
                // macOS keeps 1777 (sticky world dir): the non-admin GUI connects
                // through /tmp and group-scoping there caused a reboot admin-prompt
                // loop (base commit 6a63cda). Real macOS boundary = Layer-3 SecCode.
                #[cfg(target_os = "macos")]
                let _ = tokio::fs::set_permissions(dir, Permissions::from_mode(0o1777)).await;
                #[cfg(not(target_os = "macos"))]
                let _ = tokio::fs::set_permissions(dir, Permissions::from_mode(0o2770)).await;
                info!("IPC socket directory {:?} recreated", dir);
            }
        }
    });
}

async fn init_ipc_state() -> Result<()> {
    let server = create_ipc_server()?;
    let router = create_ipc_router()?;
    let server = server.router(router);
    IpcState::global().lock().await.set_server(server).await;
    Ok(())
}

fn create_ipc_server() -> Result<IpcHttpServer> {
    use crate::IPC_PATH;
    use kode_bridge::ipc_http_server::ServerConfig;
    use std::time::Duration;

    // kode-bridge wraps every handler in `write_timeout` (default 10 s). A corp-VPN
    // connect legitimately runs up to ~35 s (OpenConnect TLS + auth + route push),
    // so the default would abort /corp/start mid-connect with a 408 and orphan the
    // OpenConnect process. Give handlers 45 s of headroom; this is a ceiling only —
    // ordinary handlers still return in milliseconds, and status polls run on
    // separate connections so they stay snappy during a long connect.
    let config = ServerConfig {
        write_timeout: Duration::from_secs(45),
        ..Default::default()
    };
    let server = IpcHttpServer::with_config(IPC_PATH, config)?;

    #[cfg(unix)]
    {
        use platform_lib::{S_IRGRP, S_IRUSR, S_IWGRP, S_IWUSR, mode_t};

        let mode: mode_t = platform_lib::mode_t::from(S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
        let server = server.with_listener_mode(mode);
        Ok(server)
    }

    #[cfg(windows)]
    {
        // Layer-2 hardening (NOT a trust boundary — a same-user attacker shares the
        // GUI's SID). Upstream clash-verge-service-ipc uses `D:(A;;GA;;;WD)` (World).
        // Narrow to SYSTEM + Administrators (full) and Authenticated Users, dropping
        // ANONYMOUS LOGON and other non-authenticated principals. The legitimate
        // non-admin GUI runs as an authenticated interactive user and keeps access.
        // A malformed SDDL makes kode-bridge panic at startup (fails closed).
        let server =
            server.with_listener_security_descriptor("D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;AU)");
        Ok(server)
    }
}

fn create_ipc_router() -> Result<Router> {
    let router = Router::new()
        .get(IpcCommand::Magic.as_ref(), |ctx| async move {
            trace!("Received Magic command");
            ipc_request_context_to_auth_context(&ctx)?;
            Ok(HttpResponse::builder().text("Tunglies!").build())
        })
        .get(IpcCommand::GetVersion.as_ref(), |ctx| async move {
            ipc_request_context_to_auth_context(&ctx)?;
            let json_value = Response {
                code: 0,
                message: "Success".to_string(),
                data: Some(VERSION.to_string()),
            };
            Ok(HttpResponse::builder()
                .status(StatusCode::OK)
                .json(&json_value)?
                .build())
        })
        .post(IpcCommand::StartClash.as_ref(), |ctx| async move {
            trace!("Received StartClash command");
            ipc_request_context_to_auth_context(&ctx)?;
            match ctx.json::<ClashConfig>() {
                Ok(start_clash) => {
                    match CORE_MANAGER.lock().await.start_core(start_clash).await {
                        Ok(_) => info!("Core started successfully"),
                        Err(e) => {
                            let json_value: Response<()> = Response {
                                code: 1,
                                message: format!("Failed to start core: {}", e),
                                data: None,
                            };
                            return Ok(HttpResponse::builder()
                                .status(StatusCode::SERVICE_UNAVAILABLE)
                                .json(&json_value)?
                                .build());
                        }
                    }
                    let json_value: Response<()> = Response {
                        code: 0,
                        message: "Core started successfully".to_string(),
                        data: None,
                    };
                    Ok(HttpResponse::builder()
                        .status(StatusCode::OK)
                        .json(&json_value)?
                        .build())
                }
                Err(e) => Ok(HttpResponse::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .text(format!("Invalid JSON: {}", e))
                    .build()),
            }
        })
        .get(IpcCommand::GetClashLogs.as_ref(), |ctx| async move {
            trace!("Received GetClashLogs command");
            ipc_request_context_to_auth_context(&ctx)?;
            let json_value = Response {
                code: 0,
                message: "Success".to_string(),
                data: Some(LOGGER_MANAGER.get_logs().await),
            };
            Ok(HttpResponse::builder()
                .status(StatusCode::OK)
                .json(&json_value)?
                .build())
        })
        .delete(IpcCommand::StopClash.as_ref(), |ctx| async move {
            trace!("Received StopClash command");
            ipc_request_context_to_auth_context(&ctx)?;
            match CORE_MANAGER.lock().await.stop_core().await {
                Ok(_) => info!("Core stopped successfully"),
                Err(e) => {
                    let json_value: Response<()> = Response {
                        code: 1,
                        message: format!("Failed to stop core: {}", e),
                        data: None,
                    };
                    return Ok(HttpResponse::builder()
                        .status(StatusCode::SERVICE_UNAVAILABLE)
                        .json(&json_value)?
                        .build());
                }
            }
            let json_value: Response<()> = Response {
                code: 0,
                message: "Core stopped successfully".to_string(),
                data: None,
            };
            Ok(HttpResponse::builder()
                .status(StatusCode::OK)
                .json(&json_value)?
                .build())
        })
        .put(IpcCommand::UpdateWriter.as_ref(), |ctx| async move {
            trace!("Received UpdateWriter command");
            ipc_request_context_to_auth_context(&ctx)?;
            match ctx.json::<WriterConfig>() {
                Ok(writer_config) => {
                    match set_or_update_writer(&writer_config).await {
                        Ok(_) => info!("Update writer successfully"),
                        Err(e) => {
                            let json_value: Response<()> = Response {
                                code: 1,
                                message: format!("Failed to update writer: {}", e),
                                data: None,
                            };
                            return Ok(HttpResponse::builder()
                                .status(StatusCode::SERVICE_UNAVAILABLE)
                                .json(&json_value)?
                                .build());
                        }
                    };
                    let json_value: Response<()> = Response {
                        code: 0,
                        message: "Update Writer successfully".to_string(),
                        data: None,
                    };
                    Ok(HttpResponse::builder()
                        .status(StatusCode::OK)
                        .json(&json_value)?
                        .build())
                }
                Err(e) => Ok(HttpResponse::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .text(format!("Invalid JSON: {}", e))
                    .build()),
            }
        })
        .delete(IpcCommand::RemoveTun.as_ref(), |ctx| async move {
            trace!("Received RemoveTun command");
            ipc_request_context_to_auth_context(&ctx)?;
            // Best-effort: a failed sweep is not a server error. The app only
            // calls this to recover a stuck adapter and will surface its own
            // guidance if the create still fails, so we always answer 200 and
            // report how many adapters were removed in `data`.
            let removed = super::tun_cleanup::remove_tun_adapters()
                .await
                .unwrap_or_else(|e| {
                    tracing::warn!("RemoveTun sweep failed: {e}");
                    0
                });
            let json_value = Response {
                code: 0,
                message: "Success".to_string(),
                data: Some(removed),
            };
            Ok(HttpResponse::builder()
                .status(StatusCode::OK)
                .json(&json_value)?
                .build())
        })
        .put(IpcCommand::KillSwitch.as_ref(), |ctx| async move {
            trace!("Received KillSwitch enable command");
            ipc_request_context_to_auth_context(&ctx)?;
            match ctx.json::<KillSwitchRequest>() {
                Ok(req) => Ok(killswitch_response(super::killswitch::enable(req).await)?),
                Err(e) => Ok(HttpResponse::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .text(format!("Invalid JSON: {e}"))
                    .build()),
            }
        })
        .delete(IpcCommand::KillSwitch.as_ref(), |ctx| async move {
            trace!("Received KillSwitch disable command");
            ipc_request_context_to_auth_context(&ctx)?;
            killswitch_response(super::killswitch::disable().await)
        })
        .get(IpcCommand::KillSwitch.as_ref(), |ctx| async move {
            ipc_request_context_to_auth_context(&ctx)?;
            killswitch_response(Ok(super::killswitch::status().await))
        })
        .post(IpcCommand::StartCorpVpn.as_ref(), |ctx| async move {
            trace!("Received StartCorpVpn command");
            ipc_request_context_to_auth_context(&ctx)?;
            match ctx.json::<CorpVpnStartRequest>() {
                Ok(req) => match super::corp_vpn::start(req).await {
                    Ok(data) => Ok(HttpResponse::builder()
                        .status(StatusCode::OK)
                        .json(&Response {
                            code: 0,
                            message: "Success".to_string(),
                            data: Some(data),
                        })?
                        .build()),
                    Err(e) => Ok(HttpResponse::builder()
                        .status(StatusCode::SERVICE_UNAVAILABLE)
                        .json(&Response::<()> {
                            code: 1,
                            message: format!("start corp vpn: {e}"),
                            data: None,
                        })?
                        .build()),
                },
                Err(e) => Ok(HttpResponse::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .text(format!("Invalid JSON: {e}"))
                    .build()),
            }
        })
        .delete(IpcCommand::StopCorpVpn.as_ref(), |ctx| async move {
            trace!("Received StopCorpVpn command");
            ipc_request_context_to_auth_context(&ctx)?;
            let _ = super::corp_vpn::stop().await;
            Ok(HttpResponse::builder()
                .status(StatusCode::OK)
                .json(&Response::<()> {
                    code: 0,
                    message: "Success".to_string(),
                    data: None,
                })?
                .build())
        })
        .get(IpcCommand::CorpVpnStatus.as_ref(), |ctx| async move {
            ipc_request_context_to_auth_context(&ctx)?;
            let data = super::corp_vpn::status().await;
            Ok(HttpResponse::builder()
                .status(StatusCode::OK)
                .json(&Response {
                    code: 0,
                    message: "Success".to_string(),
                    data: Some(data),
                })?
                .build())
        })
        .post(IpcCommand::EnsureCorpDriver.as_ref(), |ctx| async move {
            trace!("Received EnsureCorpDriver command");
            ipc_request_context_to_auth_context(&ctx)?;
            match ctx.json::<CorpEnsureDriverRequest>() {
                Ok(req) => match super::corp_vpn::ensure_driver(req).await {
                    Ok(_) => Ok(HttpResponse::builder()
                        .status(StatusCode::OK)
                        .json(&Response::<()> {
                            code: 0,
                            message: "Success".to_string(),
                            data: None,
                        })?
                        .build()),
                    Err(e) => Ok(HttpResponse::builder()
                        .status(StatusCode::SERVICE_UNAVAILABLE)
                        .json(&Response::<()> {
                            code: 1,
                            message: format!("ensure corp driver: {e}"),
                            data: None,
                        })?
                        .build()),
                },
                Err(e) => Ok(HttpResponse::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .text(format!("Invalid JSON: {e}"))
                    .build()),
            }
        });
    Ok(router)
}

fn killswitch_response(
    result: anyhow::Result<super::killswitch::KillSwitchStatus>,
) -> Result<HttpResponse> {
    Ok(match result {
        Ok(status) => HttpResponse::builder()
            .status(StatusCode::OK)
            .json(&Response {
                code: 0,
                message: "Success".to_string(),
                data: Some(status),
            })?
            .build(),
        Err(e) => {
            tracing::warn!("kill switch: {e}");
            HttpResponse::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .json(&Response::<()> {
                    code: 1,
                    message: format!("kill switch: {e}"),
                    data: None,
                })?
                .build()
        }
    })
}
