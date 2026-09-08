# Development Linux client command

The Phase 6 development binary exposes two commands:

```text
portico client catalog --config /absolute/path/client.json
portico client connect --config /absolute/path/client.json --resource UUID --revision N
```

Catalog returns versioned JSON inventory for the authenticated device. Connect selects an immutable resource ID and explicit positive revision from a fresh private catalog, verifies the actual connector through inner mutual TLS and live controller checks, and forwards application bytes through the existing workload protocol. An old revision is never silently upgraded. The catalog is advisory; it cannot authorize dialing. The connector independently checks its local destination tuple, hosting binding, device grant and current policy before opening a destination and activating forwarding.

Connect uses inherited application input/output pipes. It writes only resource payload to stdout and fixed error messages to stderr. It opens no local listener and accepts no destination, username, SOCKS request or cached permit. The calling application and its OS user are trusted to own those pipes. This is an initial stream adapter; a supported desktop client, browser access, enrollment UI, platform key stores, IPC isolation, Arch packaging and physical lifecycle qualification remain required.

## Protected configuration

The complete schema is [client.FileConfig](../internal/client/config.go): version (1), deployment_id, devices, connectors, identity_certificate_file, identity_key_file, control, carrier, operation_timeout_ms (1–5000) and idle_timeout_seconds (1–900). Devices and connectors each contain issuer_id, root_certificate_file and issuer_certificate_file. Control and carrier each contain url, root_certificate_file and spki_sha256.

The same [protected file rules](connector-configuration.md#local-files) apply to both clients and connectors through a shared identity parser. The client requires a device-profile leaf and its matching PKCS#8 software key; a connector identity is rejected. JSON is bounded to 64 KiB and rejects duplicate/case-alias keys, unknown fields, trailing documents and inline secrets. All paths and trust material are explicit. No configuration supplies a clock-health override. Other platforms fail closed until their native local-file and pipe adapters are qualified.

Both service endpoints are explicit pinned HTTPS loopback endpoints. One normalized local device identity supplies control, carrier and inner TLS credentials. The command checks native Linux clock health before contacting control and uses the workload clock supervisor thereafter. It installs no service and configures no system clock, global DNS or firewall. The native clock provider and remaining time-source qualification are described in the [clock contract](connector-clock.md).

## Application lifetime

Input EOF sends a workload FIN while output continues, allowing a destination to produce a final response after consuming the request. Output EOF closes the application output independently. The client joins both copy workers and waits for acknowledgment that the peer consumed the request before returning success. A validated consumed FIN can still yield zero-byte EOF after carrier closure; it never grants further byte reads, writes or lease authority.

Each copy direction uses one 32 KiB buffer. On abrupt carrier termination or caller cancellation, owned pipes close and unblock both workers. If all incoming DATA has already entered the application copy path and a valid FIN has been consumed, carrier closure permits that final buffered chunk to drain for at most operation_timeout_ms. Kernel pipe buffers and bytes already delivered to an application cannot be recalled. This finite drain does not renew authority or qualify the unresolved physical suspend/revocation timing scenarios.

The Linux adapter checks inherited FDs are pipes with the expected direction, then opens its own /proc/self/fd entries as pollable descriptions. This avoids changing shared O_NONBLOCK flags. CLI setup transfers ownership and closes the original stdin/stdout handles. It rejects terminals, regular files and sockets. Procfs access and pipe inode permissions must allow reopening; there is no permission-repair fallback. [Linux procfs descriptor documentation](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html), [Go file deadlines](https://pkg.go.dev/os#File.SetDeadline).

The guarded [client process scenario](../internal/controller/client_command_linux_test.go) runs the actual client and connector binaries inside a NIC-less Linux guest. It exercises native-clock startup rejection, unsafe keys, wrong profiles/overrides, exact inventory, no-authority selection failures, final output under backpressure, signals and grant revocation. Positive clock metadata is a synthetic disposable-kernel fixture, restored afterward; it does not prove real synchronization, change UTC or affect the host. The canonical acceptance matrix remains separate from this component evidence.
