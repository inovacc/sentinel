# Sentinel — Evidence-Driven Hardening Findings

**Source:** `F:\evicende_sentinel` CA-mismatch field-failure bundle (2026-06-03)
**Method:** 7 parallel code investigators + per-finding adversarial verification (34 agents). 27 findings confirmed, 0 refuted.
**Also done:** `go.mod` toolchain `1.26.3→1.26.4` — closes reachable CVEs GO-2026-5039 / GO-2026-5037 (govulncheck clean, tests green).

> The peer rotated its CA; its `:7400` daemon still served the stale server cert. The client correctly rejected it, but Sentinel could neither **detect**, **diagnose**, nor **recover** from this — and `doctor` reported all-green throughout. These clusters fix that chain.

## Cluster A — CA fingerprint pinning + rotation detection  [ROOT CAUSE]
_max severity: **CRITICAL** · 5 findings_

### no-per-peer-ca-fingerprint-storage  — `CRITICAL` · effort M · verdict confirmed
**Fleet registry lacks per-peer CA fingerprint field**

- **Current:** When a peer is registered in the fleet (cmd/bootstrap.go:258-273), only device_id, address, role, status are stored. The CA certificate received during bootstrap (result.CACertPEM) is saved locally in certs/ca.crt but never associated with the specific peer in the registry.
- **Evidence:** internal/fleet/registry.go:51-63 schema has device_id, hostname, os, arch, role, status, address, cert_pem, last_seen_at, created_at, metadata — NO ca_fingerprint or ca_cert column. Device struct (lines 21-33) likewise lacks CAFingerprint field.
- **Fix:** Add ca_fingerprint TEXT and ca_cert_pem BLOB columns to fleet_devices table schema. In Device struct, add CAFingerprint string and CACertPEM []byte fields. During bootstrap client save (cmd/bootstrap.go ~line 242), compute SHA-256 fingerprint of result.CACertPEM and store both the fingerprint and full cert with the peer entry.
- **Files:** `internal/fleet/registry.go`, `cmd/bootstrap.go`
- **Verifier:** Verified via re-reading the actual code:

1. Device struct (internal/fleet/registry.go:21-33) - confirmed it contains only: DeviceID, Hostname, OS, Arch, Role, Status, Address, CertPEM, LastSeenAt, CreatedAt, Metadata. NO CAFingerprint field exists.

2. Database schema (internal/fleet/registry.go:51-63) - confirmed the CREATE TABLE statement includes device_id, hostname, os, arch, role, status, ad

### no-ca-rotation-detection-on-connect  — `CRITICAL` · effort M · verdict confirmed
**No CA rotation detection when connecting to peer**

- **Current:** Client loads a single global ca.crt at startup and uses it for all peer connections. When resolving a peer by device ID, only the address is retrieved from fleet registry. There is no check that the peer's presented cert is signed by the CA fingerprint agreed during pairing.
- **Evidence:** internal/client/resolve.go:11-33 returns only device.Address; internal/client/client.go:94 loads LOCAL ca.crt once; no per-peer CA validation. internal/client/target.go:53 ResolveDevice returns only address string with no CA info.
- **Fix:** Modify ResolveDevice to return both address and expected CA fingerprint. Update client.ConnectFromStore to accept per-peer CA cert data. In client.Connect (line 33+), after loading caCertPEM, compute its fingerprint and compare against the peer-specific fingerprint stored in registry. Return a clear error if mismatch detected: 'peer %s CA rotated: expected %s got %s'.
- **Files:** `internal/client/resolve.go`, `internal/client/client.go`, `internal/client/target.go`
- **Verifier:** The gap is real. Evidence from code: (1) internal/client/resolve.go:11-33 returns only device.Address with no CA data; (2) internal/fleet/registry.go:29 shows Device has CertPEM field but it is never populated when devices are registered (see cmd/bootstrap.go:258-263 where only Address is set); (3) internal/client/client.go:94 loads a SINGLE global ca.crt used for all peer connections with no per-

### bootstrap-client-no-fingerprint-save  — `HIGH` · effort M · verdict confirmed
**Bootstrap client does not save or validate peer CA fingerprint at pairing time**

- **Current:** When 'sentinel connect' succeeds, the bootstrap client receives result.CACertPEM from the server but only stores it locally in certs/ca.crt. The peer device is registered with only {device_id, address, role, status}. No fingerprint of the peer's CA is recorded in the fleet registry.
- **Evidence:** cmd/bootstrap.go:242-273 calls store.SaveMTLS(result.SignedCertPEM, ..., result.CACertPEM) to save LOCAL certs, then calls reg.AddPending(peerDevice) where peerDevice has no CA fingerprint. The received CA cert is saved but never linked to the peer entry.
- **Fix:** In cmd/bootstrap.go:250-273, after receiving bootstrap result, compute SHA-256 fingerprint of result.CACertPEM. Pass CAFingerprint and CACertPEM to the peerDevice struct before calling reg.AddPending(). Update fleet.Device struct to include these fields and persist them via registry.
- **Files:** `cmd/bootstrap.go`, `internal/fleet/registry.go`
- **Verifier:** Re-read cmd/bootstrap.go:242-273, internal/fleet/registry.go:20-33, and internal/fleet/registry.go:71-83. The finding is accurate: (1) Line 243 saves result.CACertPEM to local filesystem via store.SaveMTLS(); (2) Lines 258-263 create peerDevice with only DeviceID, Address, Role, Status - result.CACertPEM is available but never passed to the Device struct; (3) The Device struct (registry.go:21-33) 

### no-pinning-on-first-use  — `HIGH` · effort M · verdict confirmed
**No pinning-on-first-use: peer CA fingerprint is not stored, enabling CA rotation attacks during bootstrap**

- **Current:** During bootstrap (cmd/bootstrap.go:236), the client receives the server's CA cert and saves it locally (line 242-246). However, the server's CA cert (result.CACertPEM) is NOT recorded in the fleet registry. On later connections to :7400 (mTLS), the client loads its own CA cert from the data dir but does NOT verify that the server's mTLS cert is signed by the same CA that was advertised during bootstrap. If the peer's CA rotates between bootstrap and mTLS connection, the mTLS handshake may fail with x509: certificate signed by unknown authority, but there is no recovery path or warning that the CA was swapped.
- **Evidence:** cmd/bootstrap.go:257-259 registers the peer in the fleet registry using only result.PeerDeviceID, result.MTLSAddr, and role='admin'. The Device struct (internal/fleet/registry.go:20-33) includes CertPEM field but the bootstrap flow does NOT save the server's CA cert or its fingerprint. At cmd/bootstrap.go:242-247, the client saves result.CACertPEM locally, but there is no check that the CA used on subsequent mTLS connections (7400) matches the CA received during bootstrap. internal/fleet/registry.go schema includes cert_pem column (line 59) but bootstrap.go does not populate it when calling reg.AddPending(peerDevice) at line 264.
- **Fix:** Save the server's CA certificate fingerprint (SHA256 hash) in the fleet registry's metadata field when bootstrapping. At mTLS connection time (pkg/transport/manager.go or mTLS dial logic), extract the server's mTLS cert chain, compute the fingerprint of the root CA, and compare it to the stored fingerprint. If mismatch, log a security event and refuse connection. Alternatively, save the full CA cert PEM in the registry.CertPEM field (currently unused per fleet/registry.go:29 json:"-") and validate it matches.
- **Files:** `cmd/bootstrap.go`, `internal/fleet/registry.go`, `pkg/transport/manager.go`
- **Verifier:** The gap exists as described. Evidence from code review:

1. cmd/bootstrap.go:242-246: CA cert IS saved locally to disk via store.SaveMTLS(result.SignedCertPEM, clientManager.DeviceKeyPEM(), result.CACertPEM)

2. cmd/bootstrap.go:258-263: When registering peer in fleet registry, peerDevice struct is created without setting CertPEM field: peerDevice := &fleet.Device{DeviceID: result.PeerDeviceID, Ad

### no-ca-fingerprint-storage-per-peer  — `MEDIUM` · effort M · verdict confirmed
**Fleet registry stores peer cert but no CA fingerprint; no per-peer CA trust pinning**

- **Current:** The fleet registry stores the peer's device cert in cert_pem but only one global CA cert is trusted (ca.crt in data dir). If a peer generates a new CA and re-bootstraps with a new device cert signed by the new CA, there is no way to track that this peer now requires trust from a different CA root — the global CA cert has already been rotated or is unavailable for that peer.
- **Evidence:** internal/fleet/registry.go:21-33 Device struct has CertPEM []byte field but no CAFingerprint or CAThumbprint field; fleet schema line 51-62 stores cert_pem BLOB but no ca_fingerprint; bootstrap handshake internal/ca/ca.go does not extract or record which CA signed the peer's cert
- **Fix:** Extend Device struct in internal/fleet/registry.go to include CAFingerprint (e.g., SHA-256 of the CA cert that signed this device). During bootstrap (pkg/transport/bootstrap.go line 204-206 sends CACertPEM), extract the fingerprint and store it per-peer. On mTLS connection, verify the peer cert against the peer's stored CA fingerprint, not just the global CA pool. This enables each peer to have its own CA trust anchor and supports CA rotation scenarios where different peers may be at different stages of the CA rollover.
- **Files:** `internal/fleet/registry.go`, `pkg/transport/bootstrap.go`, `internal/client/client.go`, `internal/grpc/server.go`
- **Verifier:** The finding is REAL and accurately describes a genuine gap. Evidence:

(1) Device struct: internal/fleet/registry.go:21-33 has CertPEM field but no CAFingerprint/CAThumbprint field.

(2) Database schema: internal/fleet/registry.go:50-63 stores cert_pem BLOB but no ca_fingerprint column.

(3) Bootstrap does not extract CA fingerprint: pkg/transport/bootstrap.go:203-252 (signAndExchangeCerts) receiv


## Cluster B — doctor fleet trust probe  [THE BLIND-SPOT]
_max severity: **HIGH** · 8 findings_

### doctor-no-ca-rotation-detection  — `HIGH` · effort M · verdict confirmed
**Doctor does not detect CA rotation drift between peers**

- **Current:** The registry stores peer device_id, address, role, status but does not store a reference fingerprint (hash) of the peer's CA or server cert. When a peer regenerates its CA (field-failure scenario), the local doctor has no record to compare against, so it cannot detect the drift.
- **Evidence:** internal/fleet/registry.go:21-32 Device struct stores only CertPEM (the enrollment cert), not the peer's expected server cert or CA fingerprint. cmd/doctor.go never loads or compares peer certificates. internal/fleet/health.go:156 loads LOCAL ca.crt for validation but does not store or compare per-peer CA certificates.
- **Fix:** Extend the Device struct in internal/fleet/registry.go to include CertFingerprint (SHA-256 hash of peer's CA cert or server cert). During bootstrap (cmd/bootstrap.go:264), store the peer's CA fingerprint in the registry. In doctor, compare stored fingerprint against the live peer's cert. Report WARN if the peer cert fingerprint has changed since registration.
- **Files:** `internal/fleet/registry.go`, `cmd/bootstrap.go`, `cmd/doctor.go`
- **Verifier:** internal/fleet/registry.go:21-32 Device struct confirmed to store only CertPEM (enrollment cert), not CACertFingerprint or peer CA fingerprint. Database schema at registry.go:50-65 has no fingerprint column. cmd/bootstrap.go:242-274 shows peer's CACertPEM received but not stored in registry—only saved locally. cmd/doctor.go:56-60 runDoctor() confirmed to perform no peer certificate checks whatsoev

### doctor-skips-peer-cert-trust  — `HIGH` · effort M · verdict confirmed
**Doctor command validates LOCAL certs but never probes peers' mTLS trust chain**

- **Current:** Doctor only checks: data directory exists, config schema valid, CA loaded, device cert valid, and listen ports available. It returns '5 ok, 0 warnings, 0 problems' even if every peer's :7400 mTLS server cert is signed by a DIFFERENT CA (peer rotated CA locally, client never updated). Doctor never opens a client connection to any peer to test if the stored CA will validate the peer's presented server cert.
- **Evidence:** cmd/doctor.go:56-86 runs checks: checkDataDir(), checkConfig(), checkCA(), checkDeviceCert(), checkPorts(). None of these probe fleet peers or attempt mTLS connections to verify peer certs are signed by the stored CA. internal/fleet/health.go:115-183 (HealthMonitor.pingDevice) loads certs from disk and dials peers, but this ONLY runs during daemon's health monitoring loop (serve.go:338) and is not part of 'sentinel doctor'. doctor.go has no health monitor or peer CA fingerprint comparison logic.
- **Fix:** Extend doctor.go to add a new check (checkPeerCerts or checkFleetHealth) that: 1) Lists all online/offline peers from registry; 2) For each peer with an address, attempts a test mTLS connection using stored CA certs; 3) If connection fails with 'certificate signed by unknown authority', warn/fail with peer device_id and suggest 'sentinel connect <address> --renew-certs'; 4) Store peer CA fingerprints in fleet registry (add ca_fingerprint column to fleet_devices table) and verify they haven't rotated unexpectedly.
- **Files:** `cmd/doctor.go (add checkFleetHealth or checkPeerTrust function)`, `internal/fleet/registry.go (add ca_fingerprint column to schema)`, `internal/fleet/registry.go (add UpdateCAFingerprint method)`, `cmd/bootstrap.go (store peer CA fingerprint in registry after successful handshake, line 271)`
- **Verifier:** Verified through direct code inspection:

cmd/doctor.go:56-86 (runDoctor function): Contains only 5 checks: checkDataDir(), checkConfig(), checkCA(), checkDeviceCert(), checkPorts(). None probe fleet peers or mTLS connections. The test at cmd/doctor_test.go:80 explicitly validates only these 5 checks exist.

internal/fleet/health.go:115-183 (HealthMonitor.pingDevice): Loads peer certs and dials pe

### doctor-no-peer-ca-validation  — `HIGH` · effort L · verdict confirmed
**Doctor command does not validate peer CA trust or detect rotation**

- **Current:** 'sentinel doctor' reports all GREEN when local state is valid, but provides zero visibility into whether any peer's CA has rotated or if trusted peers are reachable with valid certs. A peer can have a stale/rotated CA and doctor will not detect it.
- **Evidence:** cmd/doctor.go:56-86 runs checkDataDir, checkConfig, checkCA, checkDeviceCert, checkPorts. No fleet registry checks. No peer CA fingerprint validation. checkCA() (line 168-175) only loads local CA, never probes peers.
- **Fix:** Add checkFleetPeers() function to doctor that: (1) iterates over accepted/online devices in fleet registry, (2) for each peer, loads stored CA fingerprint, (3) makes a probe connection attempt (or checks stored metadata), (4) compares expected CA fingerprint against peer's cert, (5) reports WARN if mismatch or FAIL if connection fails. Include a 'fleet peers' check result in doctor output.
- **Files:** `cmd/doctor.go`
- **Verifier:** Verified cmd/doctor.go:56-86 runDoctor() calls only 5 checks: checkDataDir, checkConfig, checkCA(), checkDeviceCert, checkPorts. checkCA() at lines 168-175 only loads local CA via ca.Load(caDir) with no fleet registry or peer validation. Fleet registry (internal/fleet/registry.go) stores peer Device.CertPEM but no CA fingerprints. Health monitor (health.go:115-184 pingDevice) probes peers separate

### doctor-no-cert-san-validation  — `MEDIUM` · effort S · verdict confirmed
**Doctor does not validate peer certificate Subject Alternative Names**

- **Current:** When a client connects to a peer via mTLS (internal/client/client.go), the TLS config skips SAN verification. This works during normal operation (peers self-identify by device ID) but doctor has no way to detect if a peer's cert SAN does not match its advertised address.
- **Evidence:** internal/client/client.go:44-48 sets InsecureSkipVerify: true and only does manual peer cert chain validation (line 58), but does NOT verify hostname/IP SAN. The comment on line 48 explicitly states: 'Skip hostname/IP SAN check.' cmd/doctor.go has no peer connection logic at all.
- **Fix:** In the new checkFleetPeerTrust() function (recommendation 1), after validating the peer cert chain, extract and log the peer's certificate subject CN and SAN extensions. Compare against the peer.Address and peer.Hostname in the registry. Report WARN if SAN/CN does not match the expected identity (e.g., cert CN=TYGRIJLO but device_id is W6CAVI2M).
- **Files:** `cmd/doctor.go`
- **Verifier:** Verified the gap exists in code:

1. internal/client/client.go:48 explicitly sets InsecureSkipVerify: true with comment "Skip hostname/IP SAN check"
2. internal/client/client.go:49-63 VerifyPeerCertificate callback only validates CA chain via peerCert.Verify() with empty VerifyOptions - does not check DNSNames, IPAddresses, or subject CN
3. cmd/doctor.go:56-60 runDoctor() function only calls 5 che

### doctor-no-peer-reachability  — `MEDIUM` · effort M · verdict adjusted
**Doctor command does not probe registered fleet peers for mTLS connectivity**

- **Current:** Doctor performs 5 checks: (1) data dir structure, (2) config file, (3) CA loaded, (4) device cert expiry, (5) listen ports. All checks read local files or bind to local sockets. Registered fleet peers in the database are never queried or contacted.
- **Evidence:** cmd/doctor.go:56-86 runDoctor() calls checkDataDir, checkConfig, checkCA, checkDeviceCert, checkPorts — all local-only. No registry lookup, no peer discovery, no network probes. Fleet peers are never contacted.
- **Fix:** Add a 6th doctor check: checkFleetPeerTrust(cfg, registry). For each peer in registry.List(StatusOnline), attempt a gRPC dial to peer.Address using local mTLS certs (device cert + CA). Validate the peer's server cert is signed by the local CA. Report WARN if any peer is unreachable or serves a cert not signed by the CA. Report OK if all peers verify or if no peers are registered.
- **Files:** `cmd/doctor.go`
- **Verifier:** Confirmed: doctor command does NOT probe fleet peers (cmd/doctor.go:56-86 contains only 5 local-only checks as documented). Registry.List(StatusOnline) exists (internal/fleet/registry.go:140-168) but is never called during doctor execution. However, gap severity is MEDIUM not HIGH because: (1) peer reachability IS continuously monitored via HealthMonitor.Start() (internal/fleet/health.go:48-63, ca

### doctor-health-monitor-integration-gap  — `MEDIUM` · effort M · verdict confirmed
**Doctor command does not expose health monitor peer check errors to user**

- **Current:** The HealthMonitor (internal/fleet/health.go) is instantiated and run by the daemon (internal/cmd/serve.go or similar), not by doctor. Doctor never instantiates or calls the monitor. Peer cert validation errors (e.g., 'peer cert not signed by CA') are only logged to the daemon's stderr, not returned to the doctor command.
- **Evidence:** internal/fleet/health.go:115-143 pingDevice() performs mTLS dial and gRPC ping to peer. If dial fails (line 120, which includes cert validation errors), it returns error (line 122). But line 85-89 only mark device offline; the actual cert error is logged at WARN level and never surfaced to 'sentinel doctor' output.
- **Fix:** Either: (A) Have doctor instantiate HealthMonitor and run checkAll(ctx) synchronously on demand, capturing and reporting failures, OR (B) Create a separate doctor check function that directly probes peers using the same logic as health.go:pingDevice but with proper error reporting. Return peer trust errors as FAIL or WARN status.
- **Files:** `cmd/doctor.go`, `internal/fleet/health.go`
- **Verifier:** Confirmed by re-reading: (1) cmd/doctor.go:56-60 shows doctor calls checkDataDir, checkConfig, checkCA, checkDeviceCert, checkPorts - NO peer health check; (2) cmd/doctor.go:1-18 shows NO import of fleet package or database access; (3) cmd/serve.go:329 confirms HealthMonitor instantiated only in serve(), not doctor; (4) internal/fleet/health.go:85-90 shows errors ARE logged at WARN level with full

### no-peer-cert-diagnostic-in-doctor  — `MEDIUM` · effort M · verdict confirmed
**doctor command never validates peer mTLS trust or peer certificate authority chain**

- **Current:** Running 'sentinel doctor' and 'sentinel doctor --fix' both report all checks pass, even when a registered peer's :7400 mTLS server is serving a cert not signed by the local CA. The chicken-and-egg problem: doctor cannot fix the peer remotely, but it should at least WARN that the peer's cert is not verifiable.
- **Evidence:** cmd/doctor.go:168-174 checkCA() only loads local CA. cmd/doctor.go:177-200 checkDeviceCert() only validates local device cert (not expiry vs peer's expectation, not CA chain). cmd/doctor.go:202-226 checkPorts() only checks if ports are available, never attempts to connect to registered peers on :7400. doctor reports '5 ok, 0 warnings, 0 problems' even though 'fleet list' shows peer at 192.168.15.100:7400 with a mismatched server cert.
- **Fix:** Add a checkPeerTrust() function in cmd/doctor.go that: (1) reads 'fleet list' to enumerate registered peers, (2) attempts a TLS handshake to each peer's :7400 address (no gRPC call needed, just tls.Dial with manual VerifyPeerCertificate), (3) reports WARN if the peer's cert cannot be verified, with a message like 'peer DEVICE_ID at ADDRESS has a cert not signed by local CA — the peer may have rotated its CA without syncing'. This is a diagnostic-only check and should not fail doctor.
- **Files:** `cmd/doctor.go`
- **Verifier:** Confirmed via re-reading cmd/doctor.go:56-86 (runDoctor function only calls checkDataDir, checkConfig, checkCA, checkDeviceCert, checkPorts) and cmd/doctor.go:202-226 (checkPorts only checks local port availability with net.Listen, never connects to peers). The fleet registry at internal/fleet/registry.go:20-33 stores Device structs with Address and CertPEM fields, and internal/client/target.go pr

### doctor-no-peer-ca-trust-check  — `MEDIUM` · effort M · verdict confirmed
**Doctor command only validates local certs and CA, never probes peer :7400 mTLS trust**

- **Current:** Doctor reports all green if local directories, config, local CA, and local device cert are valid. It never attempts to connect to any peer on :7400 to verify their mTLS cert chain is signed by the stored CA. A peer that has rotated its CA or serves a stale cert remains invisible to doctor — the operator learns of the break only when 'sentinel exec' fails at runtime.
- **Evidence:** cmd/doctor.go:56-86 calls checkDataDir, checkConfig, checkCA (line 171 loads only local CA), checkDeviceCert (line 179 only reads local device.crt), checkPorts (line 202 only verifies local listen ports are available); no function validates that peers at registered addresses can be reached and their certs verify against the stored CA
- **Fix:** Add a 'fleet health' check to doctor that iterates through online devices in the fleet registry and attempts a test connection to each peer's :7400 address using the stored CA cert pool. Report warnings if any peer cert fails to verify against the trusted root. This mirrors the health monitor in internal/fleet/health.go but runs on-demand rather than continuously. Invoke fleet.HealthMonitor.pingDevice or a similar function for each registered peer.
- **Files:** `cmd/doctor.go`
- **Verifier:** Verified cmd/doctor.go:56-86 calls only local checks: checkDataDir, checkConfig, checkCA (line 171 loads only local CA via ca.Load), checkDeviceCert (line 179 reads only local device.crt), and checkPorts (line 202 tests local listen availability). No imports of fleet package; no calls to registry.List(), pingDevice(), or dialDevice() from internal/fleet/health.go. The fleet health monitor code exi


## Cluster C — Actionable error surfacing (x509 classify + SilenceUsage)
_max severity: **HIGH** · 4 findings_

### missing-silence-flags  — `HIGH` · effort S · verdict confirmed
**exec command does not suppress usage output on error (SilenceUsage/SilenceErrors)**

- **Current:** User runs 'sentinel exec 192.168.15.100:7400 ls' with stale peer cert. ConnectFromStore fails with 'client: peer cert not signed by CA: x509: certificate signed by unknown authority'. Cobra prints entire 'Execute a command on a sentinel daemon' help text, flags documentation, and raw error—overwhelming and not actionable.
- **Evidence:** cmd/exec.go:17-55 defines execCmd with no SilenceUsage or SilenceErrors fields set. Compare to cmd/doctor.go:47 which sets 'SilenceUsage: true'. When RunE returns an error, cobra's default behavior (no silence flags) prints the full usage block + error to stderr.
- **Fix:** Add SilenceUsage: true and SilenceErrors: true to execCmd definition in cmd/exec.go:18. Then customize error output in runExec to call a diagnostic helper that formats the x509 error with a remediation hint (e.g., 'The peer\'s certificate authority has changed. Run: sentinel pair --renew or re-pair the device').
- **Files:** `cmd/exec.go`
- **Verifier:** Verified by direct inspection: cmd/exec.go:18-47 defines execCmd with no SilenceUsage or SilenceErrors fields set. Confirmed by comparison: cmd/doctor.go:47 explicitly sets SilenceUsage: true, proving the feature is known and used elsewhere. The x509 error path is real (cmd/exec.go:70-72 calls ConnectFromStore which can fail with cert verification errors). When RunE returns an error without silenc

### no-x509-error-classification  — `HIGH` · effort M · verdict confirmed
**No classification of x509 handshake errors into user-friendly messages**

- **Current:** When mTLS handshake fails with x509 verification error (e.g., peer cert signed by different CA), the error propagates unwrapped from gRPC/tls library through ConnectFromStore and runExec, then cobra prints the raw error message and full usage/help block to stderr, with no guidance on remediation.
- **Evidence:** cmd/exec.go:70-72 returns raw error: 'c, err := client.ConnectFromStore(addr, certDir)' then 'if err != nil { return err }'. internal/client/client.go:49-63 manually verifies peer cert with VerifyPeerCertificate callback that returns 'fmt.Errorf("client: peer cert not signed by CA: %w", err)' wrapping the raw x509.VerifyError. pkg/transport/mtls.go:62-74 has similar manual verification returning 'fmt.Errorf("mtls: peer cert not signed by CA: %w", err)'. No attempt to classify whether the error is x509.UnknownAuthorityError, expired cert, wrong CA, etc.
- **Fix:** Create an internal/errors package with a ClassifyX509Error(err error) function that detects x509.UnknownAuthorityError, x509.CertificateInvalidError, and other cert failures, returning a typed error with Severity and Remediation fields. Call this in cmd/exec.go after ConnectFromStore fails, and set execCmd.SilenceUsage=true + execCmd.SilenceErrors=true to suppress cobra's default usage dump. Return a cleanly formatted error message instead.
- **Files:** `cmd/exec.go`, `internal/client/client.go`, `internal/errors/x509.go (new)`
- **Verifier:** Verified in cmd/exec.go:17-55 that execCmd does NOT set SilenceUsage or SilenceErrors (comparing to doctor.go:47 which does set SilenceUsage=true). Verified in cmd/exec.go:70-72 that ConnectFromStore error is returned raw without classification. Verified in internal/client/client.go:60 and pkg/transport/mtls.go:72 that x509 errors are wrapped with fmt.Errorf but never classified into specific x509

### cert-mismatch-no-user-guidance  — `MEDIUM` · effort S · verdict confirmed
**Client connection failure (cert mismatch) returns raw x509 error with no recovery hint**

- **Current:** When peer's CA has rotated (peer regenerated CA but :7400 daemon still serves old server cert), 'sentinel exec <peer> cmd' fails with opaque x509 error. User has no guidance that this is a CA mismatch (not a network error) and that 'sentinel connect <peer-bootstrap-addr> --renew-certs' would recover.
- **Evidence:** internal/client/client.go:59-62 returns 'peer cert not signed by CA' error wrapped in client.go:70 as 'client: dial %s: %w'. The error string is a bare x509 verify error. cmd/exec.go:57-86 (runExec) catches error at line 71 and wraps again as 'resolve target: %w' or line 72 'exec: %w'. No try/catch logic checks if the error contains 'signed by unknown authority' and suggests re-pairing. The user sees only: 'x509: ECDSA verification failure while trying to verify candidate authority certificate'.
- **Fix:** In internal/client/client.go, wrap the VerifyPeerCertificate callback (line 49-63) to detect 'certificate signed by unknown authority' or 'ECDSA verification failure' and annotate the error with: 'peer mTLS CA may have rotated; try: sentinel connect <bootstrap-addr> --renew-certs to re-pair'. Optionally, in cmd/exec.go, check if the error message contains cert keywords and suggest recovery command to stderr before returning the error.
- **Files:** `internal/client/client.go (enhance VerifyPeerCertificate error message, lines 49-63)`, `cmd/exec.go (check error message and append recovery suggestion, line 71)`
- **Verifier:** Confirmed by direct code review:

EVIDENCE OF GAP:
1. internal/client/client.go:49-63: VerifyPeerCertificate callback returns raw x509 error wrapped only as "client: peer cert not signed by CA: %w" (line 60)
2. internal/client/client.go:66-71: Error from callback is wrapped again as "client: dial %s: %w" (line 70)
3. cmd/exec.go:70-72: ConnectFromStore error is returned directly with NO error insp

### x509-error-not-unwrapped-for-inspection  — `MEDIUM` · effort M · verdict confirmed
**x509 errors are wrapped multiple times without unwrapping for type assertion**

- **Current:** The underlying x509.UnknownAuthorityError or x509.CertificateInvalidError is buried under multiple fmt.Errorf wrappers, making it impossible to distinguish 'peer cert signed by wrong CA' from 'peer cert expired' or 'peer cert malformed' without string parsing.
- **Evidence:** internal/client/client.go:58-61 calls peerCert.Verify(...) which returns an x509.VerifyError, then wraps it: 'fmt.Errorf("client: peer cert not signed by CA: %w", err)'. Then ConnectFromStore:99 wraps again: 'return Connect(...)'. Then cmd/exec.go:70-72 just returns the wrapped error. At no point is errors.As() or type assertion used to inspect the underlying x509.VerifyError and check if it is x509.UnknownAuthorityError.
- **Fix:** In a new internal/errors/x509.go utility, define a function that uses errors.As(err, &x509.UnknownAuthorityError{}) to unwrap and identify the specific x509 failure mode. Use this in cmd/exec.go to map errors to specific remediation messages: UnknownAuthorityError → 're-pair the device', CertificateInvalidError (expired) → 'renew certs', etc.
- **Files:** `internal/errors/x509.go (new)`, `cmd/exec.go`
- **Verifier:** Verified the finding is real by examining cited code:

1. internal/client/client.go:58-61 (actual lines 49-63): peerCert.Verify() called, error wrapped with fmt.Errorf("client: peer cert not signed by CA: %w", err) at line 60. The underlying x509.VerifyError is buried.

2. internal/client/client.go:99: ConnectFromStore returns Connect() result directly, propagating the wrapped error.

3. cmd/exec.


## Cluster D — mDNS identity verification (LAN spoof surface)
_max severity: **HIGH** · 3 findings_

### mdns-advertised-id-not-verified  — `HIGH` · effort M · verdict confirmed
**Advertised mDNS device ID is never compared to bootstrap server's self-identified device ID**

- **Current:** When 'sentinel connect --discovery' is used: (1) mDNS scanner advertises a device ID in the TXT record (internal/discovery/mdns.go:64-67). (2) discoverServerAddr() prints the advertised device ID but discards it (cmd/connect.go:73). (3) Only the address is passed to bootstrap connect. (4) Bootstrap client verifies the server's TLS cert device ID matches its hello message (pkg/transport/bootstrap.go:377-380), but never checks if that ID matches the original mDNS advertised ID. A peer at 192.168.15.100:7399 advertising device ID 'TYGRIJLO-...' over mDNS could respond to bootstrap requests identifying itself as 'W6CAVI2M-...', and the client will accept it because there is no identity continuity check between discovery and bootstrap handshake.
- **Evidence:** cmd/connect.go:62-82 discoverServerAddr() extracts devices[0].DeviceID and prints it to stderr but returns ONLY devices[0].Address (the IP:port). This address is passed to runBootstrapConnect(addr, role) at cmd/connect.go:46, which calls bc.Connect(ctx, addr, role) at cmd/bootstrap.go:236 — the address only, no advertised device ID. The BootstrapClient.Connect() method at pkg/transport/bootstrap.go:329-475 never receives or checks the advertised device ID. It only verifies the TLS certificate's device ID matches the hello message device ID (lines 356-380), but this is a local TLS handshake verification, not a comparison to the mDNS-advertised ID.
- **Fix:** Modify cmd/connect.go to carry the advertised device ID through the bootstrap flow: (1) Change discoverServerAddr() to return both address and device ID (e.g., struct { addr string; deviceID string }). (2) Pass the advertised device ID to runBootstrapConnect(). (3) In BootstrapClient.Connect(), accept an optional expectedDeviceID parameter. (4) After extracting serverDeviceID from TLS cert (pkg/transport/bootstrap.go:356-366), add a verification: if expectedDeviceID != "" and serverDeviceID != expectedDeviceID, return an error: "bootstrap: server device ID mismatch with mDNS advertisement: advertised=%s, server=%s". This ensures identity continuity from discovery to bootstrap.
- **Files:** `cmd/connect.go`, `cmd/bootstrap.go`, `pkg/transport/bootstrap.go`
- **Verifier:** The gap is real and exactly as described. Code verification:

1. cmd/connect.go:62-82 (discoverServerAddr): Extracts devices[0].DeviceID at line 73 and prints it, but returns only devices[0].Address at line 74 — the advertised device ID is discarded.

2. cmd/connect.go:46: Calls runBootstrapConnect(addr, role) with address only.

3. cmd/bootstrap.go:236: Calls bc.Connect(ctx, addr, role) passing o

### bootstrap-hello-mismatch-accepted-without-warning  — `MEDIUM` · effort S · verdict confirmed
**mDNS advertised device ID can differ from bootstrap hello ID; client accepts anyway without warning**

- **Current:** User runs 'sentinel connect --discovery', mDNS returns device A, but bootstrap hello identifies as device B. No warning printed. User proceeds and pairs with B's CA cert, registers B in fleet. Later, when trying to reach device A (different machine), lookup fails or connects to wrong peer.
- **Evidence:** cmd/connect.go:73 prints 'Discovered %s at %s' from mDNS beacon (discovery.DeviceID). pkg/transport/bootstrap.go:139-150 validates hello device ID matches TLS cert device ID (server-side check). However, there is NO client-side check in the BootstrapClient (must be in pkg/transport/bootstrap_client.go) to verify that the mDNS-advertised device ID matches the Hello message device ID received from the server. If mDNS advertises TYGRIJLO-... but bootstrap hello says W6CAVI2M-..., the client will silently accept and proceed (chicken-and-egg scenario: bootstrap succeeds, only :7400 is broken).
- **Fix:** In cmd/connect.go (lines 73-81), after discovering server address via mDNS, parse mDNS DeviceID. After bootstrap handshake completes (line 236 result returned), extract peerDeviceID from result and compare to mDNS device ID. If they differ, warn user: 'WARNING: mDNS advertised %s but bootstrap identified as %s. Possible MITM or misconfigured device. Accept (y/n)?'. Require explicit approval before storing credentials.
- **Files:** `cmd/connect.go (add mDNS device ID comparison post-bootstrap, lines 73-81)`, `cmd/bootstrap.go (lines 184-299, ensure runBootstrapConnect returns peer identity for comparison)`
- **Verifier:** The gap is real. Verified by reading: (1) cmd/connect.go:73 prints the mDNS device ID but the function only returns the address. (2) cmd/connect.go:46 calls runBootstrapConnect(addr, role) with no mDNS device ID parameter. (3) cmd/bootstrap.go:236 calls bc.Connect(ctx, addr, role) without any mDNS device ID. (4) pkg/transport/bootstrap.go:414 returns result.PeerDeviceID from the bootstrap hello, b

### device-id-not-cryptographically-bound  — `MEDIUM` · effort M · verdict adjusted
**Device ID is derived from TLS cert subject CN but not cryptographically bound as a principal identifier**

- **Current:** Device ID is computed from the bootstrap certificate (line 362) as ca.DeviceID(serverCertPEM), then the hello message includes a DeviceID field sent over the wire (line 112). There is no cryptographic proof that the ID matches the cert; it's a computed value. An attacker cannot forge the cert, but if the cert structure changes, the ID computation might differ, and there is no explicit binding in the cert itself (e.g., SubjectAltName or OID extension with the ID).
- **Evidence:** internal/ca/ca.go likely computes DeviceID() by hashing the cert's public key or subject. In pkg/transport/bootstrap.go:362, ca.DeviceID(serverCertPEM) extracts the ID from the cert. The bootstrap protocol (HelloMessage at lines 111-119, serverHello at line 371) sends device ID in plaintext. The ID is NOT in a certificate extension or signed blob; it's derived on-the-fly. This is similar to Syncthing's pattern but Syncthing binds the device ID into the cert's Subject:CN or as an extension. Here, the ID is computed ad-hoc and sent in protocol messages, which is less tamper-evident.
- **Fix:** Store the device ID as an explicit X.509 certificate extension (e.g., OID 1.3.6.1.4.1.NNNNN.1 = 'SentinelDeviceID') in bootstrap and mTLS certs at cert generation time (pkg/transport/bootstrap.go:GenerateBootstrapIdentity, internal/ca/ca.go:SignCSR). Then validate that the computed ca.DeviceID() matches the extension value. This makes the ID cryptographically bound and auditable. Alternative (lighter): include the device ID in the certificate Subject:CN (e.g., "sentinel-<device-id>") and validate it matches the hello message.
- **Files:** `pkg/transport/bootstrap.go`, `internal/ca/ca.go`
- **Verifier:** CONFIRMED: Device ID is derived from certificate DER bytes (internal/ca/identity.go:20: sha256.Sum256(block.Bytes)) but NOT embedded as an explicit X.509 extension. The bootstrap certificate template (pkg/transport/bootstrap.go:559-570) contains no device ID extension. CA-signed certs also lack this (internal/ca/ca.go:168, 219 only add roleExtension, not deviceID extension).

HOWEVER, SEVERITY IS 


## Cluster E — Recovery / re-pair (renew) CLI flow
_max severity: **HIGH** · 1 findings_

### renewal-no-cli-trigger  — `HIGH` · effort M · verdict confirmed
**EnableRenewal method exists but has no CLI entry point**

- **Current:** Transport layer has full renewal capability (PhaseRenewing state, timeout handling, transition logic) but it is unreachable from CLI. If a user's peer CA rotates or mTLS cert becomes stale, there is no 'sentinel renew-certs' or similar command to trigger the recovery.
- **Evidence:** pkg/transport/transport.go:276-317 defines EnableRenewal() which temporarily opens bootstrap for cert exchange. However, searching all cmd/*.go files and root.go:27-45 shows NO command that calls EnableRenewal(). The CLAUDE.md file (line 22) documents '--renew-certs flag' as design intent, but this flag is never implemented in any command.
- **Fix:** Create a new 'sentinel renew' or 'sentinel renew-certs' command (in cmd/renew.go or extend cmd/serve.go with a flag) that: 1) Checks if daemon is running (via PID file in datadir); 2) Sends signal to daemon to call transportMgr.EnableRenewal(ctx); 3) Waits for bootstrap to open; 4) Guides user through re-pairing. Alternatively, add '--renew-certs' to 'sentinel serve' that immediately opens bootstrap without waiting for a remote signal.
- **Files:** `cmd/renew.go (new file)`, `cmd/root.go (register new renew command)`, `cmd/serve.go (optional: add --renew-certs flag to serve)`
- **Verifier:** Re-read pkg/transport/transport.go:276-317 which contains the complete EnableRenewal() implementation. Verified cmd/root.go:27-45 lists all 17 registered CLI commands with no renewal/renew command present. Searched entire cmd/ directory (22 .go files) and found no renew.go or renewal-related command. Grep search for "EnableRenewal" in cmd/ and internal/grpc/ directories returns zero results in imp


## Cluster F — Bootstrap surface + RBAC + EKU least-privilege
_max severity: **HIGH** · 4 findings_

### bootstrap-always-open  — `HIGH` · effort M · verdict confirmed
**Bootstrap port remains open indefinitely alongside mTLS daemon**

- **Current:** Once the mTLS listener starts, the bootstrap port (:7399) never closes and accepts new pairing connections indefinitely. Both listeners coexist and accept connections throughout daemon lifetime.
- **Evidence:** cmd/serve.go:304 sets `BootstrapTimeout: 0` with comment 'No timeout — keep bootstrap open for pairing'; pkg/transport/transport.go:391-402 shows timeout only triggers if `BootstrapTimeout > 0`; cmd/serve.go:504-507 calls `StartBootstrapOnly(ctx)` with no transition logic to close it
- **Fix:** Add a configurable BootstrapTimeout that defaults to a short window (e.g., 5 minutes after mTLS transition completes). After timeout, closeBootstrap() is called. If continuous pairing is required by roadmap, gate it behind explicit config flag (Security.ContinuousPairingEnabled) that defaults to false, and log each bootstrap connection when enabled to detect abuse.
- **Files:** `cmd/serve.go`, `pkg/transport/transport.go`, `internal/settings/settings.go`
- **Verifier:** Re-reading the code confirms the gap exists but with important context:

CONFIRMED PATH: In the post-pairing scenario (when daemon has mTLS certs and restarts):
- cmd/serve.go:304: BootstrapTimeout explicitly set to 0
- pkg/transport/transport.go:115-117: NewManager converts 0 to 5 minutes, BUT...
- pkg/transport/transport.go:145-146: Phase is set to PhaseMTLS (not PhaseBootstrap) when mTLS certs 

### role-grant-default-operator  — `HIGH` · effort M · verdict confirmed
**Peer requesting bootstrap without CA is automatically granted operator role**

- **Current:** When a peer joins via bootstrap without owning a CA, it requests signing from the peer that has CA. The code at line 272 hardcodes RequestedRole to 'operator', but the actual role assignment depends on the OnPeerAccepted callback. If auto-accept is enabled, the role is silently granted without explicit admin approval of the role level.
- **Evidence:** pkg/transport/bootstrap.go:272 (requestCertFromPeer): hardcodes `RequestedRole: ca.RoleOperator` when peer lacks CA and requests signing from server; cmd/serve.go:437-439 (buildOnPeerAccepted): auto-accept callback returns true without role validation when autoAccept is enabled
- **Fix:** Remove hardcoded operator default at bootstrap.go:272; instead, expose a ConfigurableBootstrapRole in Config or use a callback to determine the role for new peers. In buildOnPeerAccepted (serve.go), require explicit admin approval when auto-accept is disabled, and log the requested role. When auto-accept is enabled, default to the least-privilege role (RoleReader) instead of operator, and only grant higher roles if a config/policy explicitly allows it by peer ID or hostname.
- **Files:** `pkg/transport/bootstrap.go`, `cmd/serve.go`, `pkg/transport/transport.go`
- **Verifier:** Verified the gap exists in the code: (1) pkg/transport/bootstrap.go:271 hardcodes RequestedRole to ca.RoleOperator when a peer without CA requests signing from server with CA. (2) pkg/transport/bootstrap.go:226-229 shows that when the peer receives this request, it signs with the requested role unless invalid, defaulting only to RoleReader if the request is malformed. (3) cmd/serve.go:437-439 show

### eku-overly-broad  — `MEDIUM` · effort M · verdict confirmed
**Device and bootstrap certificates carry both ClientAuth and ServerAuth ExtKeyUsage**

- **Current:** All device certificates and bootstrap certificates are issued with both ClientAuth and ServerAuth ExtKeyUsage, regardless of the role assigned. A reader-role device is cryptographically capable of acting as both client and server; role-based access control is enforced only at the gRPC method layer, not the TLS layer.
- **Evidence:** internal/ca/ca.go:166-168 (SignDevice): `ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}`; internal/ca/ca.go:217-219 (SignCSR): identical ExtKeyUsage; pkg/transport/bootstrap.go:568 (GenerateBootstrapIdentity): same both usages
- **Fix:** Scope ExtKeyUsage per role: assign only ExtKeyUsageClientAuth to reader/operator roles (they only initiate outbound mTLS connections), and ExtKeyUsageServerAuth | ExtKeyUsageClientAuth to admin role (which may bootstrap other devices). Bootstrap identities should use both until the device is promoted to mTLS. Encode this in SignDevice(role) and SignCSR(role) templates before the x509.CreateCertificate call.
- **Files:** `internal/ca/ca.go`, `pkg/transport/bootstrap.go`
- **Verifier:** Re-read code confirms all three cited locations:

1. internal/ca/ca.go:166 (SignDevice): `ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}` - hardcoded regardless of role parameter

2. internal/ca/ca.go:217 (SignCSR): `ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}` - same hardcoding

3. pkg/transport/bootstrap.go:568 

### role-not-validated-at-transport  — `MEDIUM` · effort M · verdict confirmed
**Role is not validated or gated at TLS transport layer; enforcement only at gRPC method level**

- **Current:** A device cert with a 'reader' role is accepted at the TLS layer and can attempt any gRPC method. The RBAC policy then blocks the method call at the gRPC handler level. This creates a gap: invalid/revoked devices pass TLS, and gRPC methods are the only barrier to role violation.
- **Evidence:** internal/ca/role.go:31-49 (ExtractRole) extracts role from cert but never used in pkg/transport/transport.go or pkg/transport/bootstrap.go; pkg/transport/transport.go:419-424 (startMTLS) accepts any cert signed by CA without checking ExtKeyUsage or role; internal/rbac/rbac.go:75-86 (Check) enforces per method, not at connection layer; gRPC server never pre-checks role before routing to service methods
- **Fix:** Extract the role from the peer certificate in startMTLS (after TLS handshake in the gRPC server's unary/stream interceptor chain) and validate it matches the expected role in a role whitelist per service. Store the role in the gRPC context (ctx.WithValue) and use it in place of or alongside method-level RBAC checks. Add a connection-level audit log of role + method on every request. Consider adding a per-role max-concurrent-connection limit in the transport layer.
- **Files:** `pkg/transport/transport.go`, `internal/grpc/grpc_server.go`, `internal/rbac/rbac.go`
- **Verifier:** Confirmed: Code review shows:

1. pkg/transport/transport.go:419-424 (startMTLS): TLS config has no VerifyPeerCertificate callback, no ExtKeyUsage validation, accepts any CA-signed cert
2. internal/ca/role.go:31-49 (ExtractRole): Function exists but is only called in internal/grpc/interceptor.go:58, never at TLS layer
3. internal/grpc/interceptor.go:52-68 (checkAccess): Role validation happens in 


## Cluster G — Revocation + CA-rotation trust window
_max severity: **HIGH** · 2 findings_

### single-ca-pool-no-rotation  — `HIGH` · effort M · verdict confirmed
**No support for CA rotation overlapping or old+new CA trust during rollover**

- **Current:** Each mTLS connection constructs an x509.CertPool containing exactly one CA cert loaded from ca.crt. If a peer rotates its CA (generates new root cert), old signed certs become invalid because the new CA root is not in the pool. There is no mechanism to load or trust both old and new CAs during a transition window.
- **Evidence:** pkg/transport/mtls.go:32-35 creates single CertPool with AppendCertsFromPEM(cfg.CACertPEM); pkg/transport/store.go:20 saves only ONE 'ca.crt' file; pkg/transport/transport.go:414-417 loads single CA; internal/client/client.go:39-40 loads single CA into RootCAs pool
- **Fix:** Extend CertStore to support ca-old.crt and ca-new.crt (or a ca-rotation.crt bundle). Modify CertPool construction in mtls.go and all client/server TLS code to AppendCertsFromPEM both roots if both exist. Add a rotation overlap window (e.g., 7 days) after bootstrap receives a new CA cert from a peer: save the new CA to ca-new.crt, trust both ca.crt and ca-new.crt until the old one expires. Once old certs expire, rotate ca-new.crt -> ca.crt and drop ca-old.crt.
- **Files:** `pkg/transport/store.go`, `pkg/transport/mtls.go`, `pkg/transport/transport.go`, `internal/client/client.go`, `internal/grpc/server.go`, `internal/fleet/health.go`
- **Verifier:** Verified all cited code paths confirm the gap:

1. pkg/transport/mtls.go:32-35: Creates single x509.CertPool with one CA cert via AppendCertsFromPEM(cfg.CACertPEM) - no multi-CA support.

2. pkg/transport/store.go:20,27: Saves to single "ca.crt" file constant only.

3. pkg/transport/store.go:78-88 (SaveMTLS): Writes single caCertPEM to fileCACert, always overwrites.

4. pkg/transport/store.go:92-1

### no-crl-ocsp-revocation  — `HIGH` · effort L · verdict confirmed
**No revocation mechanism: CA advertises KeyUsage CRLSign but no CRL is issued or checked**

- **Current:** The root CA template includes KeyUsageCRLSign flag, implying that CRLs should exist. However, no CRL is ever generated, distributed, or checked. Certificates are verified only against the trusted root — once signed, they remain valid until expiry, even if compromised or needing immediate revocation.
- **Evidence:** internal/ca/ca.go:62 sets KeyUsage x509.KeyUsageCertSign | x509.KeyUsageCRLSign on root CA cert; pkg/transport/mtls.go:70 and internal/client/client.go:58 call cert.Verify(x509.VerifyOptions{Roots: caPool}) with no Roots.CRL or VerifyConnection hook; no CRL distribution points extension found in device certs (internal/ca/ca.go:165-168 sets KeyUsage and ExtKeyUsage but no CRLDistributionPoints extension)
- **Fix:** Add CRL support: (1) Generate and persist CRLs in the CA directory after revoking device certs. (2) Add CRLDistributionPoints extension to device cert templates (internal/ca/ca.go:168) pointing to a local or HTTP endpoint. (3) Implement VerifyConnection callback in tls.Config to fetch and check CRL before accepting connections (pkg/transport/mtls.go:70, internal/client/client.go:58). Alternatively, use OCSP for real-time revocation checks. At minimum, remove KeyUsageCRLSign if CRL support is not planned, to avoid false expectations.
- **Files:** `internal/ca/ca.go`, `pkg/transport/mtls.go`, `internal/client/client.go`, `internal/grpc/server.go`
- **Verifier:** Verified all cited code:

1. Root CA KeyUsageCRLSign: internal/ca/ca.go:62 sets "KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign" on the root CA template.

2. No CRL issued/checked: 
   - internal/ca/ca.go:165-168: Device cert template has no CRLDistributionPoints extension
   - No CRL generation code exists in the codebase
   - pkg/transport/mtls.go:70: cert.Verify() called with only Roots

