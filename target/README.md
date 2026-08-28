# crownfall target

`crownfall_target.py` is the disposable Linux target for Crownfall. It
runs two identities in one container:

- a root supervisor provides a fixed-operation keeper on
  `/run/crownfall/keeper.sock`;
- a forked HTTP service permanently drops to uid/gid `10001` before it binds its
  TCP listener or processes a bundle.

The target is deliberately vulnerable, but the privileged surface is narrow.
The keeper cannot run a command, load a module, accept a filesystem path, or
write caller-supplied content. It can create or remove only
`/srv/crownfall/proofs/<validated-32-hex-nonce>.proof`, and it generates every
byte of that file itself.

Use this image only as a disposable target you control. The supplied Compose
file has no host mounts, uses a read-only image, places mutable state on tmpfs,
and puts the service on an internal Docker network.

## Starting the target

The runtime requires two values:

- `CROWNFALL_LAB_ID`: 8-48 lowercase letters, digits, or hyphens;
- `CROWNFALL_OUTER_KEY_HEX`: a 32-byte ownership key encoded as 64 lowercase
  hexadecimal characters.

`prepare_lab.py` in the parent directory emits a matching `target.env` and
client authorization file. The commands below assume the recommended remote
layout, with `target.env` beside the copied `target` directory:

```sh
cd target
docker compose --env-file ../target.env up --build
```

The Compose default publishes only to `127.0.0.1`. A prepared remote lab may
set `CROWNFALL_BIND=0.0.0.0`; in that case, restrict the VM firewall to the
operator's source address. `CROWNFALL_PORT` controls both the published port and
the service port in the container.

The two readiness records are JSON lines. The root record includes
`"component":"keeper"`, uid/gid `0`, and socket mode `0660`. The HTTP record
includes `"component":"http"`, uid/gid `10001`, the bound address, port, lab
identifier, and fingerprint.

The runtime can also be started directly on a disposable Linux system:

```sh
sudo env \
  CROWNFALL_LAB_ID=crownfall-lab-01 \
  CROWNFALL_OUTER_KEY_HEX='<64-lowercase-hex>' \
  python3 crownfall_target.py --bind 127.0.0.1 --port 8785
```

Direct execution recreates `/srv/crownfall/{staging,plugins,results,proofs}`.
Do not run it on a host where that fixed tree contains anything valuable.

## Target fingerprint

The static target fingerprint is:

```text
HMAC-SHA256(
    outer_key,
    b"crownfall-target-v1\0" + lab_id_ascii
)
```

The public endpoint requires a fresh 32-lowercase-hex challenge:

```text
GET /manifest?challenge=<challenge>
```

It returns `service`, `protocol`, `lab_id`, `target_fingerprint`, the echoed
`challenge`, and `attestation_mac`. The attestation is:

```text
HMAC-SHA256(
    outer_key,
    b"crownfall-manifest-v1\0"
    + challenge_ascii + b"\0"
    + lab_id_ascii + b"\0"
    + fingerprint_ascii + b"\0"
    + b"1"
)
```

This binds a run to the configured lab without publishing the ownership key.

## Signed requests

Every route involved in the chain requires these single-instance headers:

```text
X-Crownfall-Lab: <lab id>
X-Crownfall-Time: <decimal Unix time>
X-Crownfall-Nonce: <32 lowercase hex>
X-Crownfall-Mac: <64 lowercase hex>
X-Application-Role: guest
```

The MAC input is UTF-8 bytes with no trailing newline:

```text
METHOD.upper()
raw request target, including query
lab id
decimal Unix time
request nonce
lowercase SHA-256 of the exact body
```

Those six fields are joined with `\n`. Requests outside the configured clock
window fail. A nonce is recorded only after its MAC verifies; a second valid use
of that nonce returns `request_replayed`.

## Deliberate chain

### 1. Raw-path authorization mismatch

The policy checks the raw request path and rejects a direct
`/internal/admin/...` request. Dispatch decodes and normalizes before routing.
The client uses these signed request targets:

```text
/public/%2e%2e/internal/admin/bundle
/public/%2e%2e/internal/admin/activate
/public/%2e%2e/internal/admin/result?proof_nonce=<32-hex>
/public/%2e%2e/internal/admin/cleanup
```

The raw policy sees a public prefix. Dispatch sees the intended internal admin
route.

### 2. Bundle link traversal

`bundle` accepts an uncompressed tar no larger than 256 KiB. The extractor
strictly checks the fixed three-member layout, member names, expanded size, file
size, and member types. It does not check a symbolic link's target before the
regular-file open, and that open follows intermediate links. A post-write guard
removes and rejects a file if it did not land at the fixed plugin destination.

The intended archive sequence is:

```text
notes                         directory
bridge -> ../plugins          symbolic link
bridge/crown_probe.py         regular file
```

The third lexical path is under staging. Its resolved path is
`/srv/crownfall/plugins/crown_probe.py`. The response records both paths,
member hashes, the landed file's uid/gid/mode, and whether the link was followed.
Failed extraction clears both application-owned working trees before returning.

### 3. Plugin activation

`activate` accepts exactly:

```json
{
  "plugin_name": "crown_probe.py",
  "plugin_sha256": "<64-lowercase-hex>",
  "proof_nonce": "<32-lowercase-hex>"
}
```

The target rechecks the file type, real path, size, ownership, and SHA-256. The
plugin runs as uid/gid `10001` through a small internal launcher with CPU,
address-space, output, descriptor, and process limits. There is no shell.

Before launch, the HTTP process independently attempts the fixed proof write and
requires `EACCES` or `EPERM`. The plugin repeats that control, then makes one
clean keeper request and one duplicate-role request.

### 4. Keeper parser differential

The keeper protocol uses a four-byte, unsigned, network-order length followed by
the exact JSON bytes. Request and response frames are each limited to 4096
bytes. The Unix peer must be uid/gid `10001`.

The clean request has one role:

```json
{
  "role": "guest",
  "op": "write_proof",
  "lab_id": "...",
  "proof_nonce": "...",
  "plugin_sha256": "..."
}
```

It reaches the backend and is denied as `backend_role_denied`. The second
request preserves two role keys in its raw bytes:

```json
{"role":"guest","op":"write_proof","lab_id":"...","proof_nonce":"...","plugin_sha256":"...","role":"admin"}
```

The policy constructs a first-key-wins object and sees `guest`. The backend uses
ordinary last-key-wins JSON semantics and sees `admin`. Only `role` may occur
twice; every other field must occur exactly once and match under both views.

The accepted operation creates:

- a root:root `0600` proof beneath the fixed `proofs` directory;
- a root:`10001` `0640` evidence record beneath the fixed `results` directory.

The evidence includes keeper and peer credentials, policy/backend roles, parent
directory mode, proof ownership/mode/size/hash, and nanosecond filesystem
timestamps. The HTTP process can read the result but cannot modify the result
directory.

## Result and cleanup

`result` takes `proof_nonce` as its only query parameter. It returns only a
regular, root-owned, mode-`0640` result whose embedded nonce matches the query.

`cleanup` accepts exactly:

```json
{
  "proof_nonce": "<32-lowercase-hex>",
  "plugin_sha256": "<64-lowercase-hex>"
}
```

The root keeper verifies the stored proof identity before deleting the proof and
result. The application then verifies and removes the landed plugin without
following links and clears staging. The response includes the proof's pre-delete
mode/hash/timestamps, root and peer identities, per-file deletion booleans, and
post-delete absence checks.

Cleanup is also safe after a partial run. If no proof was created, the endpoint
reports `partial_run` and still removes the matching plugin and staging entries.
After a complete cleanup, the signed `result` route returns HTTP 404.

## Container boundaries

The supplied deployment has the following properties:

- no host bind mounts or named volumes;
- read-only image filesystem;
- fixed state, runtime socket, and temporary files on size-limited tmpfs;
- internal Docker network;
- host publication on loopback unless explicitly changed;
- all Linux capabilities dropped except `CHOWN`, `SETGID`, and `SETUID`, which
  the root supervisor needs while constructing and splitting the two identities;
- `no-new-privileges`, a 64-process ceiling, and a 384 MiB container limit.

Destroy the container after the run:

```sh
docker compose --env-file ../target.env down --remove-orphans
```
