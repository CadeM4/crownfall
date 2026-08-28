# crownfall

`crownfall` is one fixed remote exploit chain built for the disposable target in
this directory. It is not a scanner and it has no arbitrary command, path,
payload, persistence, or target override.

The chain crosses three separate trust boundaries:

1. an encoded traversal passes a raw-path authorization check and normalizes to
   an internal administrator route;
2. an ordered tar containing a relative symbolic link writes the generated
   plugin outside the importer staging tree;
3. the uid/gid `10001` plugin sends duplicate `role` keys to a root keeper whose
   policy and backend disagree about which value wins.

The keeper accepts that last request as administrator and creates a root-owned
`0600` proof beneath a root-only `0700` directory. The client reconstructs and
hashes the canonical proof, verifies the keeper and Unix peer credentials,
checks the root-owned result file, removes every artifact, and confirms that the
signed result route returns `404` afterward.

## Files

- `crownfall.py` is the native client and generated plugin source.
- `prepare_lab.py` creates a one-lab ownership key, fingerprint, deployment
  environment, and URL-locked client authorization document.
- `target/crownfall_target.py` is the split uid `0` keeper and uid `10001` HTTP
  runtime.
- `target/Dockerfile` and `target/compose.yaml` define the disposable remote
  deployment.
- `target/README.md` documents the target protocol and each deliberate defect.

Python 3.11 or newer is sufficient for the client. The target requires Linux
and must start as root so it can construct the two identities. Docker Compose is
the intended remote deployment.

## Prepare one remote lab

Choose a disposable Linux VM you control, assign it a private address, and
restrict the VM firewall so the chosen port is reachable only from the operator
machine. From this directory on the operator machine:

```text
python prepare_lab.py --i-own-this-lab --base-url http://10.20.30.40:8785 --output prepared --bind-address 0.0.0.0 --listen-port 8785 --expose-all-interfaces
```

The output directory is created exclusively and preparation refuses to replace
an existing path. It contains:

- `target.env`, which belongs only on the disposable target;
- `authorization.json`, which stays with the operator and locks the client to
  the exact URL, lab identifier, key, and fingerprint;
- `deployment.json`, a non-secret description except for the lab identifier and
  fingerprint.

`target.env` and `authorization.json` both contain the ownership key. Transfer
only `target/` and `target.env` to the VM over an authenticated channel. Do not
publish either generated file or leave it in shell history.

On the disposable VM, place `target.env` beside the copied `target` directory,
then start the target:

```text
cd target
docker compose --env-file ../target.env up --build --detach
docker compose --env-file ../target.env ps
```

The image has no host mounts or persistent volume, uses a read-only image
filesystem with bounded tmpfs state, drops all capabilities except the three
needed to construct the split identities, and has an internal network, process
limit, memory limit, and no-new-privileges setting.

## Run the chain

Back on the operator machine:

```text
python crownfall.py --authorization prepared/authorization.json --i-own-this-lab
```

The client first resolves and pins the authorized address, then verifies a
fresh challenge-response MAC from the target. Plain HTTP is accepted only when
every resolved address is private or loopback. Redirects are never followed.

Progress records go to stderr. The final, machine-readable JSON on stdout
contains the controls, observed boundary transitions, root proof metadata,
hashes, cleanup evidence, and elapsed time. The ownership key and request MACs
are never included.

## Destroy the target

After the client reports successful cleanup, remove the container and its tmpfs
state on the VM:

```text
docker compose --env-file ../target.env down --remove-orphans
```

Delete the transferred target directory and `target.env` from the disposable
VM, then delete the local `prepared` directory when the authorization record is
no longer needed. A subsequent run must begin with a newly prepared directory
and a fresh ownership key.
