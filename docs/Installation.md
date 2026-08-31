# Installation

## Requirements

- **Go** (build from source only — the prebuilt binaries published on every
  release have no runtime dependencies). The project's `go.mod` pins the
  toolchain.
- An **authorized** directory/domain for live assessments. None is needed to
  build, test, or run the offline demo (`shaka assess --sim`).

## Build

```sh
make build
```

This produces `bin/shaka`. Or manually:

```sh
go build -o bin/shaka ./cmd/shaka
```

## Install script

The zero-config installer detects your operating system, CPU architecture and
shell, downloads the matching prebuilt binary from GitHub Releases (verifying
its SHA-256 against the published `checksums.txt`), and falls back to building
from source when no release is available yet. By default it installs under
`~/.local` and adds the directory to your `PATH` (sudo is only used when
installing system-wide):

```sh
curl -fsSL https://raw.githubusercontent.com/QYVORA/qyvora-shaka/master/install.sh | bash
```

Or from a checkout:

```sh
./install.sh
```

On Linux the installer also installs the shaka app icon and a `.desktop`
entry so shaka appears with its logo in the application menu.

### Windows

```powershell
irm https://raw.githubusercontent.com/QYVORA/qyvora-shaka/master/install.ps1 | iex
```

Installs the checksum-verified binary under `%LOCALAPPDATA%\Programs\shaka\bin`,
adds it to your user PATH, installs the shaka icon, and creates a Start Menu
shortcut. Pin `$env:SHAKA_VERSION` or `$env:SHAKA_PREFIX` to control the
version or install location.

## Install into your environment

`shaka` ships with the tool's icon and a desktop entry. Installing it makes
the `shaka` command available, adds it to your application menu with the
logo, and is fully searchable — for example, typing `shaka` in the
application launcher shows the tool with its icon.

### System-wide (Linux/Unix, typically requires root)

```sh
sudo make install
```

This installs:

- `bin` (default `/usr/local/bin/shaka`) — the command
- `share/applications/shaka.desktop` — desktop entry
- `share/icons/hicolor/512x512/apps/` icon
- `share/pixmaps/` icon (pixmap lookup)

`PREFIX` and `DESTDIR` are honored for packaging and staging:

```sh
make install PREFIX=/usr
make install DESTDIR=/tmp/pkgroot
```

### Per-user (no root)

```sh
make install-user
```

Installs the same layout under `~/.local` (`bin`, `share/applications`,
`share/icons`, `share/pixmaps`). If `~/.local/bin` is not on your `PATH`, add
it:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

### After installing

```sh
which shaka
shaka version
```

The desktop entry is indexed by the launcher, so searching `shaka` in the
application menu shows the tool with its logo. Desktop and icon caches are
refreshed automatically when the cache tools are present.

## Updating

Once installed, update with:

```sh
shaka updates            # check; `shaka update` works as an alias
shaka updates --install  # download, verify, and install the latest
```

The command is also available inside the interactive console (`updates`).

What it does:

1. Reads the installed version — the same value `shaka version` reports.
2. Queries the official QYVORA GitHub releases
   (`github.com/QYVORA/qyvora-shaka/releases`); no other source is contacted.
3. Compares versions semantically and reports whether an update exists.
4. Downloads the artifact built for your OS and CPU architecture.
5. Verifies its SHA-256 against the `checksums.txt` manifest published with the
   release; installation never proceeds on a mismatch or when no verifiable
   checksum exists.
6. Swaps the new binary in atomically, preserving the original file
   permissions.
7. Cleans up temporary files and confirms the new version.

Notes:

- No Go toolchain, Git, or source checkout is required — official prebuilt
  binaries are the update channel.
- If the binary lives somewhere your user cannot write to, the updater stops
  with clear guidance instead of escalating on its own. Re-run with the
  appropriate permissions or use `make install-user`.
- Downgrades are refused: an installed version newer than the latest release
  is left alone.
- Offline or GitHub unreachable? The command fails cleanly; your installed
  binary stays exactly as it was.

## Verify

```sh
./bin/shaka version
./bin/shaka --help
```

`shaka version` prints `shaka <version>` with the framework, commit, built
date, build user, and Go version fields.

## Uninstall

Remove installed files (system or user):

```sh
sudo make uninstall      # removes the system-wide install
make uninstall-user      # removes the per-user install
make clean               # removes local bin/ build outputs
```

## Tooling

| Tool | Purpose |
|---|---|
| `go test ./...` | unit tests (no live directory required) |
| `make check` | `gofmt` + `go vet` + `go test` in one step |
| `make install` / `make install-user` | install with icon + desktop entry |