# CLI Reference

`shaka` follows the shared QYVORA tier grammar:

```
shaka <tier> <module> [<action>] [target] [flags]
```

`<tier>` is one of `recon`, `exploit`, or `report`. Every pre-tier command remains available as a hidden alias.

## recon

| Command | Purpose |
|---------|---------|
| `shaka recon analyze` | Run the rule engine and risk assessment over the latest session |
| `shaka recon assess` | Run the full assessment pipeline (discover→enumerate→graph→analyze→findings→risk) |
| `shaka recon capabilities` | List shaka's machine-readable capabilities |
| `shaka recon completion` | Generate shell completion script |
| `shaka recon discover` | Discover domains and domain controllers |
| `shaka recon enumerate` | Enumerate directory objects |
| `shaka recon evidence` | List evidence collected in the latest session |
| `shaka recon findings` | List findings from the latest session |
| `shaka recon graph` | Render the relationship graph from the latest session |
| `shaka recon help` | Help about any command |
| `shaka recon report` | Render an assessment report from the latest session |
| `shaka recon target` | Manage assessment targets |
| `shaka recon tools` | List shaka's AI-ready tool capabilities |
| `shaka recon tui` | start the interactive terminal application |
| `shaka recon updates` | Check for and install shaka updates |
| `shaka recon version` | Print shaka version and build information |

## exploit

| Command | Purpose |
|---------|---------|
| `shaka exploit analyze` | Run the rule engine and risk assessment over the latest session |
| `shaka exploit assess` | Run the full assessment pipeline (discover→enumerate→graph→analyze→findings→risk) |
| `shaka exploit capabilities` | List shaka's machine-readable capabilities |
| `shaka exploit completion` | Generate shell completion script |
| `shaka exploit discover` | Discover domains and domain controllers |
| `shaka exploit enumerate` | Enumerate directory objects |
| `shaka exploit evidence` | List evidence collected in the latest session |
| `shaka exploit findings` | List findings from the latest session |
| `shaka exploit graph` | Render the relationship graph from the latest session |
| `shaka exploit help` | Help about any command |
| `shaka exploit report` | Render an assessment report from the latest session |
| `shaka exploit target` | Manage assessment targets |
| `shaka exploit tools` | List shaka's AI-ready tool capabilities |
| `shaka exploit tui` | start the interactive terminal application |
| `shaka exploit updates` | Check for and install shaka updates |
| `shaka exploit version` | Print shaka version and build information |

## report

_No report-tier modules._

## Utilities

| Command | Purpose |
|---------|---------|
| `shaka analyze` | Run the rule engine and risk assessment over the latest session |
| `shaka assess` | Run the full assessment pipeline (discover→enumerate→graph→analyze→findings→risk) |
| `shaka discover` | Discover domains and domain controllers |
| `shaka enumerate` | Enumerate directory objects |
| `shaka evidence` | List evidence collected in the latest session |
| `shaka findings` | List findings from the latest session |
| `shaka graph` | Render the relationship graph from the latest session |
| `shaka target` | Manage assessment targets |
| `shaka tools` | List shaka's AI-ready tool capabilities |
| `shaka tui` | start the interactive terminal application |
| `docs script <file>` | Run a `.qs` script with the shared scripting engine (`run`/`build` subcommands) |
