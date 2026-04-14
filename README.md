# pora

**Security audit market CLI, SDK, and MCP server.**

*The passage where code enters, findings emerge, and vulnerability knowledge is destroyed.*

> Audit. Earn. Forget.

## Install

```bash
cargo install --git https://github.com/heliopora/pora-cli
```

Or build from source:

```bash
git clone https://github.com/heliopora/pora-cli
cd pora-cli
cargo build --release
```

## Quick Start

### As a requester (get your code audited)

```bash
# Submit a bounty (creates bounty + configures repo + sets up delivery)
pora request submit owner/repo --amount 1.0

# List open bounties
pora request list

# Top up a standing bounty
pora request topup 1 --amount 0.5

# Cancel and reclaim funds
pora request cancel 1
```

### As a performer (earn by auditing)

```bash
# Initialize performer config
pora performer init --provider anthropic

# Request a claim on a bounty
pora performer claim-payout 1

# Monitor on-chain events
pora performer start

# Check earnings and reputation
pora performer status
```

### System utilities

```bash
# Check config, connectivity, wallet balance
pora system doctor

# Show wallet address, network, balance
pora system whoami

# Generate X25519 delivery keypair
pora system keygen
```

### As an MCP server (AI agent integration)

```bash
# Start the MCP server (stdio transport)
pora mcp
```

Exposes all CLI commands as MCP tools (`pora_request_submit`, `pora_performer_status`, etc.) for use by AI agents via the Model Context Protocol.

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORA_PRIVATE_KEY` | -- | Wallet private key for transactions |
| `PORA_RPC_URL` | `https://testnet.sapphire.oasis.io` | Sapphire RPC endpoint |
| `PORA_CONTRACT` | testnet deployment | LetheMarket contract address |
| `PORA_GATEWAY_URL` | testnet gateway | Delivery gateway URL |
| `PORA_ROFL_APP_ID` | dev default | ROFL app ID for config hash |
| `PORA_MODEL` | `default` | LLM model for config hash |
| `PORA_IMAGE_HASH` | `dev` | TEE image hash for config hash |

Config files are stored in `~/.pora/`.

## Architecture

```
src/
├── main.rs           -- CLI entrypoint (clap)
├── commands/
│   ├── request.rs    -- Requester commands (submit, cancel, topup, list)
│   ├── performer.rs  -- Performer commands (init, start, status, claim)
│   └── system.rs     -- System utilities (doctor, whoami, keygen)
├── mcp/
│   ├── mod.rs        -- MCP server (stdio transport)
│   ├── tools.rs      -- Tool definitions and dispatch
│   └── resources.rs  -- Resource definitions
├── abi.rs            -- ABI encoding/decoding
├── config.rs         -- Config loading (~/.pora/)
├── contract.rs       -- On-chain read helpers
├── crypto.rs         -- X25519, secp256k1 key management
├── github.rs         -- GitHub API (visibility detection)
├── output.rs         -- Structured output (JSON/text, TTY-aware)
├── rpc.rs            -- Sapphire JSON-RPC client
└── tx.rs             -- Transaction building and signing
```

## Output Format

pora auto-detects TTY and switches between human-readable text and machine-parseable JSON:

```bash
# TTY: human-readable
pora system whoami

# Pipe/redirect: JSON
pora request list | jq '.bounties'

# Force format
pora --format json system doctor
```

## Mascot

**Heliopora** -- the blue coral. The only octocoral that builds a massive calcium carbonate skeleton. Unique, beautiful, resilient. Like pora: a structure where life happens inside, protected from the outside world.

## Links

- [pora-market](https://github.com/heliopora/pora-market) -- Protocol contracts + ROFL TEE worker
- [heliopora.github.io](https://heliopora.github.io) -- Landing page

## License

MIT
