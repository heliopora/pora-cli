"""pora CLI — human-friendly interface to the security audit market."""

import json
import sys

import click

from pora.client import PoraClient


def _client(**kwargs) -> PoraClient:
    return PoraClient(**{k: v for k, v in kwargs.items() if v})


@click.group()
@click.version_option()
def main():
    """pora — Security audit market. Audit. Earn. Forget."""
    pass


# ── Key management ──


@main.command()
@click.option("--output", "-o", default=".", help="Directory for keypair files")
def keygen(output):
    """Generate X25519 delivery keypair."""
    priv_path, pub_hex = PoraClient.generate_keypair(output)
    click.echo(f"Private key: {priv_path}")
    click.echo(f"Public key:  {pub_hex}")
    click.echo("⚠ Back up your private key. Lost keys = unrecoverable audit results.")


# ── Bounty commands ──


@main.group()
def bounty():
    """Manage bounties."""
    pass


@bounty.command("create")
@click.argument("repo")
@click.option("--amount", "-a", type=float, default=1.0, help="ROSE to deposit")
@click.option("--duration", "-d", type=int, default=7, help="Duration in days")
@click.option("--standing/--one-time", default=True, help="Repeating bounty")
@click.option("--installation-id", "-i", type=int, required=True, help="GitHub App installation ID")
@click.option("--trigger", "-t", default="on-change", help="Trigger mode: on-change, periodic, both")
@click.option("--period-days", type=int, default=0, help="Days between periodic audits")
@click.option("--tool-mode", type=int, default=1, help="1=static, 2=static+llm, 3=llm-full")
@click.option("--delivery-key", type=str, default="", help="Path to X25519 public key file for encrypted delivery")
@click.option("--private-key", envvar="PORA_PRIVATE_KEY", help="Wallet private key")
@click.option("--rpc", envvar="PORA_RPC_URL", default="", help="Sapphire RPC URL")
@click.option("--contract", envvar="PORA_CONTRACT", default="", help="LetheMarket address")
def bounty_create(repo, amount, duration, standing, installation_id, trigger, period_days, tool_mode, delivery_key, private_key, rpc, contract):
    """Create a bounty for REPO (owner/repo format).

    Example: pora bounty create lethe-protocol/lethe-market --amount 1 -i 122858796
    """
    client = _client(private_key=private_key, rpc_url=rpc, contract_address=contract)

    click.echo(f"Creating bounty for {repo}...")
    bounty_id = client.create_bounty(repo, amount_rose=amount, duration_days=duration, standing=standing)
    click.echo(f"Bounty #{bounty_id} created.")

    click.echo(f"Linking repo info...")
    client.set_repo_info(bounty_id, repo=repo, installation_id=installation_id)
    click.echo(f"Repo linked.")

    click.echo(f"Setting audit config ({trigger})...")
    client.set_audit_config(bounty_id, trigger=trigger, period_days=period_days, tool_mode=tool_mode)
    click.echo(f"Config set.")

    if delivery_key:
        import os
        if os.path.isfile(delivery_key):
            pub_hex = open(delivery_key).read().strip()
        else:
            pub_hex = delivery_key
        client.set_delivery_key(bounty_id, pub_key_hex=pub_hex)
        click.echo("Delivery key registered.")

    click.echo(f"\n✓ Bounty #{bounty_id} is live. ROFL worker will pick it up on next poll cycle.")


@bounty.command("list")
@click.option("--all", "show_all", is_flag=True, help="Include closed/cancelled bounties")
@click.option("--rpc", envvar="PORA_RPC_URL", default="", help="Sapphire RPC URL")
@click.option("--contract", envvar="PORA_CONTRACT", default="", help="LetheMarket address")
def bounty_list(show_all, rpc, contract):
    """List bounties on the market."""
    client = _client(rpc_url=rpc, contract_address=contract)
    bounties = client.list_bounties(only_open=not show_all)

    if not bounties:
        click.echo("No bounties found.")
        return

    states = {0: "Open", 1: "Completed", 2: "Cancelled"}
    for b in bounties:
        rose = client.w3.from_wei(b.amount, "ether")
        standing = "standing" if b.standing else "one-time"
        click.echo(f"  #{b.id}  {states.get(b.state, '?')}  {rose} ROSE  {standing}  audits={b.audit_count}")


@bounty.command("fund")
@click.argument("bounty_id", type=int)
@click.option("--amount", "-a", type=float, required=True, help="ROSE to add")
@click.option("--private-key", envvar="PORA_PRIVATE_KEY")
@click.option("--rpc", envvar="PORA_RPC_URL", default="")
@click.option("--contract", envvar="PORA_CONTRACT", default="")
def bounty_fund(bounty_id, amount, private_key, rpc, contract):
    """Top up a standing bounty."""
    client = _client(private_key=private_key, rpc_url=rpc, contract_address=contract)
    tx = client.fund_bounty(bounty_id, amount_rose=amount)
    click.echo(f"Funded bounty #{bounty_id} with {amount} ROSE. tx={tx}")


@bounty.command("cancel")
@click.argument("bounty_id", type=int)
@click.option("--private-key", envvar="PORA_PRIVATE_KEY")
@click.option("--rpc", envvar="PORA_RPC_URL", default="")
@click.option("--contract", envvar="PORA_CONTRACT", default="")
def bounty_cancel(bounty_id, private_key, rpc, contract):
    """Cancel a bounty and reclaim funds."""
    client = _client(private_key=private_key, rpc_url=rpc, contract_address=contract)
    tx = client.cancel_bounty(bounty_id)
    click.echo(f"Cancelled bounty #{bounty_id}. tx={tx}")


@bounty.command("watch")
@click.argument("bounty_id", type=int)
@click.option("--interval", "-i", type=int, default=30, help="Poll interval in seconds")
@click.option("--rpc", envvar="PORA_RPC_URL", default="")
@click.option("--contract", envvar="PORA_CONTRACT", default="")
def bounty_watch(bounty_id, interval, rpc, contract):
    """Watch a bounty for audit completion."""
    import time
    client = _client(rpc_url=rpc, contract_address=contract)

    last_audit_count = client.get_bounty(bounty_id).audit_count
    click.echo(f"Watching bounty #{bounty_id} (current audits: {last_audit_count})...")

    while True:
        time.sleep(interval)
        try:
            b = client.get_bounty(bounty_id)
            if b.audit_count > last_audit_count:
                # New audit completed
                audit_id = client.audit_count()  # latest audit
                a = client.get_audit(audit_id)
                result = "Findings" if a.result == 0 else "NoFindings"
                payout = client.w3.from_wei(a.payout, 'ether')
                click.echo(f"\n  Audit #{audit_id} complete!")
                click.echo(f"  Result: {result} ({a.finding_count} findings)")
                click.echo(f"  Payout: {payout} ROSE")
                last_audit_count = b.audit_count

                # Check if delivery is ready
                d = client.get_delivery(audit_id)
                if d.delivery_status == 1:
                    click.echo(f"  Delivery: Ready")
                    click.echo(f"  Retrieve: pora audit retrieve {audit_id} --key <your-key>")
                break
            else:
                click.echo(".", nl=False)
        except Exception as e:
            click.echo(f"\n  Error: {e}")


# ── Performer commands ──


@main.group()
def performer():
    """Manage performer agent configuration."""
    pass


@performer.command("estimate")
@click.option("--provider", default="anthropic", help="LLM provider")
@click.option("--model", default="", help="Model name")
@click.option("--rpc", envvar="PORA_RPC_URL", default="")
@click.option("--contract", envvar="PORA_CONTRACT", default="")
def performer_estimate(provider, model, rpc, contract):
    """Estimate costs and potential earnings for performing audits."""
    client = _client(rpc_url=rpc, contract_address=contract)
    bounties = client.list_bounties(only_open=True)

    if not bounties:
        click.echo("No open bounties. Nothing to estimate.")
        return

    # Rough API cost estimates per provider
    cost_per_audit = {"anthropic": 0.15, "openai": 0.10, "openrouter": 0.08}
    api_cost = cost_per_audit.get(provider, 0.15)

    click.echo(f"Open bounties: {len(bounties)}")
    click.echo(f"Provider: {provider} (est. ${api_cost:.2f}/audit)")
    click.echo()
    for b in bounties:
        pool = client.w3.from_wei(b.amount, 'ether')
        policy = client.payout_policy()
        per_audit = float(pool) * policy.standing_percent_bps / 10000
        base_fee = per_audit * policy.execution_fee_bps / 10000
        click.echo(f"  Bounty #{b.id}: {pool} ROSE pool")
        click.echo(f"    Per audit: {per_audit:.4f} ROSE total, {base_fee:.4f} ROSE base fee")
        click.echo(f"    API cost: ~${api_cost:.2f} -> {'profitable' if float(base_fee) * 0.08 > api_cost else 'need findings for profit'}")


# ── Delivery commands ──


@main.group()
def delivery():
    """Encrypted delivery management."""
    pass


@delivery.command("setup")
@click.argument("bounty_id", type=int)
@click.option("--key", "-k", required=True, help="Path to public key file or hex string")
@click.option("--private-key", envvar="PORA_PRIVATE_KEY")
@click.option("--rpc", envvar="PORA_RPC_URL", default="")
@click.option("--contract", envvar="PORA_CONTRACT", default="")
def delivery_setup(bounty_id, key, private_key, rpc, contract):
    """Register encryption key for a bounty."""
    client = _client(private_key=private_key, rpc_url=rpc, contract_address=contract)

    import os
    if os.path.isfile(key):
        pub_hex = open(key).read().strip()
    else:
        pub_hex = key

    tx = client.set_delivery_key(bounty_id, pub_key_hex=pub_hex)
    click.echo(f"Delivery key set for bounty #{bounty_id}. tx={tx}")


# ── Audit commands ──


@main.group()
def audit():
    """View and manage audits."""
    pass


@audit.command("list")
@click.option("--bounty-id", "-b", type=int, help="Filter by bounty ID")
@click.option("--rpc", envvar="PORA_RPC_URL", default="")
@click.option("--contract", envvar="PORA_CONTRACT", default="")
def audit_list(bounty_id, rpc, contract):
    """List audits."""
    client = _client(rpc_url=rpc, contract_address=contract)
    count = client.audit_count()

    if count == 0:
        click.echo("No audits found.")
        return

    results = {0: "Findings", 1: "NoFindings"}
    states = {0: "Pending", 1: "Verified", 2: "Disputed"}

    for i in range(1, count + 1):
        a = client.get_audit(i)
        if bounty_id and a.bounty_id != bounty_id:
            continue
        rose = client.w3.from_wei(a.payout, "ether")
        click.echo(
            f"  #{a.id}  bounty={a.bounty_id}  {states.get(a.state, '?')}  "
            f"{results.get(a.result, '?')}  findings={a.finding_count}  payout={rose} ROSE"
        )


@audit.command("show")
@click.argument("audit_id", type=int)
@click.option("--rpc", envvar="PORA_RPC_URL", default="")
@click.option("--contract", envvar="PORA_CONTRACT", default="")
def audit_show(audit_id, rpc, contract):
    """Show detailed audit info."""
    client = _client(rpc_url=rpc, contract_address=contract)
    a = client.get_audit(audit_id)
    d = client.get_delivery(audit_id)
    s = client.get_settlement(audit_id)

    click.echo(f"Audit #{audit_id}")
    click.echo(f"  Bounty:    #{a.bounty_id}")
    click.echo(f"  Result:    {'Findings' if a.result == 0 else 'NoFindings'} ({a.finding_count} findings)")
    click.echo(f"  Payout:    {client.w3.from_wei(a.payout, 'ether')} ROSE")
    click.echo(f"  State:     {['Pending', 'Verified', 'Disputed'][a.state]}")
    click.echo(f"  Commit:    0x{a.commit_hash[:20].hex()}")
    click.echo(f"  PoE:       0x{a.poe_hash.hex()[:16]}...")
    click.echo(f"  Delivery:  {'Ready' if d.delivery_status == 1 else 'None'}")

    click.echo(f"  Settlement:")
    click.echo(f"    Performer:   {s['performer']}")
    click.echo(f"    Exec fee:    {client.w3.from_wei(s['execution_fee'], 'ether')} ROSE")
    click.echo(f"    Finding:     {client.w3.from_wei(s['finding_bonus'], 'ether')} ROSE")
    click.echo(f"    Patch:       {client.w3.from_wei(s['patch_bonus'], 'ether')} ROSE")
    click.echo(f"    Regression:  {client.w3.from_wei(s['regression_bonus'], 'ether')} ROSE")
    click.echo(f"    Claimed:     {client.w3.from_wei(s['claimed_amount'], 'ether')} ROSE")


@audit.command("retrieve")
@click.argument("audit_id", type=int)
@click.option("--key", "-k", required=True, help="Path to X25519 private key")
@click.option("--handle", "-h", default="", help="Delivery handle (e.g., pkt-2-abc123)")
@click.option("--output", "-o", default="", help="Write report to file instead of stdout")
@click.option("--auth-token", envvar="PORA_GATEWAY_TOKEN", default="", help="Gateway auth token")
@click.option("--rpc", envvar="PORA_RPC_URL", default="")
@click.option("--contract", envvar="PORA_CONTRACT", default="")
@click.option("--gateway", envvar="PORA_GATEWAY_URL", default="")
def audit_retrieve(audit_id, key, handle, output, auth_token, rpc, contract, gateway):
    """Download and decrypt an encrypted audit report.

    AUDIT_ID is the on-chain audit identifier.

    Example:
        pora audit retrieve 7 --key pora-delivery.key --handle pkt-2-1c5df70af11c
    """
    client = _client(rpc_url=rpc, contract_address=contract, gateway_url=gateway)

    try:
        packet = client.retrieve_audit(
            audit_id,
            private_key_path=key,
            handle=handle,
            auth_token=auth_token,
        )
    except RuntimeError as exc:
        click.echo(f"Error: {exc}", err=True)
        raise SystemExit(1)

    report_md = packet.get("reportMarkdown", "")
    finding_count = packet.get("findingCount", 0)
    result_type = packet.get("resultType", "unknown")

    if output:
        with open(output, "w") as f:
            f.write(report_md)
        click.echo(f"Report written to {output}")
        click.echo(f"Result: {result_type}  Findings: {finding_count}")
    else:
        click.echo(report_md)


# ── Market overview ──


@main.command()
@click.option("--rpc", envvar="PORA_RPC_URL", default="")
@click.option("--contract", envvar="PORA_CONTRACT", default="")
def status(rpc, contract):
    """Show market status."""
    client = _client(rpc_url=rpc, contract_address=contract)
    bc = client.bounty_count()
    ac = client.audit_count()
    pp = client.payout_policy()

    click.echo(f"pora market status")
    click.echo(f"  Contract:  {client.contract_address}")
    click.echo(f"  Network:   {client.rpc_url}")
    click.echo(f"  Bounties:  {bc}")
    click.echo(f"  Audits:    {ac}")
    click.echo(f"  Policy:    {pp.execution_fee_bps//100}% exec / {pp.finding_bonus_bps//100}% finding / {pp.patch_bonus_bps//100}% patch / {pp.regression_bonus_bps//100}% regression")
    click.echo(f"  Standing:  {pp.standing_percent_bps//100}% per audit, min {client.w3.from_wei(pp.minimum_payout, 'ether')} ROSE")


# ── MCP server ──


@main.command()
@click.option("--port", "-p", type=int, default=8900, help="Server port")
@click.option("--host", default="127.0.0.1", help="Bind address (use 0.0.0.0 for remote access)")
@click.option("--private-key", envvar="PORA_PRIVATE_KEY", default="", help="Wallet private key")
@click.option("--rpc", envvar="PORA_RPC_URL", default="", help="Sapphire RPC URL")
@click.option("--contract", envvar="PORA_CONTRACT", default="", help="LetheMarket contract address")
@click.option("--gateway", envvar="PORA_GATEWAY_URL", default="", help="Delivery gateway URL")
def mcp(port, host, private_key, rpc, contract, gateway):
    """Start the pora MCP server for AI agent integration.

    Exposes pora market tools as HTTP endpoints on localhost.
    Agents can call GET /tools to discover available tools,
    then POST /tools/<name> with a JSON body to invoke them.

    Example:
        pora mcp --port 8900
        curl http://localhost:8900/tools
        curl -X POST http://localhost:8900/tools/market_status
    """
    from pora.mcp_server import start_server

    start_server(
        host=host,
        port=port,
        private_key=private_key,
        rpc_url=rpc,
        contract_address=contract,
        gateway_url=gateway,
    )


if __name__ == "__main__":
    main()
