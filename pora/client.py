"""pora SDK — core market interaction logic.

All CLI and MCP tool calls resolve to methods on PoraClient.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from web3 import Web3
from Crypto.Hash import keccak

_ABI_PATH = Path(__file__).parent / "abi.json"
_ABI = json.loads(_ABI_PATH.read_text())

# Default deployments (Sapphire testnet)
DEFAULT_RPC = "https://testnet.sapphire.oasis.io"
DEFAULT_CONTRACT = "0x2B057b903850858A00aCeFFdE12bdb604e781573"
DEFAULT_GATEWAY = "https://lethe-market.onrender.com/delivery"


def _keccak256(data: bytes) -> bytes:
    return keccak.new(data=data, digest_bits=256).digest()


def repo_hash(owner: str, repo: str) -> bytes:
    """Compute the on-chain repo identifier.

    returns: keccak256("github:" + owner + "/" + repo) as 32 bytes
    """
    return _keccak256(f"github:{owner}/{repo}".encode())


@dataclass(frozen=True)
class Bounty:
    id: int
    requester: str
    amount: int
    repo_hash: bytes
    created_at: int
    deadline: int
    standing: bool
    state: int  # 0=Open, 1=Completed, 2=Cancelled
    audit_count: int


@dataclass(frozen=True)
class Audit:
    id: int
    bounty_id: int
    commit_hash: bytes
    poe_hash: bytes
    payout: int
    completed_at: int
    state: int  # 0=Pending, 1=Verified, 2=Disputed
    result: int  # 0=FindingsFound, 1=NoFindings
    finding_count: int


@dataclass(frozen=True)
class DeliveryInfo:
    ciphertext_hash: bytes
    manifest_hash: bytes
    delivery_mode: int
    delivery_status: int  # 0=None, 1=Ready, 2=Retrieved, 3=Failed


@dataclass(frozen=True)
class PayoutPolicy:
    standing_percent_bps: int
    minimum_payout: int
    execution_fee_bps: int
    finding_bonus_bps: int
    patch_bonus_bps: int
    regression_bonus_bps: int


class PoraClient:
    """Main SDK client for interacting with the pora security audit market.

    Usage:
        from pora import PoraClient
        client = PoraClient(private_key="0x...")
        client.create_bounty("owner/repo", amount_rose=1.0, standing=True)
    """

    def __init__(
        self,
        *,
        rpc_url: str = "",
        contract_address: str = "",
        gateway_url: str = "",
        private_key: str = "",
    ):
        self.rpc_url = rpc_url or os.environ.get("PORA_RPC_URL", DEFAULT_RPC)
        self.contract_address = contract_address or os.environ.get(
            "PORA_CONTRACT", DEFAULT_CONTRACT
        )
        self.gateway_url = gateway_url or os.environ.get(
            "PORA_GATEWAY_URL", DEFAULT_GATEWAY
        )
        self._private_key = private_key or os.environ.get("PORA_PRIVATE_KEY", "")

        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        self.contract = self.w3.eth.contract(
            address=Web3.to_checksum_address(self.contract_address), abi=_ABI
        )
        self._account = None
        if self._private_key:
            self._account = self.w3.eth.account.from_key(self._private_key)

    @property
    def address(self) -> str:
        if not self._account:
            raise ValueError("No private key configured. Set PORA_PRIVATE_KEY or pass private_key=")
        return self._account.address

    def _send_tx(self, fn, value: int = 0) -> str:
        """Build, sign, and send a contract transaction.

        returns: transaction hash hex string
        """
        if not self._account:
            raise ValueError("No private key configured")
        tx = fn.build_transaction({
            "from": self.address,
            "value": value,
            "nonce": self.w3.eth.get_transaction_count(self.address),
            "gas": 500_000,
            "gasPrice": self.w3.eth.gas_price,
            "chainId": self.w3.eth.chain_id,
        })
        signed = self._account.sign_transaction(tx)
        tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        if receipt["status"] != 1:
            raise RuntimeError(f"Transaction reverted: {tx_hash.hex()}")
        return tx_hash.hex()

    # ── Market stats ──

    def bounty_count(self) -> int:
        return self.contract.functions.bountyCount().call()

    def audit_count(self) -> int:
        return self.contract.functions.auditCount().call()

    def payout_policy(self) -> PayoutPolicy:
        p = self.contract.functions.payoutPolicy().call()
        return PayoutPolicy(
            standing_percent_bps=p[0],
            minimum_payout=p[1],
            execution_fee_bps=p[2],
            finding_bonus_bps=p[3],
            patch_bonus_bps=p[4],
            regression_bonus_bps=p[5],
        )

    # ── Requester operations ──

    def create_bounty(
        self,
        repo: str,
        *,
        amount_rose: float = 1.0,
        duration_days: int = 7,
        standing: bool = True,
    ) -> int:
        """Create a standing bounty for a GitHub repo.

        Args:
            repo: "owner/repo" format
            amount_rose: ROSE to deposit
            duration_days: bounty duration
            standing: if True, bounty repeats until cancelled

        returns: bounty ID
        """
        owner, name = repo.split("/", 1)
        rh = repo_hash(owner, name)
        value = self.w3.to_wei(amount_rose, "ether")
        duration = duration_days * 86400

        fn = self.contract.functions.createBounty(rh, duration, standing)
        self._send_tx(fn, value=value)

        # Return the new bounty ID (bountyCount after creation)
        return self.bounty_count()

    def set_repo_info(
        self, bounty_id: int, *, repo: str, installation_id: int
    ) -> str:
        """Link a GitHub repo to a bounty.

        returns: transaction hash
        """
        owner, name = repo.split("/", 1)
        fn = self.contract.functions.setRepoInfo(bounty_id, owner, name, installation_id)
        return self._send_tx(fn)

    def set_audit_config(
        self,
        bounty_id: int,
        *,
        trigger: str = "on-change",
        period_days: int = 0,
        tool_mode: int = 1,
    ) -> str:
        """Configure audit triggers.

        Args:
            trigger: "on-change", "periodic", or "both"
            period_days: days between periodic audits (required if trigger includes periodic)
            tool_mode: 1=static, 2=static+llm, 3=llm-full

        returns: transaction hash
        """
        mode = 0
        if "change" in trigger:
            mode |= 0x01
        if "periodic" in trigger:
            mode |= 0x08
        if mode == 0:
            mode = 0x01  # default: on-change

        fn = self.contract.functions.setAuditConfig(bounty_id, mode, 1, tool_mode, period_days)
        return self._send_tx(fn)

    def set_delivery_key(self, bounty_id: int, *, pub_key_hex: str) -> str:
        """Register X25519 public key for encrypted delivery.

        Args:
            pub_key_hex: 32-byte X25519 public key as hex string

        returns: transaction hash
        """
        pub_bytes = bytes.fromhex(pub_key_hex.replace("0x", ""))
        assert len(pub_bytes) == 32, "X25519 public key must be 32 bytes"
        fn = self.contract.functions.setDeliveryConfig(
            bounty_id,
            pub_bytes,
            b"\x00" * 32,  # notification policy hash (unused for now)
            1,  # DeliveryMode.RequesterOnly
        )
        return self._send_tx(fn)

    def fund_bounty(self, bounty_id: int, *, amount_rose: float) -> str:
        """Top up a standing bounty.

        returns: transaction hash
        """
        value = self.w3.to_wei(amount_rose, "ether")
        fn = self.contract.functions.topUpBounty(bounty_id)
        return self._send_tx(fn, value=value)

    def cancel_bounty(self, bounty_id: int) -> str:
        """Cancel a bounty and reclaim remaining funds.

        returns: transaction hash
        """
        fn = self.contract.functions.cancelBounty(bounty_id)
        return self._send_tx(fn)

    def dispute_audit(self, audit_id: int) -> str:
        """Dispute an audit result (requester only, within challenge window).

        returns: transaction hash
        """
        fn = self.contract.functions.disputeAudit(audit_id, b"\x00" * 32)
        return self._send_tx(fn)

    # ── Read operations ──

    def get_bounty(self, bounty_id: int) -> Bounty:
        b = self.contract.functions.getBounty(bounty_id).call()
        return Bounty(
            id=bounty_id,
            requester=b[0],
            amount=b[1],
            repo_hash=b[2],
            created_at=b[3],
            deadline=b[4],
            standing=b[5],
            state=b[6],
            audit_count=b[7],
        )

    def get_audit(self, audit_id: int) -> Audit:
        a = self.contract.functions.getAudit(audit_id).call()
        return Audit(
            id=audit_id,
            bounty_id=a[0],
            commit_hash=a[1],
            poe_hash=a[2],
            payout=a[3],
            completed_at=a[4],
            state=a[5],
            result=a[6],
            finding_count=a[7],
        )

    def get_delivery(self, audit_id: int) -> DeliveryInfo:
        d = self.contract.functions.getAuditDelivery(audit_id).call()
        return DeliveryInfo(
            ciphertext_hash=d[0],
            manifest_hash=d[1],
            delivery_mode=d[2],
            delivery_status=d[3],
        )

    def list_bounties(self, *, only_open: bool = True) -> list[Bounty]:
        """List all bounties, optionally filtered to open ones."""
        count = self.bounty_count()
        bounties = []
        for i in range(1, count + 1):
            b = self.get_bounty(i)
            if only_open and b.state != 0:
                continue
            bounties.append(b)
        return bounties

    # ── Performer operations ──

    def claim_payout(self, audit_id: int) -> str:
        """Claim unlocked bonus payout after challenge window.

        returns: transaction hash
        """
        fn = self.contract.functions.claimAuditPayout(audit_id)
        return self._send_tx(fn)

    def get_settlement(self, audit_id: int) -> dict:
        """Get settlement details for an audit."""
        s = self.contract.functions.getAuditSettlement(audit_id).call()
        return {
            "performer": s[0],
            "execution_fee": s[1],
            "finding_bonus": s[2],
            "patch_bonus": s[3],
            "regression_bonus": s[4],
            "claimed_amount": s[5],
            "locked_until": s[6],
            "dispute_status": s[7],
        }

    # ── Encrypted delivery ──

    def retrieve_audit(
        self, audit_id: int, *, private_key_path: str, handle: str = "", auth_token: str = ""
    ) -> dict:
        """Download, verify, and decrypt an encrypted audit report.

        # checks: audit exists, delivery status is Ready (1), private key is valid
        # effects: downloads ciphertext from gateway, verifies on-chain hashes, decrypts
        # returns: decrypted report dict with reportMarkdown, findingCount, resultType
        #
        # WHY: requesters need a single call to go from audit ID to readable report
        # SECURITY: private key never leaves this process. Decryption is local.
        # TRUST: on-chain delivery hashes are the integrity anchor; gateway is semi-trusted
        """
        from pora.crypto import download_and_decrypt, load_private_key

        delivery = self.get_delivery(audit_id)
        if delivery.delivery_status != 1:
            status_names = {0: "None", 1: "Ready", 2: "Retrieved", 3: "Failed"}
            raise RuntimeError(
                f"Delivery not ready for audit #{audit_id}: "
                f"status={status_names.get(delivery.delivery_status, delivery.delivery_status)}"
            )

        resolved_handle = handle
        if not resolved_handle:
            audit = self.get_audit(audit_id)
            raise RuntimeError(
                f"--handle is required (the gateway does not support listing). "
                f"Look for pkt-{audit.bounty_id}-<random> in the delivery notification."
            )

        private_key = load_private_key(private_key_path)
        return download_and_decrypt(
            resolved_handle,
            self.gateway_url,
            private_key,
            auth_token=auth_token,
        )

    # ── Key management ──

    @staticmethod
    def generate_keypair(output_dir: str = ".") -> tuple[str, str]:
        """Generate X25519 delivery keypair.

        returns: (private_key_path, public_key_hex)
        """
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )

        private_key = X25519PrivateKey.generate()
        pub_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        priv_bytes = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

        priv_path = os.path.join(output_dir, "pora-delivery.key")
        with open(priv_path, "w") as f:
            f.write(priv_bytes.hex())
        os.chmod(priv_path, 0o600)

        pub_hex = pub_bytes.hex()
        pub_path = os.path.join(output_dir, "pora-delivery.pub")
        with open(pub_path, "w") as f:
            f.write(pub_hex)

        return priv_path, pub_hex
