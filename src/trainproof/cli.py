"""Command-line interface for producing and checking training certificates."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from .bundle import BundleError, build_demo_bundle
from .verify import audit_bundle, verify_bundle
from .zk import verify_zk_demo


def _print(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trainproof",
        description="Build and verify proof-carrying training checkpoints.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    demo = subcommands.add_parser(
        "demo",
        help="create a complete signed distributed-training demo bundle",
    )
    demo.add_argument("--output", default="demo-run", help="new output directory")
    demo.add_argument("--steps", type=int, default=4)
    demo.add_argument("--workers", type=int, default=2)
    demo.add_argument(
        "--source-root",
        default=".",
        help="source repository to commit into the run manifest (default: current directory)",
    )

    verify = subcommands.add_parser(
        "verify",
        help="verify public artifacts plus the canonical checkpoint object",
    )
    verify.add_argument("run_dir")
    verify.add_argument(
        "--source",
        help="also compare the source artifact tree to this directory",
    )
    verify.add_argument(
        "--trust-policy",
        help="pin expected participant key IDs from a verifier-controlled JSON policy",
    )

    audit = subcommands.add_parser(
        "audit",
        help="open private data and check that every committed transition is satisfiable",
    )
    audit.add_argument("run_dir")
    audit.add_argument(
        "--source",
        help="also bind the replay report to this exact source tree and Git state",
    )
    audit.add_argument(
        "--trust-policy",
        help="pin expected participant key IDs from a verifier-controlled JSON policy",
    )

    zk_verify = subcommands.add_parser(
        "zk-verify",
        help="verify the concrete PLONK demo and its signed SHA-256 envelope",
    )
    zk_verify.add_argument("run_dir")
    zk_verify.add_argument(
        "--toolchain-root",
        default=".",
        help="repository containing pinned zk/, tools/, package-lock.json and node_modules",
    )
    zk_verify.add_argument(
        "--trust-policy",
        help="pin expected participant key IDs from a verifier-controlled JSON policy",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "demo":
        try:
            result = build_demo_bundle(
                args.output,
                args.source_root,
                steps=args.steps,
                workers=args.workers,
            )
        except (BundleError, OSError, ValueError) as exc:
            _print({"created": False, "error": str(exc)})
            return 2
        public_report = verify_bundle(args.output)
        audit_report = audit_bundle(args.output, source_root=args.source_root)
        result["public_verification"] = public_report
        result["private_audit"] = audit_report
        _print(result)
        return 0 if public_report["valid"] and audit_report["valid"] else 1
    if args.command == "verify":
        report = verify_bundle(
            args.run_dir,
            source_root=args.source,
            trust_policy=args.trust_policy,
        )
        _print(report)
        return 0 if report["valid"] else 1
    if args.command == "audit":
        report = audit_bundle(
            args.run_dir,
            source_root=args.source,
            trust_policy=args.trust_policy,
        )
        _print(report)
        return 0 if report["valid"] else 1
    if args.command == "zk-verify":
        report = verify_zk_demo(
            args.run_dir,
            args.toolchain_root,
            trust_policy=args.trust_policy,
        )
        _print(report)
        return 0 if report["valid"] else 1
    raise AssertionError("argparse accepted an unknown command")


if __name__ == "__main__":
    sys.exit(main())
