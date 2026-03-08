"""ssvc-calc CLI — SSVC decision lookup from the command line."""

from __future__ import annotations

import argparse
import json
import sys

from ssvc_calc.core import Decision, decide, decide_human_impact


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="ssvc-calc",
        description="SSVC Deployer decision lookup.",
    )
    parser.add_argument(
        "--exploitation", required=True,
        choices=["none", "poc", "active"],
        help="Exploitation status",
    )
    parser.add_argument(
        "--exposure", required=True,
        choices=["small", "controlled", "open"],
        help="System exposure level",
    )
    parser.add_argument(
        "--automatable", action="store_true", default=False,
        help="Whether the vulnerability is automatable",
    )
    parser.add_argument(
        "--human-impact",
        choices=["low", "medium", "high", "very_high"],
        help="Human impact level (直接指定する場合)",
    )
    parser.add_argument(
        "--safety-impact",
        choices=["negligible", "marginal", "critical", "catastrophic"],
        help="Safety impact (--mission-impact と組み合わせて human-impact を自動計算)",
    )
    parser.add_argument(
        "--mission-impact",
        choices=["degraded", "mef_support_crippled", "mef_failure", "mission_failure"],
        help="Mission impact (--safety-impact と組み合わせて human-impact を自動計算)",
    )
    parser.add_argument(
        "--output", default="text", choices=["text", "json"],
        help="Output format (default: text)",
    )

    args = parser.parse_args()

    # human-impact: 直接指定 or safety+mission から計算
    if args.human_impact:
        human_impact = args.human_impact
    elif args.safety_impact and args.mission_impact:
        human_impact = decide_human_impact(args.safety_impact, args.mission_impact)
    else:
        parser.error("--human-impact か、--safety-impact と --mission-impact の両方を指定してください")

    result = decide(
        exploitation=args.exploitation,
        exposure=args.exposure,
        automatable=args.automatable,
        human_impact=human_impact,
    )

    if args.output == "json":
        data = {
            "exploitation": args.exploitation,
            "exposure": args.exposure,
            "automatable": args.automatable,
            "human_impact": human_impact,
            "decision": str(result),
        }
        json.dump(data, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(result)


if __name__ == "__main__":
    main()
