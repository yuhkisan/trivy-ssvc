from __future__ import annotations

import argparse
import sys

from trivy_ssvc import trivy, ssvc, state, output, notify


VALID_EXPOSURE = {"open", "controlled", "small"}
VALID_SAFETY = {"negligible", "marginal", "critical", "catastrophic"}
VALID_MISSION = {"minimal", "degraded", "failed"}
VALID_THRESHOLD = {"Defer", "Scheduled", "Out-of-cycle", "Immediate"}
VALID_OUTPUT = {"table", "json"}


def _validate(args: argparse.Namespace) -> None:
    errors = []
    if args.system_exposure not in VALID_EXPOSURE:
        errors.append(f"--system-exposure must be one of {sorted(VALID_EXPOSURE)}")
    if args.safety_impact not in VALID_SAFETY:
        errors.append(f"--safety-impact must be one of {sorted(VALID_SAFETY)}")
    if args.mission_impact not in VALID_MISSION:
        errors.append(f"--mission-impact must be one of {sorted(VALID_MISSION)}")
    if args.threshold not in VALID_THRESHOLD:
        errors.append(f"--threshold must be one of {sorted(VALID_THRESHOLD)}")
    if args.output not in VALID_OUTPUT:
        errors.append(f"--output must be one of {sorted(VALID_OUTPUT)}")
    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="trivy-ssvc",
        description="Apply SSVC prioritization to Trivy vulnerability scan results.",
    )
    parser.add_argument("--vulns", required=True, help="Path to trivy JSON output (trivy fs ./ --format json)")
    parser.add_argument("--system-exposure", required=True, choices=sorted(VALID_EXPOSURE),
                        help="System exposure level")
    parser.add_argument("--safety-impact", required=True, choices=sorted(VALID_SAFETY),
                        help="Safety impact level")
    parser.add_argument("--mission-impact", required=True, choices=sorted(VALID_MISSION),
                        help="Mission impact level")
    parser.add_argument("--previous-state", default="", help="Path to previous state JSON file")
    parser.add_argument("--save-state", default="", help="Path to save current state JSON file")
    parser.add_argument("--slack-webhook", default="", help="Slack Incoming Webhook URL")
    parser.add_argument("--threshold", default="Scheduled",
                        choices=sorted(VALID_THRESHOLD),
                        help="Minimum SSVC status to send Slack notification (default: Scheduled)")
    parser.add_argument("--output", default="table", choices=sorted(VALID_OUTPUT),
                        help="Output format: table or json (default: table)")

    args = parser.parse_args()
    _validate(args)

    # 1. Trivyのスキャン結果を読み込む
    try:
        report = trivy.parse_file(args.vulns)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)

    vulns = report.vulnerabilities()

    # 2. SSVCスコアを計算する
    params = ssvc.Params(
        system_exposure=args.system_exposure,
        safety_impact=args.safety_impact,
        mission_impact=args.mission_impact,
    )
    results = ssvc.score_all(vulns, params)

    # 3. 前回のstateを読み込む
    prev_state = state.load_file(args.previous_state) if args.previous_state else None

    # 4. 差分を計算する
    diff = state.diff(prev_state, results)

    # 5. 結果を出力する
    if args.output == "json":
        output.json_output(sys.stdout, results)
    else:
        output.table(sys.stdout, results)

    # 6. Slack通知する
    if args.slack_webhook:
        threshold = ssvc.Status.parse(args.threshold)
        try:
            notify.slack(args.slack_webhook, diff, threshold)
        except RuntimeError as e:
            print(f"warning: {e}", file=sys.stderr)

    # 7. stateを保存する
    if args.save_state:
        current_state = state.from_results(results, prev_state)
        state.save_file(args.save_state, current_state)


if __name__ == "__main__":
    main()
