import argparse

from pathlib import Path

from app.telemetry import generate_demo_timeline, inject_incident, run_generator


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate Agentic Ops telemetry.")
    parser.add_argument(
        "--interval", type=float, default=5.0, help="Normal event interval in seconds."
    )
    parser.add_argument(
        "--incident-interval",
        type=float,
        default=600.0,
        help="Incident injection interval in seconds.",
    )
    parser.add_argument(
        "--inject-once", action="store_true", help="Inject one incident burst and exit."
    )
    parser.add_argument(
        "--incident-type",
        default=None,
        help="Optional incident type for --inject-once.",
    )
    parser.add_argument(
        "--demo-timeline",
        action="store_true",
        help="Generate the full deterministic demo timeline and exit.",
    )
    parser.add_argument(
        "--duration-minutes", type=int, default=35, help="Demo timeline duration."
    )
    parser.add_argument("--output", default=None, help="Optional output log path.")
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite the output file before generating.",
    )
    args = parser.parse_args()

    output_path = Path(args.output) if args.output else None

    if args.demo_timeline:
        incident_ids = generate_demo_timeline(
            path=output_path,
            duration_minutes=args.duration_minutes,
            overwrite=args.overwrite,
        )
        print("Generated demo timeline")
        for incident_id in incident_ids:
            print(incident_id)
        return

    if args.inject_once:
        incident_id = inject_incident(args.incident_type, path=output_path)
        print(f"Injected incident {incident_id}")
        return

    run_generator(args.interval, args.incident_interval)


if __name__ == "__main__":
    main()
