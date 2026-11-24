import argparse
import json
import sys

from .config import get_settings


def main() -> int:
    parser = argparse.ArgumentParser(prog="triage-forge")
    sub = parser.add_subparsers(dest="command", required=True)
    train = sub.add_parser("train", help="train the risk and technique models")
    train.add_argument("--alerts", type=int, default=6000)
    one = sub.add_parser("triage", help="triage an alert from a JSON file")
    one.add_argument("path")
    serve = sub.add_parser("serve", help="run the API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    settings = get_settings()
    if args.command == "train":
        from .models import save
        from .models import train as train_models

        risk, technique = train_models(n=args.alerts)
        save(risk, technique, settings.model_dir)
        print(f"Saved models to {settings.model_dir}")
    elif args.command == "triage":
        from .pipeline import Triage
        from .schemas import Alert

        alert = Alert.model_validate_json(open(args.path).read())
        print(json.dumps(Triage(settings).run(alert).model_dump(mode="json"), indent=2))
    elif args.command == "serve":
        import uvicorn

        uvicorn.run("triage_forge.main:app", host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
