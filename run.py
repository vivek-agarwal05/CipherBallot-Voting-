"""
CipherBallot — Entry point

Run with TLS/HTTPS (default when local X.509 cert exists):
    python run.py

Run over plain HTTP (useful for Wireshark unprotected vs TLS comparison):
    python run.py --http
"""
import argparse
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

from app import create_app

app = create_app()


def main() -> None:
    parser = argparse.ArgumentParser(description='Run CipherBallot server.')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--https', action='store_true', help='Run with TLS/HTTPS using local X.509 certificate.')
    group.add_argument('--http', action='store_true', help='Run plain HTTP (for Wireshark plaintext comparison).')
    parser.add_argument('--host', default='127.0.0.1', help='Bind host (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=5000, help='Bind port (default: 5000)')
    args = parser.parse_args()

    cert_path = Path(app.config.get('TLS_CERT_PATH', 'instance/certs/cert.pem'))
    key_path = Path(app.config.get('TLS_KEY_PATH', 'instance/certs/key.pem'))
    certs_exist = cert_path.exists() and key_path.exists()

    use_https = False if args.http else (True if args.https else certs_exist)

    if use_https:
        if not certs_exist:
            raise RuntimeError(
                f"TLS certificate not found at '{cert_path}' / '{key_path}'. "
                "Run: python scripts/init_keys.py --ensure-missing"
            )
        app.config['SESSION_COOKIE_SECURE'] = True
        print(f"\n🔒 Starting CipherBallot over HTTPS/TLS at https://{args.host}:{args.port}")
        print(f"   Certificate: {cert_path}")
        print("   Tip: Use 'python run.py --http' when capturing unprotected HTTP traffic in Wireshark.\n")
        app.run(debug=True, host=args.host, port=args.port, ssl_context=(str(cert_path), str(key_path)))
    else:
        app.config['SESSION_COOKIE_SECURE'] = False
        print(f"\n⚠️  Starting CipherBallot over plain HTTP at http://{args.host}:{args.port}")
        print("   (Plaintext mode — ideal for Wireshark HTTP vs TLS demonstration)\n")
        app.run(debug=True, host=args.host, port=args.port)


if __name__ == '__main__':
    main()
