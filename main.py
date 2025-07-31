import ssl
import socket
import logging
from datetime import datetime, timezone
from flask import Flask, request, jsonify

logging.basicConfig(level=logging.DEBUG)
app = Flask(__name__)

def get_cert_expiry(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=15) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                not_after = cert['notAfter']
                expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                expiry = expiry.replace(tzinfo=timezone.utc)
                days_remaining = (expiry - datetime.now(timezone.utc)).days

                # Get issuer in readable format
                issuer = ", ".join(f"{x[0]}={x[1]}" for x in cert.get("issuer", []))

                return {
                    "domain": domain,
                    "status": "ok",
                    "expiry": expiry.isoformat(),
                    "days_remaining": days_remaining,
                    "issuer": issuer
                }

    except ssl.SSLError as e:
        error_msg = str(e).lower()
        if "certificate has expired" in error_msg or "certificate verify failed" in error_msg:
            return {
                "domain": domain,
                "status": "expired",
                "reason": str(e)
            }
        return {
            "domain": domain,
            "status": "ssl_error",
            "reason": str(e)
        }

    except socket.timeout:
        return {
            "domain": domain,
            "status": "error",
            "reason": "Connection timeout after 15 seconds"
        }

    except socket.gaierror as e:
        return {
            "domain": domain,
            "status": "error",
            "reason": f"DNS resolution failed: {str(e)}"
        }

    except Exception as e:
        return {
            "domain": domain,
            "status": "error",
            "reason": str(e)
        }

@app.route("/", methods=["POST"])
def check_certificates():
    try:
        data = request.get_json()
        if not data or "domains" not in data or not isinstance(data["domains"], list):
            return jsonify({"error": "Invalid JSON format"}), 400

        results = []
        for domain in data["domains"]:
            if not isinstance(domain, str) or not domain.strip():
                results.append({
                    "domain": domain,
                    "status": "error",
                    "reason": "Invalid domain name"
                })
                continue

            clean_domain = domain.strip().replace("https://", "").replace("http://", "")
            results.append(get_cert_expiry(clean_domain))

        return jsonify(results)

    except Exception as e:
        app.logger.error(f"Unexpected error: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/", methods=["GET"])
def index():
    return jsonify({
        "message": "SSL Certificate Checker API",
        "usage": "POST / with JSON: {'domains': ['example.com']}",
        "fields": ["domain", "status", "expiry", "days_remaining", "issuer", "reason (if error)"]
    })

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "404 not found"}), 404

@app.errorhandler(405)
def not_allowed(e):
    return jsonify({"error": "405 method not allowed"}), 405

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
