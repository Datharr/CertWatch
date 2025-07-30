import ssl
import socket
import logging
from datetime import datetime, timezone
from flask import Flask, request, jsonify

# Configure logging for debugging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

def get_cert_expiry(domain):
    """
    Check SSL certificate expiry for a given domain.
    
    Args:
        domain (str): The domain name to check
        
    Returns:
        dict: Certificate status information including expiry date and days remaining
    """
    try:
        # Create SSL context with default settings
        context = ssl.create_default_context()
        
        # Establish connection with 15-second timeout
        with socket.create_connection((domain, 443), timeout=15) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Get certificate information
                cert = ssock.getpeercert()
                
                # Parse the 'notAfter' field to get expiry date
                not_after = cert['notAfter']
                expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                expiry = expiry.replace(tzinfo=timezone.utc)
                
                # Calculate days remaining until expiry
                days_remaining = (expiry - datetime.now(timezone.utc)).days
                
                return {
                    "domain": domain,
                    "status": "ok",
                    "expiry": expiry.isoformat(),
                    "days_remaining": days_remaining
                }
                
    except ssl.SSLError as e:
        # Handle SSL-specific errors
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
        # Handle connection timeout
        return {
            "domain": domain,
            "status": "error",
            "reason": "Connection timeout after 15 seconds"
        }
        
    except socket.gaierror as e:
        # Handle DNS resolution errors
        return {
            "domain": domain,
            "status": "error",
            "reason": f"DNS resolution failed: {str(e)}"
        }
        
    except Exception as e:
        # Handle any other unexpected errors
        return {
            "domain": domain,
            "status": "error",
            "reason": str(e)
        }

@app.route("/", methods=["POST"])
def check_certificates():
    """
    Main API endpoint to check SSL certificates for multiple domains.
    
    Expected JSON payload:
    {
        "domains": ["example.com", "google.com", ...]
    }
    
    Returns:
        JSON array with certificate status for each domain
    """
    try:
        # Get JSON data from request
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
            
        domains = data.get("domains", [])
        
        if not isinstance(domains, list):
            return jsonify({"error": "domains must be an array"}), 400
            
        if not domains:
            return jsonify({"error": "domains array cannot be empty"}), 400
            
        # Check certificates for all domains
        results = []
        for domain in domains:
            if not isinstance(domain, str) or not domain.strip():
                results.append({
                    "domain": domain,
                    "status": "error",
                    "reason": "Invalid domain name"
                })
                continue
                
            # Remove any protocol prefixes and whitespace
            clean_domain = domain.strip().replace("https://", "").replace("http://", "")
            results.append(get_cert_expiry(clean_domain))
            
        return jsonify(results)
        
    except Exception as e:
        app.logger.error(f"Unexpected error in check_certificates: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/", methods=["GET"])
def index():
    """
    Simple GET endpoint to show API usage information.
    """
    return jsonify({
        "message": "SSL Certificate Checker API",
        "usage": "Send POST request to / with JSON: {'domains': ['example.com', 'google.com']}",
        "response_fields": {
            "domain": "The checked domain name",
            "status": "ok | expired | ssl_error | error",
            "expiry": "ISO format expiry date (when status is 'ok')",
            "days_remaining": "Days until expiry (when status is 'ok')",
            "reason": "Error description (when status is not 'ok')"
        }
    })

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({"error": "Endpoint not found. Use POST / to check certificates."}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    """Handle method not allowed errors."""
    return jsonify({"error": "Method not allowed. Use POST / to check certificates."}), 405

if __name__ == "__main__":
    # Run the Flask application
    # Bind to 0.0.0.0:5000 as required for Replit deployment
    app.run(host="0.0.0.0", port=5000, debug=True)
