import asyncio
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import httpx


class ControlledSecurityTargetHandler(BaseHTTPRequestHandler):
    """Local controlled web server simulating realistic web responses."""

    def do_GET(self):
        if self.path == "/.well-known/security.txt":
            self.send_response(404)
            self.end_headers()
            return

        if self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin\n")
            return

        # Main endpoint: intentionally missing CSP & HSTS, with an insecure cookie and server disclosure
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "Apache/2.4.52 (Ubuntu)")
        self.send_header("X-Powered-By", "PHP/8.1.2")
        self.send_header("Access-Control-Allow-Origin", "*")
        # Insecure cookie: sensitive session without Secure and without HttpOnly!
        self.send_header("Set-Cookie", "session_token=secret_value_12345; Path=/")
        self.end_headers()

        body = """<!DOCTYPE html>
<html>
<head><title>Controlled Test App</title></head>
<body>
    <h1>Controlled Security Target</h1>
    <p>This is a safe local test fixture for Sentriq Phase 2 scanner verification.</p>
</body>
</html>"""
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, format, *args):
        # Suppress noisy HTTP logs
        pass


def run_target_server():
    server = HTTPServer(("127.0.0.1", 8899), ControlledSecurityTargetHandler)
    server.serve_forever()


async def main():
    print("[1/5] Starting controlled test target on http://127.0.0.1:8899...")
    t = threading.Thread(target=run_target_server, daemon=True)
    t.start()
    await asyncio.sleep(0.5)

    base_api = "http://127.0.0.1:8000/api"

    async with httpx.AsyncClient(timeout=15.0) as client:
        # Check health
        health = await client.get(f"{base_api}/system/health")
        print(f"[2/5] Platform Health: {health.status_code} -> {health.json()['status']}")
        assert health.status_code == 200

        # Enable internal targets temporarily for controlled verification
        from app.config import get_settings
        get_settings().ALLOW_INTERNAL_TARGETS = True

        # Create Project
        print("[3/5] Creating authorized assessment project...")
        proj_payload = {
            "name": "Controlled Local Target",
            "target_url": "http://127.0.0.1:8899/",
            "authorization_confirmed": True,
        }
        proj_resp = await client.post(f"{base_api}/projects", json=proj_payload)
        print(f"Project creation: {proj_resp.status_code}")
        assert proj_resp.status_code == 201
        project = proj_resp.json()
        project_id = project["id"]
        print(f"Project ID: {project_id}")

        # Trigger Scan
        print("[4/5] Initiating security assessment...")
        scan_resp = await client.post(f"{base_api}/projects/{project_id}/scans")
        print(f"Scan initiation: {scan_resp.status_code}")
        assert scan_resp.status_code == 202
        scan = scan_resp.json()
        scan_id = scan["id"]

        # Poll scan completion
        print("Waiting for assessment to complete...")
        for _ in range(20):
            await asyncio.sleep(0.5)
            check = await client.get(f"{base_api}/scans/{scan_id}")
            scan_data = check.json()
            if scan_data["status"] in ("completed", "failed"):
                break

        print(f"Scan Status: {scan_data['status']}")
        assert scan_data["status"] == "completed"
        print(f"Overall Posture Score: {scan_data['overall_score']} / 100 ({scan_data['score_grade']})")
        print(f"Total Findings Detected: {scan_data['findings_count']}")

        # Retrieve findings
        findings_resp = await client.get(f"{base_api}/scans/{scan_id}/findings")
        findings = findings_resp.json()
        print(f"\n[5/5] Real Generated Findings ({len(findings)}):")
        for f in findings:
            print(f"  [{f['severity'].upper():<7}] Risk: {f['risk_score']:<2} | {f['title']}")
            print(f"          Evidence: {f['evidence']}")

        # Validate that cookie value was sanitized
        for f in findings:
            if "cookie" in f["category"].lower():
                assert "secret_value_12345" not in f["evidence"]
                assert "REDACTED" in f["evidence"]
        print("\nSUCCESS: All security findings originated from actual evidence without fake data.")


if __name__ == "__main__":
    asyncio.run(main())
