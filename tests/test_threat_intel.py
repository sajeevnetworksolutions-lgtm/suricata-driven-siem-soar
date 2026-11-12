import os
import sys
from unittest.mock import patch, MagicMock

SOAR_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "soar_engine"))
if SOAR_DIR not in sys.path:
    sys.path.insert(0, SOAR_DIR)

from playbooks.threat_intel import enrich_ip, compute_reputation_score
from config import config


def test_reputation_formula_weights():
    # R(x) = 0.7 * AbuseIPDB + 0.3 * ASN
    assert compute_reputation_score(95, 78, 0.7, 0.3) == 90
    assert compute_reputation_score(100, 100, 0.7, 0.3) == 100
    assert compute_reputation_score(0, 0, 0.7, 0.3) == 0


def test_lab_ips_use_labelled_local_ioc_cache():
    apt = enrich_ip("192.168.1.150")
    assert apt.reputation_score == 90
    assert apt.intel_source == "local_ioc_cache"
    assert apt.is_malicious is True

    auth_lab = enrich_ip("172.28.0.105")
    assert auth_lab.reputation_score == 85
    assert auth_lab.intel_source == "local_ioc_cache"


def test_public_ip_queries_abuseipdb_with_formula():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "abuseConfidenceScore": 90,
            "countryName": "Germany",
            "countryCode": "DE",
            "isp": "Hetzner AS24940",
            "usageType": "Data Center/Web Hosting/Transit",
            "isTor": False,
        }
    }
    orig_key = config.ABUSEIPDB_API_KEY
    try:
        config.ABUSEIPDB_API_KEY = "test-api-key"
        with patch("playbooks.threat_intel.requests.get", return_value=mock_resp) as mocked:
            res = enrich_ip("8.8.4.4")
            assert mocked.called
            assert res.intel_source == "abuseipdb"
            # 0.7 * 90 + 0.3 * 70 (hosting ASN) = 63 + 21 = 84
            assert res.reputation_score == 84
    finally:
        config.ABUSEIPDB_API_KEY = orig_key
