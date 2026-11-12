import os
import tempfile

_TEST_ROOT = tempfile.mkdtemp(prefix="soar_pytest_")
os.environ["DATA_DIR"] = os.path.join(_TEST_ROOT, "data")
os.environ["BAN_DB"] = os.path.join(_TEST_ROOT, "data", "bans.db")
os.environ["BAN_AUDIT_LOG"] = os.path.join(_TEST_ROOT, "data", "audit.jsonl")
os.environ["DOSSIER_DIR"] = os.path.join(_TEST_ROOT, "data", "forensics")
os.environ["EVE_LOG_PATH"] = os.path.join(_TEST_ROOT, "eve.json")
os.environ["DRY_RUN"] = "true"
os.environ["ENABLE_CHATTR"] = "false"
