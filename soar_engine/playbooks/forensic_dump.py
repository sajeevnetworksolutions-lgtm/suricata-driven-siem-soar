from models import IncidentAlert
from dossier import create_forensic_dossier as _create_dossier, verify_chain

__all__ = ["create_forensic_dossier", "verify_chain"]


def create_forensic_dossier(alert: IncidentAlert) -> str:
    """Create Eq. 12 hash-chained forensic dossier and return its CaseID."""
    result = _create_dossier(alert)
    return result["case_id"]
