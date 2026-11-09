import hashlib
import json
from typing import Dict, Any, Tuple

def canonical_serialize(report_dict: Dict[str, Any]) -> Tuple[str, str]:
    """
    Implements Section 8.3 report hashing procedure.
    Removes 'web3' and 'report_hash' fields, performs deep recursive sorting of keys,
    formats with separators=(',', ':') without spaces/newlines, and returns:
    (canonical_text, sha256_hash_hex)
    """
    # Create working copy
    working_copy = json.loads(json.dumps(report_dict))
    
    # Remove fields not part of the hash
    working_copy.pop("web3", None)
    working_copy.pop("report_hash", None)

    def _clean_numbers(obj: Any) -> Any:
        if isinstance(obj, float):
            # No floating-point numbers per Section 8.3
            return int(obj) if obj.is_integer() else str(obj)
        elif isinstance(obj, dict):
            return {k: _clean_numbers(v) for k, v in sorted(obj.items())}
        elif isinstance(obj, list):
            return [_clean_numbers(elem) for elem in obj]
        return obj

    cleaned = _clean_numbers(working_copy)
    canonical_text = json.dumps(cleaned, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    report_hash = hashlib.sha256(canonical_text.encode("utf-8")).hexdigest().lower()

    return canonical_text, report_hash

def compute_onchain_id(report_id: str) -> str:
    """Computes SHA-256 over report UUID text to generate the 32-byte on-chain identifier."""
    return "0x" + hashlib.sha256(report_id.strip().encode("utf-8")).hexdigest().lower()
