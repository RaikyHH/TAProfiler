"""
MISP Galaxy service for mapping threat actor names to UUIDs
"""
import json
from pathlib import Path
from services.http_client import safe_get

MISP_INTRUSION_SET_URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/mitre-intrusion-set.json"

# Cache for MISP data
_MISP_DATA = None
_MISP_UUID_MAP = {}  # Maps actor name -> UUID
_MISP_SYNONYM_MAP = {}  # Maps synonym -> canonical name

def load_misp_data():
    """
    Load MISP Galaxy intrusion-set data from GitHub or local cache.

    Returns:
        Dictionary with MISP Galaxy data
    """
    global _MISP_DATA

    if _MISP_DATA is not None:
        return _MISP_DATA

    # Try to load from local file first
    local_file = Path(__file__).parent.parent / 'misp_intrusion_set.json'
    if local_file.exists():
        try:
            with open(local_file, 'r', encoding='utf-8') as f:
                _MISP_DATA = json.load(f)
                print(f"[MISP] Loaded data from local file: {len(_MISP_DATA.get('values', []))} actors")
                return _MISP_DATA
        except Exception as e:
            print(f"[MISP] Error loading local file: {e}")

    # Fetch from GitHub if local file doesn't exist
    try:
        print(f"[MISP] Fetching data from {MISP_INTRUSION_SET_URL}...")
        response = safe_get(MISP_INTRUSION_SET_URL, timeout=30)
        if not response:
            return None
        _MISP_DATA = response.json()

        # Save to local file for future use
        with open(local_file, 'w', encoding='utf-8') as f:
            json.dump(_MISP_DATA, f, indent=2)

        print(f"[MISP] Fetched and cached {len(_MISP_DATA.get('values', []))} actors")
        return _MISP_DATA
    except Exception as e:
        print(f"[MISP] Error fetching MISP data: {e}")
        return None

def build_uuid_mappings():
    """
    Build mappings from threat actor names and synonyms to UUIDs.
    """
    global _MISP_UUID_MAP, _MISP_SYNONYM_MAP

    if _MISP_UUID_MAP:
        return  # Already built

    data = load_misp_data()
    if not data:
        return

    for actor in data.get('values', []):
        uuid = actor.get('uuid')
        value = actor.get('value', '')

        if not uuid or not value:
            continue

        # Extract canonical name from value (e.g., "Lazarus Group - G0032" -> "Lazarus Group")
        canonical_name = value.split(' - ')[0].strip()

        # Map canonical name to UUID
        _MISP_UUID_MAP[canonical_name] = uuid

        # Map all synonyms to canonical name
        synonyms = actor.get('meta', {}).get('synonyms', [])
        for synonym in synonyms:
            _MISP_SYNONYM_MAP[synonym] = canonical_name
            # Also map synonym directly to UUID
            _MISP_UUID_MAP[synonym] = uuid

    print(f"[MISP] Built UUID mappings: {len(_MISP_UUID_MAP)} names, {len(_MISP_SYNONYM_MAP)} synonyms")

def get_uuid_for_actor(actor_name):
    """
    Get the MISP UUID for a threat actor by name.

    Args:
        actor_name: Name of the threat actor

    Returns:
        UUID string or None if not found
    """
    if not _MISP_UUID_MAP:
        build_uuid_mappings()

    # Try direct lookup first
    uuid = _MISP_UUID_MAP.get(actor_name)
    if uuid:
        return uuid

    # Try synonym lookup
    canonical_name = _MISP_SYNONYM_MAP.get(actor_name)
    if canonical_name:
        return _MISP_UUID_MAP.get(canonical_name)

    return None

def get_feedly_entity_id(actor_name):
    """
    Get the Feedly entity ID for a threat actor using MISP UUID.

    Feedly entity IDs follow the pattern: nlp/f/entity/gz:ta:{UUID}

    Args:
        actor_name: Name of the threat actor

    Returns:
        Feedly entity ID string or None if UUID not found
    """
    uuid = get_uuid_for_actor(actor_name)
    if not uuid:
        return None

    # Construct Feedly entity ID
    return f"nlp/f/entity/gz:ta:{uuid}"

# Initialize mappings on module load
build_uuid_mappings()
