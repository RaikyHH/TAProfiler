"""
Malpedia API service for mapping threat actor names to Feedly UUIDs
"""
import json
from pathlib import Path
from services.http_client import safe_get

MALPEDIA_API_BASE = "https://malpedia.caad.fkie.fraunhofer.de/api"

# Cache for Malpedia data
_MALPEDIA_ACTORS = None
_NAME_TO_SLUG = {}  # Maps actor name/synonym -> malpedia slug
_SLUG_TO_UUID = {}  # Maps malpedia slug -> UUID

def normalize_name(name):
    """Normalize actor name for comparison (lowercase, no spaces/special chars)."""
    return name.lower().replace(' ', '').replace('-', '').replace('_', '')

def load_malpedia_actors():
    """
    Load list of actors from Malpedia API or local cache.

    Returns:
        List of actor slugs
    """
    global _MALPEDIA_ACTORS

    if _MALPEDIA_ACTORS is not None:
        return _MALPEDIA_ACTORS

    # Try to load from local file first
    local_file = Path(__file__).parent.parent / 'malpedia_actors.json'
    if local_file.exists():
        try:
            with open(local_file, 'r', encoding='utf-8') as f:
                _MALPEDIA_ACTORS = json.load(f)
                print(f"[MALPEDIA] Loaded {len(_MALPEDIA_ACTORS)} actors from local cache")
                return _MALPEDIA_ACTORS
        except Exception as e:
            print(f"[MALPEDIA] Error loading local cache: {e}")

    # Fetch from API if local file doesn't exist
    try:
        print(f"[MALPEDIA] Fetching actor list from API...")
        response = safe_get(f"{MALPEDIA_API_BASE}/list/actors", timeout=30)
        if not response:
            return []
        _MALPEDIA_ACTORS = response.json()

        # Save to local file for future use
        with open(local_file, 'w', encoding='utf-8') as f:
            json.dump(_MALPEDIA_ACTORS, f, indent=2)

        print(f"[MALPEDIA] Fetched and cached {len(_MALPEDIA_ACTORS)} actors")
        return _MALPEDIA_ACTORS
    except Exception as e:
        print(f"[MALPEDIA] Error fetching actor list: {e}")
        return []

def get_actor_details(actor_slug):
    """
    Get detailed information about an actor from Malpedia.

    Args:
        actor_slug: Malpedia actor slug (e.g., "lazarus_group")

    Returns:
        Dictionary with actor details including UUID
    """
    try:
        response = safe_get(f"{MALPEDIA_API_BASE}/get/actor/{actor_slug}", timeout=10)
        if not response:
            return None
        return response.json()
    except Exception as e:
        print(f"[MALPEDIA] Error fetching details for '{actor_slug}': {e}")
        return None

def build_name_mappings():
    """
    Build mappings from actor names/synonyms to Malpedia slugs and UUIDs.
    This is done lazily on first lookup to avoid API rate limits.
    """
    global _NAME_TO_SLUG, _SLUG_TO_UUID

    if _NAME_TO_SLUG:
        return  # Already built

    actors = load_malpedia_actors()
    if not actors:
        return

    print(f"[MALPEDIA] Building name mappings for {len(actors)} actors...")

    # For efficiency, we'll just map the slug names directly
    # and load details on-demand when needed
    for actor_slug in actors:
        # Map the slug itself (e.g., "lazarus_group" -> "lazarus_group")
        _NAME_TO_SLUG[normalize_name(actor_slug)] = actor_slug

        # Also map with spaces (e.g., "lazarus group" -> "lazarus_group")
        readable_name = actor_slug.replace('_', ' ')
        _NAME_TO_SLUG[normalize_name(readable_name)] = actor_slug

    print(f"[MALPEDIA] Built {len(_NAME_TO_SLUG)} name mappings")

def get_uuid_for_actor(actor_name):
    """
    Get the Malpedia UUID for a threat actor by name.

    Args:
        actor_name: Name of the threat actor

    Returns:
        UUID string or None if not found
    """
    if not _NAME_TO_SLUG:
        build_name_mappings()

    # Try to find the actor slug
    normalized = normalize_name(actor_name)
    actor_slug = _NAME_TO_SLUG.get(normalized)

    if not actor_slug:
        return None

    # Check if we already have the UUID cached
    if actor_slug in _SLUG_TO_UUID:
        return _SLUG_TO_UUID[actor_slug]

    # Fetch details from API to get UUID
    details = get_actor_details(actor_slug)
    if not details:
        return None

    uuid = details.get('uuid')
    if uuid:
        _SLUG_TO_UUID[actor_slug] = uuid
        return uuid

    return None

def get_feedly_entity_id(actor_name):
    """
    Get the Feedly entity ID for a threat actor using Malpedia UUID.

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
build_name_mappings()
