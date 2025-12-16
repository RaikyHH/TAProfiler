"""
Malpedia API service - Single API call approach
Fetches ALL actors in one call from /api/get/actors endpoint
"""
import requests
import json
from pathlib import Path
from services.http_client import safe_get, get_global_session

MALPEDIA_ACTORS_URL = "https://malpedia.caad.fkie.fraunhofer.de/api/get/actors"

# Get reusable session with proxy support
_session = get_global_session()

# Cache for all actor data
_ALL_ACTORS_DATA = None

def fetch_all_actors():
    """
    Fetch ALL actor data from Malpedia in a SINGLE API call.

    Returns:
        Dictionary mapping actor slugs to actor data (including UUIDs)
    """
    global _ALL_ACTORS_DATA

    if _ALL_ACTORS_DATA is not None:
        return _ALL_ACTORS_DATA

    # Try local cache first
    cache_file = Path(__file__).parent.parent / 'malpedia_all_actors.json'
    if cache_file.exists():
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                _ALL_ACTORS_DATA = json.load(f)
                print(f"[MALPEDIA] Loaded {len(_ALL_ACTORS_DATA)} actors from local cache")
                return _ALL_ACTORS_DATA
        except Exception as e:
            print(f"[MALPEDIA] Error loading cache: {e}")

    # Make SINGLE API call to get all actors with proxy support
    print(f"[MALPEDIA] Making SINGLE API call to fetch all actors...")
    response = safe_get(MALPEDIA_ACTORS_URL, timeout=60, session=_session)

    if response:
        try:
            _ALL_ACTORS_DATA = response.json()

            # Save to cache
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(_ALL_ACTORS_DATA, f, indent=2)

            print(f"[MALPEDIA] SUCCESS! Fetched {len(_ALL_ACTORS_DATA)} actors in ONE call")
            return _ALL_ACTORS_DATA
        except Exception as e:
            print(f"[MALPEDIA] Error parsing JSON response: {e}")
            return {}
    else:
        print(f"[MALPEDIA] ERROR fetching actors (check proxy settings if configured)")
        return {}

def normalize_name(name):
    """Normalize name for matching (lowercase, no spaces/underscores/hyphens)."""
    return name.lower().replace(' ', '').replace('_', '').replace('-', '')

def find_actor_by_name(actor_name):
    """
    Find an actor by name from the cached Malpedia data.

    Args:
        actor_name: Name of the threat actor (e.g., "Lazarus Group")

    Returns:
        Actor data dict with 'uuid' and 'value', or None if not found
    """
    all_actors = fetch_all_actors()
    if not all_actors:
        return None

    normalized_search = normalize_name(actor_name)

    # Search through all actors
    for actor_slug, actor_data in all_actors.items():
        # Check the value field
        if 'value' in actor_data:
            if normalize_name(actor_data['value']) == normalized_search:
                return actor_data

        # Check synonyms in meta
        if 'meta' in actor_data and 'synonyms' in actor_data['meta']:
            for synonym in actor_data['meta']['synonyms']:
                if normalize_name(synonym) == normalized_search:
                    return actor_data

    return None

def get_uuid_for_actor(actor_name):
    """
    Get the Malpedia UUID for a threat actor.

    Args:
        actor_name: Name of the threat actor

    Returns:
        UUID string or None
    """
    actor_data = find_actor_by_name(actor_name)
    if actor_data and 'uuid' in actor_data:
        return actor_data['uuid']
    return None

def get_feedly_entity_id(actor_name):
    """
    Get the Feedly entity ID for a threat actor.

    Format: nlp/f/entity/gz:ta:{UUID}

    Args:
        actor_name: Name of the threat actor

    Returns:
        Feedly entity ID string or None
    """
    uuid = get_uuid_for_actor(actor_name)
    if not uuid:
        return None

    return f"nlp/f/entity/gz:ta:{uuid}"
