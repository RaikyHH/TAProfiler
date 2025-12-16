import json
import os
import requests
import urllib.parse
from pathlib import Path
from dotenv import load_dotenv
from services.malpedia_service import get_feedly_entity_id as get_malpedia_entity_id
from services.http_client import safe_get, safe_post, get_global_session
try:
    import iso3166
except ImportError:
    iso3166 = None

load_dotenv()

def get_country_name(country_code):
    """Convert ISO country code to human-readable name"""
    if not country_code or not iso3166:
        return country_code

    try:
        country = iso3166.countries.get(country_code.upper())
        if not country:
            return country_code

        # Clean up overly formal names
        name = country.name
        name = name.replace('Korea, Democratic People\'s Republic of', 'North Korea')
        name = name.replace('Korea, Republic of', 'South Korea')
        name = name.replace('Iran, Islamic Republic of', 'Iran')
        name = name.replace('Russian Federation', 'Russia')
        name = name.replace('United States of America', 'United States')
        name = name.replace('United Kingdom of Great Britain and Northern Ireland', 'United Kingdom')
        name = name.replace('Viet Nam', 'Vietnam')
        name = name.replace('Syrian Arab Republic', 'Syria')
        name = name.replace('Palestine, State of', 'Palestine')
        name = name.replace('Türkiye', 'Turkey')

        return name
    except (KeyError, AttributeError):
        return country_code

# Feedly API configuration
FEEDLY_API_BASE = "https://api.feedly.com/v3"
FEEDLY_API_TOKEN = os.getenv('FEEDLY_API_TOKEN', '').strip('\'"')  # Strip quotes

# Get reusable session with proxy support
_session = get_global_session()

# Load manual mappings (optional overrides)
_FEEDLY_MAPPINGS = {}
_mappings_file = Path(__file__).parent.parent / 'feedly_mappings.json'
if _mappings_file.exists():
    try:
        with open(_mappings_file, 'r') as f:
            mapping_data = json.load(f)
            _FEEDLY_MAPPINGS = mapping_data.get('mappings', {})
        print(f"[FEEDLY] Loaded {len(_FEEDLY_MAPPINGS)} manual actor mappings")
    except Exception as e:
        print(f"[FEEDLY] Error loading mappings: {e}")

def search_threat_actor_by_name(actor_name):
    """
    Search for a threat actor by name and return the Feedly entity ID.

    Uses a three-tier approach:
    1. Manual mappings from feedly_mappings.json (highest priority)
    2. Malpedia API UUID lookup (automatic for most actors)
    3. Return None if not found

    Args:
        actor_name: Name of the threat actor

    Returns:
        Feedly entity ID string or None
    """
    # Check manual mappings first (highest priority - for overrides)
    if actor_name in _FEEDLY_MAPPINGS:
        return _FEEDLY_MAPPINGS[actor_name]

    # Try Malpedia UUID lookup (automatic for most actors)
    try:
        entity_id = get_malpedia_entity_id(actor_name)
        if entity_id:
            return entity_id
    except Exception as e:
        print(f"[FEEDLY] Error in Malpedia lookup for '{actor_name}': {e}")

    return None

def fetch_feedly_threat_actor(entity_id):
    """
    Fetch threat actor metadata from Feedly API with proxy support and retry logic.

    Args:
        entity_id: Feedly entity ID (e.g., "nlp/f/entity/gz:ta:68391641-859f-4a9a-9a1e-3e5cf71ec376")

    Returns:
        Dictionary with threat actor data or None if not found
    """
    if not FEEDLY_API_TOKEN:
        print("[ERROR] FEEDLY_API_TOKEN not set. Cannot fetch data.")
        return None

    # URL encode the entity ID
    encoded_id = urllib.parse.quote(entity_id, safe='')
    url = f"{FEEDLY_API_BASE}/entities/{encoded_id}"

    headers = {
        'Authorization': f'Bearer {FEEDLY_API_TOKEN}'
    }

    # Use safe_get with retry logic and proxy support
    response = safe_get(url, headers=headers, timeout=30, session=_session)

    if response:
        try:
            return response.json()
        except Exception as e:
            print(f"[FEEDLY] Error parsing JSON response for {entity_id}: {e}")
            return None
    return None

def parse_feedly_response(feedly_data):
    """
    Parse Feedly API response and extract all relevant fields.

    Args:
        feedly_data: JSON response from Feedly API

    Returns:
        Dictionary with enrichment data including all available Feedly fields
    """
    if not feedly_data:
        return None

    # Extract origin country from threatActorDetails
    origin_countries = []
    threat_actor_details = feedly_data.get('threatActorDetails', {})

    if 'country' in threat_actor_details and threat_actor_details['country']:
        # Country is ISO code (e.g., "KP" for North Korea, "CN" for China)
        country_code = threat_actor_details['country']
        origin_countries = [get_country_name(country_code)]

    # Extract victim sectors/industries
    victim_sectors = []
    if 'targetIndustries' in threat_actor_details and threat_actor_details['targetIndustries']:
        victim_sectors = [industry['label'] for industry in threat_actor_details['targetIndustries']]
    
    # Fallback: Infer sectors from targets if not provided
    if not victim_sectors and 'targets' in threat_actor_details:
        targets_list = threat_actor_details.get('targets', [])
        inferred_sectors = set()
        
        # Keyword mapping for sector inference
        sector_keywords = {
            'Financial Services': ['bank', 'finance', 'financial', 'exchange', 'crypto', 'currency', 'payment', 'swift'],
            'Government': ['government', 'ministry', 'agency', 'embassy', 'diplomatic', 'election'],
            'Defense': ['defense', 'military', 'army', 'navy', 'air force', 'weapon'],
            'Energy': ['energy', 'power', 'oil', 'gas', 'electric', 'nuclear', 'utility'],
            'Telecommunications': ['telecom', 'isp', 'mobile', 'carrier'],
            'Healthcare': ['health', 'hospital', 'medical', 'pharmaceutical', 'vaccine'],
            'Education': ['university', 'college', 'research', 'academic'],
            'Technology': ['tech', 'software', 'it service', 'cyber', 'semiconductor'],
            'Media & Entertainment': ['media', 'entertainment', 'pictures', 'studio', 'broadcasting', 'news'],
            'Aerospace': ['aerospace', 'airline', 'aviation', 'space'],
            'Manufacturing': ['manufacturing', 'industrial', 'factory'],
            'Retail': ['retail', 'commerce', 'store']
        }
        
        for target in targets_list:
            target_lower = target.lower()
            for sector, keywords in sector_keywords.items():
                if any(k in target_lower for k in keywords):
                    inferred_sectors.add(sector)
        
        if inferred_sectors:
            victim_sectors = sorted(list(inferred_sectors))

    # Fallback 2: Infer sectors from description if still unknown
    description = threat_actor_details.get('malpediaDescription') or feedly_data.get('description', '')
    if not victim_sectors and description:
        inferred_sectors = set()
        desc_lower = description.lower()
        
        # Re-use sector keywords (defined above, but need to be accessible)
        # We need to redefine or move the dictionary to a broader scope if we want to reuse it efficiently
        # For now, I'll just use the same dictionary logic here
        
        sector_keywords = {
            'Financial Services': ['bank', 'finance', 'financial', 'exchange', 'crypto', 'currency', 'payment', 'swift'],
            'Government': ['government', 'ministry', 'agency', 'embassy', 'diplomatic', 'election'],
            'Defense': ['defense', 'military', 'army', 'navy', 'air force', 'weapon'],
            'Energy': ['energy', 'power', 'oil', 'gas', 'electric', 'nuclear', 'utility'],
            'Telecommunications': ['telecom', 'isp', 'mobile', 'carrier'],
            'Healthcare': ['health', 'hospital', 'medical', 'pharmaceutical', 'vaccine'],
            'Education': ['university', 'college', 'research', 'academic'],
            'Technology': ['tech', 'software', 'it service', 'cyber', 'semiconductor'],
            'Media & Entertainment': ['media', 'entertainment', 'pictures', 'studio', 'broadcasting', 'news'],
            'Aerospace': ['aerospace', 'airline', 'aviation', 'space'],
            'Manufacturing': ['manufacturing', 'industrial', 'factory'],
            'Retail': ['retail', 'commerce', 'store', 'hospitality', 'restaurant']
        }
        
        for sector, keywords in sector_keywords.items():
            if any(k in desc_lower for k in keywords):
                inferred_sectors.add(sector)
                
        if inferred_sectors:
            victim_sectors = sorted(list(inferred_sectors))

    # Extract victim countries - not directly available, use targets
    victim_countries = []
    targets = threat_actor_details.get('targets', [])
    # Filter out organization names, keep country names
    common_orgs = ['Bank', 'Pictures', 'Entertainment', 'exchanges', 'Exchange']
    for target in targets:
        if not any(org in target for org in common_orgs):
            victim_countries.append(target)

    # Extract motivations (array)
    motivations = threat_actor_details.get('motivations', [])

    # Extract associated malware
    associated_malware = []
    if 'associatedMalwares' in threat_actor_details:
        for malware in threat_actor_details['associatedMalwares']:
            associated_malware.append({
                'id': malware.get('id', ''),
                'label': malware.get('label', '')
            })

    # Extract target entities (specific organizations/countries)
    target_entities = targets

    # Extract other metadata
    popularity = feedly_data.get('popularity', 0)
    knowledge_base_url = feedly_data.get('knowledgeBaseUrl', '')
    badges = feedly_data.get('badges', [])
    first_seen_at = feedly_data.get('firstSeenAt', '')
    feedly_id = feedly_data.get('id', '')

    # Get description from malpediaDescription or main description
    description = threat_actor_details.get('malpediaDescription') or feedly_data.get('description', '')

    return {
        "origin_country": origin_countries[0] if origin_countries else "Unknown",
        "victim_sectors": victim_sectors if victim_sectors else ["Unknown"],
        "victim_countries": victim_countries if victim_countries else ["Unknown"],
        "motivations": motivations,
        "associated_malware": associated_malware,
        "target_entities": target_entities,
        "popularity": popularity,
        "knowledge_base_url": knowledge_base_url,
        "badges": badges,
        "first_seen_at": first_seen_at,
        "feedly_id": feedly_id,
        "description": description
    }

def enrich_actor_data(actor_name, feedly_entity_id=None):
    """
    Enrich actor data from Feedly API ONLY. Returns None if actor not found in Feedly.

    Args:
        actor_name: Name of the threat actor
        feedly_entity_id: Optional Feedly entity ID (e.g., "nlp/f/entity/gz:ta:{UUID}")

    Returns:
        Dictionary with enrichment data, or None if actor not found in Feedly
    """
    print(f"[FEEDLY] Enriching '{actor_name}'...")

    # Try to fetch from Feedly API
    if feedly_entity_id:
        print(f"[FEEDLY] Using provided entity ID: {feedly_entity_id}")
        feedly_data = fetch_feedly_threat_actor(feedly_entity_id)
        if feedly_data:
            print(f"[FEEDLY] Successfully fetched data from API")
            enriched = parse_feedly_response(feedly_data)
            if enriched:
                print(f"[FEEDLY] Enrichment complete: {len(enriched.get('associated_malware', []))} malware, popularity={enriched.get('popularity', 0)}")
                return enriched
        else:
            print(f"[FEEDLY] Failed to fetch data from API")
    else:
        print(f"[FEEDLY] No entity ID provided, trying name search...")
        # Try to search for the actor by name
        entity_id = search_threat_actor_by_name(actor_name)
        if entity_id:
            print(f"[FEEDLY] Found entity ID via search: {entity_id}")
            feedly_data = fetch_feedly_threat_actor(entity_id)
            if feedly_data:
                enriched = parse_feedly_response(feedly_data)
                if enriched:
                    print(f"[FEEDLY] Enrichment complete via search")
                    return enriched
        else:
            print(f"[FEEDLY] No entity found via name search")

    # NO FALLBACK - Return None if actor not found in Feedly
    print(f"[FEEDLY] [X] Actor '{actor_name}' not found in Feedly - will be skipped")
    return None
