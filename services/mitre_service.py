import requests
import json
import os
import time
import urllib.parse
from models.models import db, ThreatActor, TTP, actor_ttp, Changelog
from services.malpedia_service_v2 import fetch_all_actors, get_uuid_for_actor, find_actor_by_name
from services.feedly_service import fetch_feedly_threat_actor, parse_feedly_response
from services.http_client import safe_get, get_global_session

MITRE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/enterprise-attack/enterprise-attack.json"

# Get reusable session with proxy support
_session = get_global_session()

# CONFIGURABLE LIMITS
# 0 means unlimited - enrich all actors
MAX_ACTORS_TO_ENRICH = int(os.getenv('MAX_ACTORS_TO_ENRICH', '0'))  # Default: 0 (all actors)
DELAY_BETWEEN_FEEDLY_CALLS = 2  # seconds

def fetch_and_parse_mitre_data():
    """
    Fetch MITRE ATT&CK data and enrich with Feedly using Malpedia UUIDs.

    Process:
    1. Single Malpedia API call to get all 864 actors
    2. Fetch MITRE ATT&CK data
    3. Enrich actors with Feedly (limited by MAX_ACTORS_TO_ENRICH)
    4. Link TTPs to actors
    """

    print("=" * 70)
    print("MITRE ATT&CK DATA INGESTION WITH FEEDLY ENRICHMENT")
    print("=" * 70)
    print()

    # STEP 1: Single Malpedia API call
    print("[1/4] Fetching ALL actors from Malpedia (SINGLE API CALL)...")
    all_malpedia_actors = fetch_all_actors()

    if not all_malpedia_actors:
        print("[ERROR] Failed to fetch Malpedia data. Aborting ingestion.")
        return

    print(f"[SUCCESS] Got {len(all_malpedia_actors)} actors from Malpedia")
    print()

    # STEP 2: Fetch MITRE data with proxy support
    print(f"[2/4] Fetching MITRE ATT&CK data from {MITRE_URL}...")
    response = safe_get(MITRE_URL, timeout=60, session=_session)

    if response:
        try:
            data = response.json()
            print(f"[SUCCESS] Got MITRE data")
        except Exception as e:
            print(f"[ERROR] Failed to parse MITRE data: {e}")
            return
    else:
        print(f"[ERROR] Failed to fetch MITRE data (check proxy settings if configured)")
        return

    objects = data.get("objects", [])
    print(f"[INFO] Processing {len(objects)} MITRE objects...")
    print()

    # STEP 3: Process actors with Feedly enrichment
    limit_msg = "ALL actors" if MAX_ACTORS_TO_ENRICH == 0 else f"{MAX_ACTORS_TO_ENRICH} actors"
    print(f"[3/4] Enriching actors with Feedly (LIMIT: {limit_msg})...")
    print()

    actors = {}
    ttps = {}
    relationships = []

    # Track statistics
    total_mitre_actors = 0
    feedly_calls_made = 0
    actors_enriched = 0
    actors_skipped_not_in_malpedia = 0
    actors_skipped_limit_reached = 0
    rate_limit_hit = False

    for obj in objects:
        obj_type = obj.get("type")

        if obj_type == "intrusion-set":
            # Threat Actor
            total_mitre_actors += 1
            actor_id = obj.get("id")
            name = obj.get("name")
            description = obj.get("description", "")
            aliases = obj.get("aliases", [])
            motivation = obj.get("primary_motivation", "Unknown")

            # Check if we've reached the limit (0 means unlimited)
            if MAX_ACTORS_TO_ENRICH > 0 and feedly_calls_made >= MAX_ACTORS_TO_ENRICH:
                actors_skipped_limit_reached += 1
                continue

            # Get full Malpedia data
            malpedia_data = find_actor_by_name(name)

            if not malpedia_data:
                actors_skipped_not_in_malpedia += 1
                print(f"[SKIP] '{name}' - Not in Malpedia")
                continue

            uuid = malpedia_data.get('uuid')
            
            # Extract Malpedia enrichment data
            meta = malpedia_data.get('meta', {})
            attribution_confidence = meta.get('attribution-confidence')
            type_of_incident = meta.get('cfr-type-of-incident', [])
            references = meta.get('refs', [])
            related = malpedia_data.get('related', [])

            # Construct Feedly entity ID
            feedly_id = f"nlp/f/entity/gz:ta:{uuid}"

            actor_num_display = f"{feedly_calls_made + 1}/{MAX_ACTORS_TO_ENRICH}" if MAX_ACTORS_TO_ENRICH > 0 else f"{feedly_calls_made + 1}"
            print(f"[ACTOR {actor_num_display}] {name}")
            print(f"  UUID: {uuid}")

            # Add delay to avoid rate limiting (except for first call)
            if feedly_calls_made > 0:
                time.sleep(DELAY_BETWEEN_FEEDLY_CALLS)

            # Call Feedly API
            feedly_calls_made += 1

            try:
                feedly_data = fetch_feedly_threat_actor(feedly_id)

                if feedly_data is None:
                    print(f"  [FAILED] No data from Feedly")
                    continue

                # Parse Feedly response
                enriched = parse_feedly_response(feedly_data)

                if not enriched:
                    print(f"  [FAILED] Could not parse Feedly response")
                    continue

                actors_enriched += 1
                print(f"  [SUCCESS] {len(enriched.get('associated_malware', []))} malware, popularity={enriched.get('popularity', 0)}")

                # Use Feedly description if better
                if enriched.get('description') and len(enriched.get('description', '')) > len(description):
                    description = enriched['description']

                # Create actor with full enrichment
                actors[actor_id] = ThreatActor(
                    id=actor_id,
                    name=name,
                    description=description,
                    aliases=json.dumps(aliases),
                    motivation=motivation,
                    origin_countries=json.dumps([enriched['origin_country']]),
                    victim_sectors=json.dumps(enriched['victim_sectors']),
                    victim_countries=json.dumps(enriched['victim_countries']),
                    motivations=json.dumps(enriched.get('motivations', [])),
                    associated_malware=json.dumps(enriched.get('associated_malware', [])),
                    target_entities=json.dumps(enriched.get('target_entities', [])),
                    popularity=enriched.get('popularity', 0),
                    knowledge_base_url=enriched.get('knowledge_base_url', ''),
                    badges=json.dumps(enriched.get('badges', [])),
                    first_seen_at=enriched.get('first_seen_at', ''),
                    feedly_id=enriched.get('feedly_id', ''),
                    attribution_confidence=attribution_confidence,
                    type_of_incident=json.dumps(type_of_incident),
                    actor_references=json.dumps(references),
                    related_actors=json.dumps(related)
                )

            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 429:
                    print(f"\n[RATE LIMIT] Got 429 Too Many Requests from Feedly!")
                    print(f"[ABORT] Stopping enrichment to avoid API abuse")
                    rate_limit_hit = True
                    break
                else:
                    print(f"  [ERROR] HTTP {e.response.status_code}: {e}")
            except Exception as e:
                print(f"  [ERROR] {e}")

        elif obj_type == "attack-pattern":
            # TTP
            ttp_id = obj.get("id")
            name = obj.get("name")
            description = obj.get("description", "")

            # Extract MITRE ID
            mitre_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    mitre_id = ref.get("external_id")
                    break

            # Extract Tactics
            tactics = []
            for phase in obj.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    tactics.append(phase.get("phase_name"))

            ttps[ttp_id] = TTP(
                id=ttp_id,
                mitre_id=mitre_id,
                name=name,
                description=description,
                tactics=json.dumps(tactics)
            )

        elif obj_type == "relationship":
            relationships.append(obj)

    # STEP 4: Save to database
    print()
    print("[4/4] Saving to database...")

    try:
        # Merge actors with changelog tracking
        for id, actor in actors.items():
            existing_actor = ThreatActor.query.get(id)
            
            if existing_actor:
                # Update existing actor and track changes
                changes = []
                
                # List of fields to track
                fields_to_track = [
                    'name', 'description', 'aliases', 'origin_countries', 
                    'victim_sectors', 'victim_countries', 'motivation', 
                    'motivations', 'associated_malware', 'target_entities', 
                    'popularity', 'knowledge_base_url', 'badges', 
                    'first_seen_at', 'feedly_id', 'attribution_confidence', 
                    'type_of_incident', 'actor_references', 'related_actors'
                ]
                
                for field in fields_to_track:
                    old_val = getattr(existing_actor, field)
                    new_val = getattr(actor, field)
                    
                    # Normalize for comparison (handle None vs empty string/list)
                    if old_val != new_val:
                        # Create changelog entry
                        change = Changelog(
                            actor_id=id,
                            field_name=field,
                            old_value=str(old_val),
                            new_value=str(new_val),
                            action='update'
                        )
                        db.session.add(change)
                        # Update the field
                        setattr(existing_actor, field, new_val)
                
            else:
                # New actor
                db.session.add(actor)
                # Log creation
                change = Changelog(
                    actor_id=id,
                    field_name='all',
                    old_value=None,
                    new_value='Created',
                    action='create'
                )
                db.session.add(change)

        # Merge TTPs (Simple merge for now, TTPs are static from MITRE mostly)
        for id, ttp in ttps.items():
            db.session.merge(ttp)

        db.session.commit()
        print(f"[SUCCESS] Saved {len(actors)} actors and {len(ttps)} TTPs")

        # Process Relationships
        print(f"[INFO] Processing {len(relationships)} relationships...")
        ttp_links_added = 0

        for rel in relationships:
            source_ref = rel.get("source_ref")
            target_ref = rel.get("target_ref")

            if source_ref in actors and target_ref in ttps:
                # We need to fetch the persistent object from the session or DB
                # because 'actors' dict holds transient objects for new ones
                actor = ThreatActor.query.get(source_ref) 
                ttp = TTP.query.get(target_ref)

                if actor and ttp and ttp not in actor.ttps:
                    actor.ttps.append(ttp)
                    ttp_links_added += 1

        db.session.commit()
        print(f"[SUCCESS] Linked {ttp_links_added} TTPs to actors")

        # Final summary
        print()
        print("=" * 70)
        print("INGESTION SUMMARY")
        print("=" * 70)
        print(f"Malpedia API calls:            1")
        print(f"Total MITRE actors found:      {total_mitre_actors}")
        print(f"Feedly API calls made:         {feedly_calls_made}")
        print(f"Actors enriched & saved:       {actors_enriched}")
        print(f"Actors skipped (not in Malpedia): {actors_skipped_not_in_malpedia}")
        print(f"Actors skipped (limit reached): {actors_skipped_limit_reached}")
        print(f"TTPs linked:                   {ttp_links_added}")
        print(f"Rate limit hit:                {'YES - Stopped early' if rate_limit_hit else 'No'}")
        print("=" * 70)
        print()

        if actors_enriched > 0:
            print(f"[SUCCESS] Ingestion complete! {actors_enriched} actors ready to view.")
        else:
            print(f"[WARNING] No actors were enriched. Check logs above for errors.")

    except Exception as e:
        print(f"[ERROR] Database error: {e}")
        db.session.rollback()
