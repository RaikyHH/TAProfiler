import json
import os
import requests
from models.models import ThreatActor, TTP
from database import db
from services.http_client import safe_post, get_global_session

# Get reusable session with proxy support
_session = get_global_session()

def get_relevant_actors(user_profile):
    """
    Find actors that target the user's sector or country.
    """
    if not user_profile:
        return []

    relevant_actors = []
    all_actors = ThreatActor.query.all()

    user_sector = user_profile.sector
    user_country = user_profile.country

    for actor in all_actors:
        victim_sectors = json.loads(actor.victim_sectors)
        victim_countries = json.loads(actor.victim_countries)

        is_relevant = False

        # Check sector match
        if user_sector and user_sector in victim_sectors:
            is_relevant = True

        # Check country match (if they attack the user's country)
        if user_country and user_country in victim_countries:
            is_relevant = True

        if is_relevant:
            relevant_actors.append(actor)

    return relevant_actors

def fetch_ttps_from_feedly(actors):
    """
    Make ONE Feedly API call to get TTPs for all relevant actors.
    Returns a list of rows with TTP data and associated actors.
    """
    if not actors:
        return []

    # Get Feedly API token
    api_token = os.getenv('FEEDLY_API_TOKEN')
    if not api_token:
        print("[ERROR] FEEDLY_API_TOKEN not set in .env")
        return []

    # Collect all Feedly entity IDs from relevant actors
    threat_layer = []
    for actor in actors:
        if actor.feedly_id:
            threat_layer.append(actor.feedly_id)

    if not threat_layer:
        print("[WARNING] No Feedly IDs found for relevant actors")
        return []

    # Build payload for Feedly TTP Dashboard API
    # threatLayers is a list of lists. We put all our actors in one layer.
    payload = {
        "threatLayers": [threat_layer],
        "period": {
            "type": "Last3Months",
            "label": "Last 3 Months"
        }
    }

    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "Authorization": f"Bearer {api_token}"
    }

    url = "https://api.feedly.com/v3/trends/ttp-dashboard"

    print(f"[INFO] Calling Feedly TTP Dashboard API for {len(threat_layer)} actors...")
    response = safe_post(url, json_data=payload, headers=headers, timeout=60, session=_session)

    if response:
        try:
            data = response.json()
            rows = data.get('rows', [])
            print(f"[INFO] Retrieved {len(rows)} TTPs from Feedly")
            return rows
        except Exception as e:
            print(f"[ERROR] Failed to parse Feedly TTP Dashboard response: {e}")
            return []
    else:
        print(f"[ERROR] Feedly TTP Dashboard API call failed (check proxy settings if configured)")
        return []

def export_ttps_json(actors):
    """
    Export TTPs for a list of actors as MITRE ATT&CK Navigator layer JSON.
    Makes ONE Feedly API call to get all TTPs and generates a layer file.
    """
    # Fetch TTP data from Feedly
    ttp_rows = fetch_ttps_from_feedly(actors)

    if not ttp_rows:
        print("[WARNING] No TTP data retrieved from Feedly, using database TTPs")
        # Fallback to database TTPs if Feedly call fails
        return export_ttps_from_database(actors)

    # Load the layer template
    layer_template_path = os.path.join(os.path.dirname(__file__), '..', 'layer.json')
    try:
        with open(layer_template_path, 'r') as f:
            layer_data = json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load layer.json template: {e}")
        return {}

    # Build technique score mapping: {mitre_id: {actors: set(), tactics: set()}}
    technique_map = {}

    for row in ttp_rows:
        ttp = row.get('ttp', {})
        mitre_id = ttp.get('mitreId')

        if not mitre_id:
            continue

        # Initialize if not present
        if mitre_id not in technique_map:
            technique_map[mitre_id] = {
                'actors': set(),
                'tactics': set(),
                'name': ttp.get('name', '')
            }

        # Add actors using this TTP
        actors_list = row.get('actors', [])
        for actor in actors_list:
            technique_map[mitre_id]['actors'].add(actor.get('label', ''))

    # Query database to get tactic information for all MITRE IDs at once
    mitre_ids = list(technique_map.keys())
    if mitre_ids:
        # Optimize: Fetch all relevant TTPs in one query
        db_ttps = TTP.query.filter(TTP.mitre_id.in_(mitre_ids)).all()
        
        for ttp_obj in db_ttps:
            if ttp_obj.mitre_id in technique_map and ttp_obj.tactics:
                try:
                    tactics = json.loads(ttp_obj.tactics)
                    # Tactics are stored as list of strings in DB (e.g. ["execution"])
                    for tactic in tactics:
                        if isinstance(tactic, str):
                            technique_map[ttp_obj.mitre_id]['tactics'].add(tactic)
                        elif isinstance(tactic, dict) and 'phase_name' in tactic:
                            # Handle legacy format if any
                            phase_name = tactic['phase_name'].replace('mitre-attack:', '')
                            technique_map[ttp_obj.mitre_id]['tactics'].add(phase_name)
                except Exception as e:
                    print(f"[ERROR] Failed to parse tactics for {ttp_obj.mitre_id}: {e}")

    # Build techniques array for layer JSON
    techniques = []
    green_color = "#31a354"

    for mitre_id, data in technique_map.items():
        score = len(data['actors'])  # Score = number of actors using this technique

        # If we have tactics, create one entry per tactic
        if data['tactics']:
            for tactic in data['tactics']:
                techniques.append({
                    "techniqueID": mitre_id,
                    "tactic": tactic,
                    "score": score,
                    "color": green_color,
                    "comment": "",
                    "enabled": True,
                    "metadata": [],
                    "links": [],
                    "showSubtechniques": False
                })
        else:
            # No tactic info, create entry without tactic
            techniques.append({
                "techniqueID": mitre_id,
                "score": score,
                "color": green_color,
                "comment": "",
                "enabled": True,
                "metadata": [],
                "links": [],
                "showSubtechniques": False
            })

    # Update layer data with techniques
    layer_data['techniques'] = techniques
    layer_data['name'] = "Relevant Threat Actor TTPs"
    layer_data['description'] = f"TTPs used by {len(actors)} relevant threat actors based on Feedly intelligence"

    return layer_data

def export_ttps_from_database(actors):
    """
    Fallback: Export TTPs using database relationships (old method).
    """
    # Load the layer template
    layer_template_path = os.path.join(os.path.dirname(__file__), '..', 'layer.json')
    try:
        with open(layer_template_path, 'r') as f:
            layer_data = json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load layer.json template: {e}")
        return {}

    # Build technique score mapping from database
    technique_map = {}

    for actor in actors:
        for ttp in actor.ttps:
            if ttp.mitre_id not in technique_map:
                technique_map[ttp.mitre_id] = {
                    'count': 0,
                    'tactics': set()
                }

            technique_map[ttp.mitre_id]['count'] += 1

            # Extract tactics
            if ttp.tactics:
                try:
                    tactics = json.loads(ttp.tactics)
                    for tactic in tactics:
                        if isinstance(tactic, str):
                            technique_map[ttp.mitre_id]['tactics'].add(tactic)
                        elif isinstance(tactic, dict) and 'phase_name' in tactic:
                            phase_name = tactic['phase_name'].replace('mitre-attack:', '')
                            technique_map[ttp.mitre_id]['tactics'].add(phase_name)
                except:
                    pass

    # Build techniques array
    techniques = []
    green_color = "#31a354"

    for mitre_id, data in technique_map.items():
        if data['tactics']:
            for tactic in data['tactics']:
                techniques.append({
                    "techniqueID": mitre_id,
                    "tactic": tactic,
                    "score": data['count'],
                    "color": green_color,
                    "comment": "",
                    "enabled": True,
                    "metadata": [],
                    "links": [],
                    "showSubtechniques": False
                })
        else:
            techniques.append({
                "techniqueID": mitre_id,
                "score": data['count'],
                "color": green_color,
                "comment": "",
                "enabled": True,
                "metadata": [],
                "links": [],
                "showSubtechniques": False
            })

    layer_data['techniques'] = techniques
    layer_data['name'] = "Relevant Threat Actor TTPs"
    layer_data['description'] = f"TTPs used by {len(actors)} relevant threat actors (from database)"

    return layer_data

def export_ttps_custom(config):
    """
    Export TTPs with custom configuration from the export modal.

    Parameters:
    - actor_ids: List of actor IDs to include
    - tactics: List of tactics to include (filters out unwanted tactics)
    - timeframe: Timeframe selection (all, last_month, last_3_months, etc.)
    - start_date, end_date: Custom date range if timeframe is 'custom'
    - layer_name: Custom name for the layer
    - layer_description: Custom description
    - color_scheme: Color scheme (green, red, blue, yellow, gradient)
    - show_subtechniques: Boolean
    - aggregate_scores: Boolean (count actors per technique)
    - include_metadata: Boolean (include actor names in comments)
    """
    from datetime import datetime, timedelta

    # Get selected actors
    actor_ids = config.get('actor_ids', [])
    if not actor_ids:
        return {"error": "No actors selected"}

    actors = ThreatActor.query.filter(ThreatActor.id.in_(actor_ids)).all()

    # Determine timeframe for Feedly API call
    timeframe = config.get('timeframe', 'last_3_months')
    period_config = {
        "type": "Last3Months",
        "label": "Last 3 Months"
    }

    if timeframe == 'last_month':
        period_config = {"type": "Last30Days", "label": "Last Month"}
    elif timeframe == 'last_6_months':
        period_config = {"type": "Last6Months", "label": "Last 6 Months"}
    elif timeframe == 'last_year':
        period_config = {"type": "Last12Months", "label": "Last Year"}
    elif timeframe == 'all':
        period_config = {"type": "AllTime", "label": "All Time"}
    elif timeframe == 'custom':
        start_date = config.get('start_date')
        end_date = config.get('end_date')
        if start_date and end_date:
            period_config = {
                "type": "CustomRange",
                "label": f"{start_date} to {end_date}",
                "startDate": start_date,
                "endDate": end_date
            }

    # Fetch TTP data from Feedly
    ttp_rows = fetch_ttps_from_feedly_custom(actors, period_config)

    if not ttp_rows:
        print("[WARNING] No TTP data retrieved from Feedly, using database TTPs instead")
        # Fallback to database TTPs
        ttp_rows = []
        for actor in actors:
            for ttp in actor.ttps:
                # Convert database TTP to Feedly-like format
                ttp_row = {
                    'ttp': {
                        'mitreId': ttp.mitre_id,
                        'name': ttp.name,
                        'tactics': json.loads(ttp.tactics) if ttp.tactics else []
                    },
                    'actors': [{
                        'label': actor.name,
                        'id': f'nlp/f/entity/gz:ta:{actor.id}'
                    }]
                }
                ttp_rows.append(ttp_row)
        print(f"[INFO] Using {len(ttp_rows)} TTPs from database")

    # Load layer template
    layer_template_path = os.path.join(os.path.dirname(__file__), '..', 'layer.json')
    try:
        with open(layer_template_path, 'r') as f:
            layer_data = json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load layer.json template: {e}")
        return {}

    # Get configuration options
    selected_tactics = set(config.get('tactics', []))
    show_subtechniques = config.get('show_subtechniques', True)
    aggregate_scores = config.get('aggregate_scores', True)
    include_metadata = config.get('include_metadata', False)

    # Build technique map
    technique_map = {}

    for row in ttp_rows:
        ttp = row.get('ttp', {})
        mitre_id = ttp.get('mitreId')

        if not mitre_id:
            continue

        if mitre_id not in technique_map:
            technique_map[mitre_id] = {
                'actors': set(),
                'tactics': set(),
                'name': ttp.get('name', ''),
                'actor_list': []
            }

        # Add actors using this TTP
        actors_list = row.get('actors', [])
        for actor in actors_list:
            actor_name = actor.get('label', '')
            technique_map[mitre_id]['actors'].add(actor_name)
            if include_metadata:
                technique_map[mitre_id]['actor_list'].append(actor_name)

    # Query database for tactic information
    mitre_ids = list(technique_map.keys())
    if mitre_ids:
        db_ttps = TTP.query.filter(TTP.mitre_id.in_(mitre_ids)).all()

        for ttp_obj in db_ttps:
            if ttp_obj.mitre_id in technique_map and ttp_obj.tactics:
                try:
                    tactics = json.loads(ttp_obj.tactics)
                    for tactic in tactics:
                        if isinstance(tactic, str):
                            technique_map[ttp_obj.mitre_id]['tactics'].add(tactic)
                        elif isinstance(tactic, dict) and 'phase_name' in tactic:
                            phase_name = tactic['phase_name'].replace('mitre-attack:', '')
                            technique_map[ttp_obj.mitre_id]['tactics'].add(phase_name)
                except Exception as e:
                    print(f"[ERROR] Failed to parse tactics for {ttp_obj.mitre_id}: {e}")

    # Build techniques array with filtering
    techniques = []

    # Build technique entries
    for mitre_id, data in technique_map.items():
        score = len(data['actors']) if aggregate_scores else 1

        # Build comment with actor metadata
        comment = ""
        if include_metadata and data['actor_list']:
            comment = f"Used by: {', '.join(sorted(data['actor_list']))}"

        # Filter by selected tactics
        tactics_to_use = data['tactics'].intersection(selected_tactics) if selected_tactics else data['tactics']

        if tactics_to_use:
            for tactic in tactics_to_use:
                techniques.append({
                    "techniqueID": mitre_id,
                    "tactic": tactic,
                    "score": score,
                    "comment": comment,
                    "enabled": True,
                    "metadata": [],
                    "links": [],
                    "showSubtechniques": show_subtechniques
                })
        elif not selected_tactics:
            # No tactic filtering, include without tactic
            techniques.append({
                "techniqueID": mitre_id,
                "score": score,
                "comment": comment,
                "enabled": True,
                "metadata": [],
                "links": [],
                "showSubtechniques": show_subtechniques
            })

    # Update layer metadata
    layer_data['techniques'] = techniques
    layer_data['name'] = config.get('layer_name', 'Threat Actor TTPs')
    layer_data['description'] = config.get('layer_description', f'TTPs from {len(actors)} threat actors')

    # Add gradient configuration if using gradient colors
    if color_scheme == 'gradient':
        layer_data['gradient'] = {
            "colors": ["#fdd835", "#fb8c00", "#e53935"],
            "minValue": 0,
            "maxValue": max_score
        }

    return layer_data

def fetch_ttps_from_feedly_custom(actors, period_config):
    """
    Fetch TTPs from Feedly with custom period configuration.
    """
    if not actors:
        return []

    api_token = os.getenv('FEEDLY_API_TOKEN')
    if not api_token:
        print("[ERROR] FEEDLY_API_TOKEN not set in .env")
        return []

    # Collect Feedly entity IDs
    threat_layer = []
    for actor in actors:
        if actor.feedly_id:
            threat_layer.append(actor.feedly_id)

    if not threat_layer:
        print("[WARNING] No Feedly IDs found for selected actors")
        return []

    # Build payload
    payload = {
        "threatLayers": [threat_layer],
        "period": period_config
    }

    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "Authorization": f"Bearer {api_token}"
    }

    url = "https://api.feedly.com/v3/trends/ttp-dashboard"

    print(f"[INFO] Calling Feedly TTP Dashboard API for {len(threat_layer)} actors with period: {period_config.get('label')}")
    response = safe_post(url, json_data=payload, headers=headers, timeout=60, session=_session)

    if response:
        try:
            data = response.json()
            rows = data.get('rows', [])
            print(f"[INFO] Retrieved {len(rows)} TTPs from Feedly")
            return rows
        except Exception as e:
            print(f"[ERROR] Failed to parse Feedly TTP Dashboard response: {e}")
            return []
    else:
        print(f"[ERROR] Feedly TTP Dashboard API call failed")
        return []
