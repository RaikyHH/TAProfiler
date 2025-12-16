import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from flask import Flask, render_template, jsonify, request, send_file, Response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from database import init_db, db
from models.models import ThreatActor, OrganizationProfile, Changelog, Settings
from services.analysis_service import get_relevant_actors, export_ttps_json
from services.avatar_service import generate_actor_avatar
import json
import io
import sys

app = Flask(__name__)
# Support both local and Docker database paths
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', 'sqlite:///taprofiler.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Security: Generate secret key for CSRF protection
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or os.urandom(32).hex()

# Security: Set maximum request size to prevent DoS attacks (16MB limit)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Security: Initialize CSRF protection
csrf = CSRFProtect(app)

# Security: Initialize rate limiter to prevent DoS and abuse
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Custom Jinja Filter
@app.template_filter('from_json')
def from_json_filter(s):
    try:
        return json.loads(s) if s else []
    except:
        return []

# Initialize DB
init_db(app)

# Security: Add security headers to all responses
@app.after_request
def set_security_headers(response):
    # Prevent clickjacking attacks
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'

    # Enable XSS protection (for older browsers)
    response.headers['X-XSS-Protection'] = '1; mode=block'

    # Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'

    # Content Security Policy - restrict resource loading
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'"

    # Referrer policy - limit information leakage
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # Permissions policy - disable unnecessary browser features
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'

    # Strict transport security (HSTS) - force HTTPS (only enable in production with HTTPS)
    # response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    # Security: Limit response size to prevent DoS (32MB limit for responses)
    if response.content_length and response.content_length > 32 * 1024 * 1024:
        return jsonify({'error': 'Response too large. Please refine your query.'}), 413

    return response

# Security: Error handler for request too large
@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({'error': 'Request payload too large. Maximum size is 16MB.'}), 413

# Security: Validate JSON depth to prevent DoS via deeply nested structures
@app.before_request
def validate_json_request():
    if request.is_json and request.method in ['POST', 'PUT', 'PATCH']:
        try:
            # Set recursion limit for JSON parsing
            original_limit = sys.getrecursionlimit()
            sys.setrecursionlimit(100)  # Limit JSON nesting depth

            # Try to parse JSON - will fail if too deeply nested
            _ = request.get_json(force=True)

            # Restore original limit
            sys.setrecursionlimit(original_limit)
        except RecursionError:
            sys.setrecursionlimit(1000)  # Restore to safe default
            return jsonify({'error': 'JSON payload too deeply nested. Maximum depth is 100 levels.'}), 400
        except Exception as e:
            sys.setrecursionlimit(1000)  # Restore to safe default
            # Let other errors pass through to be handled normally
            pass

@app.route('/')
def index():
    # Pass unique values for filters to the template
    all_actors = ThreatActor.query.all()
    origins = set()
    victim_sectors = set()
    victim_countries = set()
    motivations = set()
    badges = set()
    malware = set()

    for actor in all_actors:
        try:
            # Origin countries
            for o in json.loads(actor.origin_countries):
                if o and o != "Unknown": origins.add(o)

            # Victim sectors
            for s in json.loads(actor.victim_sectors):
                if s and s != "Unknown": victim_sectors.add(s)

            # Victim countries
            for c in json.loads(actor.victim_countries):
                if c and c != "Unknown": victim_countries.add(c)

            # Motivations (from Feedly - more detailed)
            feedly_motivations = json.loads(actor.motivations) if actor.motivations else []
            for m in feedly_motivations:
                if m: motivations.add(m)

            # Badges (sources like MALPEDIA, MISP)
            actor_badges = json.loads(actor.badges) if actor.badges else []
            for b in actor_badges:
                if b: badges.add(b)

            # Associated malware
            malware_list = json.loads(actor.associated_malware) if actor.associated_malware else []
            for mal in malware_list:
                if isinstance(mal, dict) and 'label' in mal:
                    malware.add(mal['label'])
        except Exception as e:
            print(f"Error processing actor filters: {e}")
            pass

    return render_template('index.html',
                           origins=sorted(list(origins)),
                           victim_sectors=sorted(list(victim_sectors)),
                           victim_countries=sorted(list(victim_countries)),
                           motivations=sorted(list(motivations)),
                           badges=sorted(list(badges)),
                           malware=sorted(list(malware)))

def apply_actor_filters(actors, request_args):
    # Get all filter parameters
    target_origins = request_args.getlist('origin')
    target_victim_sectors = request_args.getlist('victim_sector')
    target_victim_countries = request_args.getlist('victim_country')
    target_motivations = request_args.getlist('motivation')
    target_badges = request_args.getlist('badge')
    target_malware = request_args.getlist('malware')
    min_popularity = request_args.get('min_popularity', type=int)
    max_popularity = request_args.get('max_popularity', type=int)
    search_query = request_args.get('search', '').lower()

    filtered_results = []

    for actor in actors:
        # Search filter (name or aliases)
        if search_query:
            actor_name = actor.name.lower()
            # Security fix: Handle null values before JSON parsing
            actor_aliases = [a.lower() for a in json.loads(actor.aliases)] if actor.aliases else []
            if search_query not in actor_name and not any(search_query in alias for alias in actor_aliases):
                continue

        # Origin Filter (OR logic: if actor has ANY of the selected origins)
        if target_origins:
            # Security fix: Handle null values before JSON parsing
            actor_origins = json.loads(actor.origin_countries) if actor.origin_countries else []
            if not any(o in actor_origins for o in target_origins):
                continue

        # Victim Sector Filter (OR logic)
        if target_victim_sectors:
            # Security fix: Handle null values before JSON parsing
            actor_sectors = json.loads(actor.victim_sectors) if actor.victim_sectors else []
            if not any(s in actor_sectors for s in target_victim_sectors):
                continue

        # Victim Country Filter (OR logic)
        if target_victim_countries:
            # Security fix: Handle null values before JSON parsing
            actor_countries = json.loads(actor.victim_countries) if actor.victim_countries else []
            if not any(c in actor_countries for c in target_victim_countries):
                continue

        # Motivation Filter (OR logic - check Feedly motivations)
        if target_motivations:
            actor_motivations = json.loads(actor.motivations) if actor.motivations else []
            if not any(m in actor_motivations for m in target_motivations):
                continue

        # Badge Filter (OR logic)
        if target_badges:
            actor_badges = json.loads(actor.badges) if actor.badges else []
            if not any(b in actor_badges for b in target_badges):
                continue

        # Malware Filter (OR logic)
        if target_malware:
            malware_list = json.loads(actor.associated_malware) if actor.associated_malware else []
            actor_malware_labels = [m['label'] for m in malware_list if isinstance(m, dict) and 'label' in m]
            if not any(m in actor_malware_labels for m in target_malware):
                continue

        # Popularity range filter
        if min_popularity is not None and (not actor.popularity or actor.popularity < min_popularity):
            continue
        if max_popularity is not None and (not actor.popularity or actor.popularity > max_popularity):
            continue

        filtered_results.append(actor)

    return filtered_results

@app.route('/api/actors')
@limiter.limit("10 per minute")
def get_actors():
    query = ThreatActor.query
    actors = query.all()
    filtered_actors = apply_actor_filters(actors, request.args)
    # Sort by popularity descending
    filtered_actors.sort(key=lambda x: x.popularity or 0, reverse=True)
    return jsonify({"actors": [a.to_dict() for a in filtered_actors]})

@app.route('/actor/<actor_id>/avatar.svg')
def actor_avatar(actor_id):
    actor = ThreatActor.query.get_or_404(actor_id)
    svg = generate_actor_avatar(actor)
    return Response(svg, mimetype='image/svg+xml')

def sort_references_by_trust(references, trusted_domains):
    """Sort references by trusted domain priority"""
    if not references or not trusted_domains:
        return references

    def get_domain_priority(url):
        """Get priority score for URL based on trusted domains (lower is better)"""
        try:
            from urllib.parse import urlparse
            domain = urlparse(url).netloc
            # Remove www. prefix
            domain = domain.replace('www.', '')

            # Check if domain matches any trusted domain
            for idx, trusted_domain in enumerate(trusted_domains):
                if trusted_domain in domain or domain in trusted_domain:
                    return idx  # Lower index = higher priority
            return len(trusted_domains)  # Untrusted domains go last
        except:
            return len(trusted_domains)  # On error, treat as untrusted

    return sorted(references, key=get_domain_priority)

@app.route('/actor/<actor_id>')
def actor_profile(actor_id):
    actor = ThreatActor.query.get_or_404(actor_id)
    changelog = Changelog.query.filter_by(actor_id=actor_id).order_by(Changelog.timestamp.desc()).all()

    # Get trusted domains and sort references
    settings_obj = Settings.query.first()
    trusted_domains = []
    if settings_obj and settings_obj.trusted_domains:
        trusted_domains = json.loads(settings_obj.trusted_domains)

    # Sort actor references by trusted domains
    actor_refs = json.loads(actor.actor_references) if actor.actor_references else []
    sorted_refs = sort_references_by_trust(actor_refs, trusted_domains)

    return render_template('actor_profile.html', actor=actor, changelog=changelog, sorted_references=sorted_refs)

@app.route('/changelog')
def global_changelog():
    # Join with ThreatActor to get actor names
    logs = db.session.query(Changelog, ThreatActor.name).join(ThreatActor, Changelog.actor_id == ThreatActor.id).order_by(Changelog.timestamp.desc()).all()
    return render_template('changelog.html', logs=logs)

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    profile = OrganizationProfile.query.first()
    if not profile:
        profile = OrganizationProfile(id=1, name="", sector="", country="")
        db.session.add(profile)
        db.session.commit()

    # Get trusted domains settings
    settings_obj = Settings.query.first()
    if not settings_obj:
        settings_obj = Settings(id=1, trusted_domains='[]')
        db.session.add(settings_obj)
        db.session.commit()

    trusted_domains = json.loads(settings_obj.trusted_domains) if settings_obj.trusted_domains else []
    trusted_domains_text = '\n'.join(trusted_domains)

    if request.method == 'POST':
        data = request.form
        profile.name = data.get('name')
        profile.sector = data.get('sector')
        profile.country = data.get('country')
        db.session.commit()
        return render_template('settings.html', profile=profile, trusted_domains_text=trusted_domains_text, saved=True)

    return render_template('settings.html', profile=profile, trusted_domains_text=trusted_domains_text)

@app.route('/settings/trusted-domains', methods=['POST'])
def update_trusted_domains():
    settings_obj = Settings.query.first()
    if not settings_obj:
        settings_obj = Settings(id=1)
        db.session.add(settings_obj)

    # Parse textarea input - one domain per line
    domains_text = request.form.get('trusted_domains', '')
    domains = [line.strip() for line in domains_text.split('\n') if line.strip()]

    settings_obj.trusted_domains = json.dumps(domains)
    db.session.commit()

    # Redirect back to settings with success message
    profile = OrganizationProfile.query.first()
    if not profile:
        profile = OrganizationProfile(id=1, name="", sector="", country="")
        db.session.add(profile)
        db.session.commit()

    trusted_domains_text = '\n'.join(domains)
    return render_template('settings.html', profile=profile, trusted_domains_text=trusted_domains_text, saved=True)

@app.route('/api/relevant_actors')
@limiter.limit("10 per minute")
def relevant_actors():
    profile = OrganizationProfile.query.first()
    actors = get_relevant_actors(profile)
    # Apply the same filters to relevant actors
    filtered_actors = apply_actor_filters(actors, request.args)
    # Sort by popularity descending
    filtered_actors.sort(key=lambda x: x.popularity or 0, reverse=True)
    return jsonify({"actors": [a.to_dict() for a in filtered_actors]})

@app.route('/api/export_ttps', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
@csrf.exempt
def export_ttps():
    if request.method == 'POST':
        # New enhanced export with custom parameters
        from services.analysis_service import export_ttps_custom

        payload = request.get_json()
        data = export_ttps_custom(payload)

        # Create in-memory file
        mem = io.BytesIO()
        mem.write(json.dumps(data, indent=2).encode('utf-8'))
        mem.seek(0)

        return send_file(mem, as_attachment=True, download_name='mitre_attack_layer.json', mimetype='application/json')
    else:
        # Legacy GET endpoint - export relevant actors
        profile = OrganizationProfile.query.first()
        actors = get_relevant_actors(profile)
        data = export_ttps_json(actors)

        # Create in-memory file
        mem = io.BytesIO()
        mem.write(json.dumps(data, indent=2).encode('utf-8'))
        mem.seek(0)

        return send_file(mem, as_attachment=True, download_name='relevant_ttps.json', mimetype='application/json')

if __name__ == '__main__':
    # Data enrichment is now handled by the separate TA-Enricher container
    # No background threading needed here

    # Security: For production deployment, use a production WSGI server (gunicorn, waitress)
    # with TLS 1.2+ enforcement. Example gunicorn command:
    # gunicorn --bind 0.0.0.0:5000 --certfile=cert.pem --keyfile=key.pem --ssl-version=TLSv1_2 app:app

    # Get host and debug mode from environment
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    debug = os.environ.get('FLASK_ENV', 'production') == 'development'

    app.run(host=host, debug=debug, port=5000)
