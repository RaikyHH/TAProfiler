from database import db
import json

# Association table for Actor <-> TTP
actor_ttp = db.Table('actor_ttp',
    db.Column('actor_id', db.String, db.ForeignKey('threat_actor.id'), primary_key=True),
    db.Column('ttp_id', db.String, db.ForeignKey('ttp.id'), primary_key=True)
)

class ThreatActor(db.Model):
    id = db.Column(db.String, primary_key=True) # STIX ID
    name = db.Column(db.String, nullable=False)
    description = db.Column(db.Text)
    aliases = db.Column(db.Text) # JSON string
    origin_countries = db.Column(db.Text) # JSON string
    victim_sectors = db.Column(db.Text) # JSON string (enriched or inferred)
    victim_countries = db.Column(db.Text) # JSON string
    motivation = db.Column(db.String)

    # Enhanced Feedly fields
    motivations = db.Column(db.Text) # JSON array of motivations
    associated_malware = db.Column(db.Text) # JSON array of malware objects
    target_entities = db.Column(db.Text) # JSON array of specific targets
    popularity = db.Column(db.Integer) # Feedly popularity score
    knowledge_base_url = db.Column(db.String) # Malpedia or other reference URL
    badges = db.Column(db.Text) # JSON array of badges (MALPEDIA, MISP, etc.)
    first_seen_at = db.Column(db.String) # ISO date string
    feedly_id = db.Column(db.String) # Feedly entity ID for future lookups
    
    # Malpedia Enrichment Fields
    attribution_confidence = db.Column(db.String)
    type_of_incident = db.Column(db.Text) # JSON array
    actor_references = db.Column(db.Text) # JSON array
    related_actors = db.Column(db.Text) # JSON array

    # Relationships
    ttps = db.relationship('TTP', secondary=actor_ttp, lazy='subquery',
        backref=db.backref('actors', lazy=True))

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "aliases": json.loads(self.aliases) if self.aliases else [],
            "origin_countries": json.loads(self.origin_countries) if self.origin_countries else [],
            "victim_sectors": json.loads(self.victim_sectors) if self.victim_sectors else [],
            "victim_countries": json.loads(self.victim_countries) if self.victim_countries else [],
            "motivation": self.motivation,
            "motivations": json.loads(self.motivations) if self.motivations else [],
            "associated_malware": json.loads(self.associated_malware) if self.associated_malware else [],
            "target_entities": json.loads(self.target_entities) if self.target_entities else [],
            "popularity": self.popularity,
            "knowledge_base_url": self.knowledge_base_url,
            "badges": json.loads(self.badges) if self.badges else [],
            "first_seen_at": self.first_seen_at,
            "feedly_id": self.feedly_id,
            "attribution_confidence": self.attribution_confidence,
            "type_of_incident": json.loads(self.type_of_incident) if self.type_of_incident else [],
            "references": json.loads(self.actor_references) if self.actor_references else [],
            "related_actors": json.loads(self.related_actors) if self.related_actors else [],
            "ttps": [t.to_dict() for t in self.ttps]
        }

class TTP(db.Model):
    id = db.Column(db.String, primary_key=True) # STIX ID
    mitre_id = db.Column(db.String) # e.g., T1001
    name = db.Column(db.String, nullable=False)
    description = db.Column(db.Text)
    tactics = db.Column(db.Text) # JSON string of kill_chain_phases

    def to_dict(self):
        return {
            "id": self.id,
            "mitre_id": self.mitre_id,
            "name": self.name,
            "description": self.description,
            "tactics": json.loads(self.tactics) if self.tactics else []
        }

class OrganizationProfile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)
    sector = db.Column(db.String)
    country = db.Column(db.String)
    
    def to_dict(self):
        return {
            "name": self.name,
            "sector": self.sector,
            "country": self.country
        }

class Changelog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    actor_id = db.Column(db.String, db.ForeignKey('threat_actor.id'))
    field_name = db.Column(db.String)
    old_value = db.Column(db.Text)
    new_value = db.Column(db.Text)
    action = db.Column(db.String) # 'create' or 'update'

    def to_dict(self):
        return {
            "timestamp": self.timestamp.isoformat(),
            "actor_id": self.actor_id,
            "field_name": self.field_name,
            "old_value": self.old_value,
            "new_value": self.new_value,
            "action": self.action
        }

class Settings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    trusted_domains = db.Column(db.Text)  # JSON array of trusted domain names

    def to_dict(self):
        return {
            "trusted_domains": json.loads(self.trusted_domains) if self.trusted_domains else []
        }
