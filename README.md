# TA Profiler

> A threat actor profiling tool that pulls data from MITRE ATT&CK, Feedly, and Malpedia to help you track bad guys relevant to your org.

![Python](https://img.shields.io/badge/Python-3.11+-green) ![Docker](https://img.shields.io/badge/Docker-Ready-blue) ![Security](https://img.shields.io/badge/Security-B+-yellow)

## What is this?

Basically, I got tired of manually tracking threat actors across different sources, so I built this. It automatically fetches threat intel from MITRE ATT&CK and enriches it with Feedly's real-time data. You get a nice dashboard showing which threat actors you should actually care about based on your industry and location.

## Features

- **Auto-synced threat intel** - Pulls from MITRE ATT&CK, Malpedia, and Feedly
- **Smart filtering** - Shows threats relevant to YOUR org (configurable by sector/country)
- **3 view modes** - Cards, compact, or list view
- **Actor profiles** - Full breakdowns with TTPs, malware, targets, and references
- **TTP exports** - Generate MITRE ATT&CK Navigator layers with custom filters
- **Trusted sources** - Sort references by trusted domains you configure
- **Change tracking** - See when actor profiles were last updated
- **Proxy support** - Works behind corporate firewalls
- **Security hardened** - CSRF protection, rate limiting, security headers

## Quick Start

### Docker (easiest way)

You'll need Docker and a [Feedly Enterprise API token](https://feedly.com/i/team/api).

```bash
# Clone and setup
git clone <your-repo>
cd TAProfiler
cp .env.docker.example .env

# Edit .env and add your Feedly token
nano .env

# Run it
./start.sh
```

Then open http://localhost:5000

The enricher will fetch all the data on first run (takes a few minutes), then exit. Set up a cron job to sync daily:

```bash
# Add to crontab (crontab -e)
0 2 * * * cd /path/to/TAProfiler && docker-compose up enricher >> /var/log/ta-enricher.log 2>&1
```

### Local Development

```bash
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your Feedly token
python ingest_data.py  # Initial data fetch
python app.py
```

## Configuration

Copy `.env.example` to `.env` and set these:

```bash
FEEDLY_API_TOKEN=your_token_here        # Required - get from Feedly
MAX_ACTORS_TO_ENRICH=0                  # 0 = all actors, or set a limit for testing
ENRICHER_MODE=once                      # 'once' for cron, 'scheduled' for 24h loop

# Optional proxy config
HTTP_PROXY=http://proxy.company.com:8080
HTTPS_PROXY=http://proxy.company.com:8080
```

## Usage

### First time setup

1. Open http://localhost:5000
2. Click "Configure Organization Profile"
3. Select your industry and country
4. The dashboard now shows relevant threats

### Filtering threats

Use the sidebar to filter by:
- Origin country
- Target sector/country
- Motivation (espionage, financial, etc.)
- Associated malware
- Data sources (MALPEDIA, MISP badges)

### Exporting TTPs

Click "Export TTP Matrix" to generate a heatmap for MITRE ATT&CK Navigator:
- Choose which actors to include
- Set timeframe (last month, 3 months, etc.)
- Pick a color scheme
- Enable/disable tactics
- Import the JSON into [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

### Trusted reference sources

Go to Settings and add domains you trust (one per line):
```
malpedia.caad.fkie.fraunhofer.de
attack.mitre.org
securelist.com
```

Actor profile references will be sorted with trusted sources first.

## Architecture

Two containers:
- **Webapp** - Flask app running on port 5000 (persistent, read-only DB access)
- **Enricher** - Runs once to sync data, then exits (schedule with cron)

Both share a SQLite database stored in a Docker volume.

Data flow:
1. Enricher fetches MITRE ATT&CK actors
2. Gets UUIDs from Malpedia (single API call, ~864 actors)
3. Enriches each actor with Feedly threat intel
4. Saves everything to SQLite
5. Webapp reads from DB (read-only for security)

All API responses are cached locally to speed up subsequent runs.



All good for production use. If you want HTTPS, stick nginx in front and uncomment the HSTS header in `app.py`.

## Troubleshooting

### No data showing up

```bash
# Check if enricher ran
docker-compose logs enricher | grep "INGESTION SUMMARY"

# Run it manually
docker-compose up enricher

# Check database
docker-compose run --rm enricher python -c "from database import *; from models.models import *; app.app_context().push(); print(f'Actors: {ThreatActor.query.count()}')"
```

### Feedly errors

- Make sure you have Enterprise tier (basic won't work)
- Verify your token is valid
- Try limiting actors for testing: `MAX_ACTORS_TO_ENRICH=50`
- Check proxy settings if you're behind a firewall

### Docker issues

```bash
# Restart everything
docker-compose down
docker-compose build
docker-compose up -d webapp
docker-compose up enricher

# Nuke everything and start fresh
docker-compose down -v
docker-compose up -d webapp
docker-compose up enricher
```

## Useful Commands

```bash
# View logs
docker-compose logs -f webapp
docker-compose logs enricher

# Manual data sync
docker-compose up enricher

# Backup database
docker cp ta-enricher:/data/taprofiler.db ./backup-$(date +%Y%m%d).db

# Update app
git pull
docker-compose down
docker-compose build
docker-compose up -d

# Database migration (if schema changes)
docker-compose run --rm enricher python migrate_database.py
```

## Data Sources

- **MITRE ATT&CK** - Official STIX repository for actor TTPs
- **Malpedia** - 864 threat actors with UUIDs and malware associations
- **Feedly** - Real-time threat intel (Enterprise API required)

First run fetches everything and caches locally. Subsequent runs use cache for speed.

## API Rate Limits

- Malpedia: 1 call per sync (gets all actors at once)
- Feedly: 2-second delay between calls, handles 429 errors
- MITRE: No limit (public repo)

For testing, set `MAX_ACTORS_TO_ENRICH=50`. For production, set it to `0` (unlimited).

## Project Structure

```
TAProfiler/
├── app.py              # Flask webapp
├── enricher.py         # Data sync service
├── docker-compose.yml  # Container setup
├── requirements.txt    # Python deps
├── models/             # Database models
├── services/           # Business logic (API clients)
├── templates/          # HTML
└── static/             # CSS/JS
```

## Contributing

PRs welcome! Just:
1. Fork it
2. Make your changes
3. Test it
4. Send a PR

## License

MIT - do whatever you want with it

## Credits

Built with MITRE ATT&CK, Feedly, Malpedia, Flask, and SQLAlchemy


