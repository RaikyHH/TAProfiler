// Current view mode (default, compact, list)
let currentView = 'default';

document.addEventListener('DOMContentLoaded', () => {
    // Check if we are on the dashboard
    if (document.getElementById('actors-grid')) {
        loadActors();
        loadRelevantActors();
    }
});

// Switch between view modes
function switchView(view) {
    currentView = view;
    const grid = document.getElementById('actors-grid');
    const relevantGrid = document.getElementById('relevant-grid');

    // Update button states
    document.querySelectorAll('.view-option').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.view === view);
    });

    // Update grid classes
    grid.className = 'grid';
    if (relevantGrid) relevantGrid.className = 'grid';

    if (view === 'compact') {
        grid.classList.add('view-compact');
        if (relevantGrid) relevantGrid.classList.add('view-compact');
    } else if (view === 'list') {
        grid.classList.add('view-list');
        if (relevantGrid) relevantGrid.classList.add('view-list');
    }

    // Re-render current data
    loadActors();
    loadRelevantActors();
}

function getFilterParams() {
    // Collect values from all filter types
    const origins = Array.from(document.querySelectorAll('.origin-cb:checked')).map(cb => cb.value);
    const victimSectors = Array.from(document.querySelectorAll('.victim-sector-cb:checked')).map(cb => cb.value);
    const victimCountries = Array.from(document.querySelectorAll('.victim-country-cb:checked')).map(cb => cb.value);
    const motivations = Array.from(document.querySelectorAll('.motivation-cb:checked')).map(cb => cb.value);
    const malware = Array.from(document.querySelectorAll('.malware-cb:checked')).map(cb => cb.value);
    const badges = Array.from(document.querySelectorAll('.badge-cb:checked')).map(cb => cb.value);

    // Get search query
    const searchInput = document.getElementById('search-input');
    const searchQuery = searchInput ? searchInput.value.trim() : '';

    // Get popularity range
    const minPopularity = document.getElementById('min-popularity')?.value;
    const maxPopularity = document.getElementById('max-popularity')?.value;

    // Build query parameters
    const params = new URLSearchParams();
    origins.forEach(v => params.append('origin', v));
    victimSectors.forEach(v => params.append('victim_sector', v));
    victimCountries.forEach(v => params.append('victim_country', v));
    motivations.forEach(v => params.append('motivation', v));
    malware.forEach(v => params.append('malware', v));
    badges.forEach(v => params.append('badge', v));

    if (searchQuery) params.append('search', searchQuery);
    if (minPopularity) params.append('min_popularity', minPopularity);
    if (maxPopularity) params.append('max_popularity', maxPopularity);

    return params;
}

async function loadActors() {
    const grid = document.getElementById('actors-grid');
    grid.innerHTML = '<div class="card" style="grid-column: 1/-1; text-align: center; padding: 3rem;"><p class="text-secondary">Loading threat database...</p></div>';

    const params = getFilterParams();

    try {
        const response = await fetch(`/api/actors?${params.toString()}`);
        const data = await response.json();
        renderGrid(grid, data.actors);
    } catch (error) {
        console.error('Error loading actors:', error);
        grid.innerHTML = '<div class="card" style="grid-column: 1/-1; text-align: center; color: var(--danger);"><p>Error loading data.</p></div>';
    }
}

async function loadRelevantActors() {
    const grid = document.getElementById('relevant-grid');
    if (!grid) return;

    // Add loading state if needed, or just update silently
    // grid.innerHTML = '...'; 

    const params = getFilterParams();

    try {
        const response = await fetch(`/api/relevant_actors?${params.toString()}`);
        const data = await response.json();

        if (data.actors.length === 0) {
            // Check if filters are applied to distinguish between "no relevant actors at all" and "filtered out"
            const hasFilters = Array.from(params.keys()).length > 0;

            if (hasFilters) {
                grid.innerHTML = `
                    <div class="card" style="grid-column: 1/-1; text-align: center; padding: 2rem;">
                        <p class="text-secondary">No high priority threats match your filters.</p>
                    </div>
                `;
            } else {
                grid.innerHTML = `
                    <div class="card" style="grid-column: 1/-1; text-align: center; padding: 2rem;">
                        <p class="text-secondary">No high priority threats identified based on your current settings.</p>
                        <a href="/settings" class="btn btn-outline" style="margin-top: 1rem; display: inline-flex;">Configure Organization Profile</a>
                    </div>
                `;
            }
        } else {
            renderGrid(grid, data.actors);
        }
    } catch (error) {
        console.error('Error loading relevant actors:', error);
    }
}

function getIcon(name, size = 16) {
    return `
        <svg width="${size}" height="${size}" class="icon" style="vertical-align: -3px; margin-right: 4px;">
            <use href="#icon-${name}"></use>
        </svg>
    `;
}

// Get country flag emoji (simple mapping)
function getCountryFlag(countryName) {
    const flagMap = {
        'China': '🇨🇳', 'Russia': '🇷🇺', 'North Korea': '🇰🇵', 'Iran': '🇮🇷',
        'United States': '🇺🇸', 'Israel': '🇮🇱', 'India': '🇮🇳', 'Pakistan': '🇵🇰',
        'Vietnam': '🇻🇳', 'Ukraine': '🇺🇦', 'Belarus': '🇧🇾', 'Syria': '🇸🇾',
        'Lebanon': '🇱🇧', 'Palestine': '🇵🇸', 'Turkey': '🇹🇷', 'Saudi Arabia': '🇸🇦',
        'United Arab Emirates': '🇦🇪', 'South Korea': '🇰🇷', 'Japan': '🇯🇵',
        'Germany': '🇩🇪', 'France': '🇫🇷', 'United Kingdom': '🇬🇧', 'Netherlands': '🇳🇱',
        'Unknown': '🌍'
    };
    return flagMap[countryName] || '🌍';
}

function renderGrid(container, actors) {
    container.innerHTML = '';

    if (actors.length === 0) {
        container.innerHTML = '<div class="card" style="grid-column: 1/-1; text-align: center; padding: 2rem;"><p class="text-secondary">No actors found matching criteria.</p></div>';
        return;
    }

    actors.forEach(actor => {
        const card = document.createElement('div');
        card.className = 'actor-card';

        // Safe access to arrays and data
        const sectors = actor.victim_sectors || [];
        const origins = actor.origin_countries || [];
        const motivations = actor.motivations || [];
        const malware = actor.associated_malware || [];
        const popularity = actor.popularity || 0;

        const originText = origins.filter(o => o !== 'Unknown').join(', ') || 'Unknown';
        const primaryOrigin = origins.find(o => o !== 'Unknown') || 'Unknown';
        const countryFlag = getCountryFlag(primaryOrigin);

        // Determine stats for boxes
        const malwareCount = malware.length;
        const sectorCount = sectors.length;

        // Tags
        let tagsHtml = '';
        if (motivations.length > 0) {
            tagsHtml += `<span class="tag purple">${motivations[0]}</span>`;
        }
        if (sectors.length > 0 && sectors[0] !== 'Unknown') {
            tagsHtml += `<span class="tag blue">${sectors[0]}</span>`;
        }

        // Render different content based on current view
        if (currentView === 'compact') {
            card.innerHTML = `
                <div class="actor-header">
                    <div class="actor-avatar">
                        <img src="/actor/${actor.id}/avatar.svg" alt="${actor.name}">
                    </div>
                    <div class="actor-info">
                        <h3>${actor.name}</h3>
                    </div>
                </div>
                <div class="actor-compact-info">
                    <span class="country-flag">${countryFlag}</span>
                    <span>${primaryOrigin}</span><br>
                    <span style="color: var(--text-muted);">Pop: ${popularity}</span>
                </div>
            `;
            card.onclick = () => window.location.href = `/actor/${actor.id}`;
        } else if (currentView === 'list') {
            card.innerHTML = `
                <div class="actor-header">
                    <div class="actor-avatar">
                        <img src="/actor/${actor.id}/avatar.svg" alt="${actor.name}">
                    </div>
                    <div class="actor-info">
                        <h3>${actor.name}</h3>
                        <div class="actor-meta" style="margin-top: 0.25rem; color: var(--text-muted);">${actor.id.split('--')[1] || actor.id}</div>
                    </div>
                </div>
                <div class="actor-body">
                    <div class="actor-stats">
                        <div class="stat-box">
                            <div class="stat-label">${getIcon('globe')} Origin</div>
                            <div class="stat-value">${countryFlag} ${originText}</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-label">${getIcon('flame')} Popularity</div>
                            <div class="stat-value" style="color: ${popularity > 1000 ? 'var(--danger)' : 'var(--success)'}">${popularity}</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-label">${getIcon('bug')} Malware</div>
                            <div class="stat-value">${malwareCount}</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-label">${getIcon('target')} Targets</div>
                            <div class="stat-value">${sectorCount}</div>
                        </div>
                    </div>
                    <div style="display: flex; gap: 0.5rem; align-items: center;">
                        ${tagsHtml}
                    </div>
                </div>
                <a href="/actor/${actor.id}" class="btn btn-outline btn-sm">View</a>
            `;
        } else {
            // Default card view
            card.innerHTML = `
                <div class="actor-header">
                    <div class="actor-avatar">
                        <img src="/actor/${actor.id}/avatar.svg" alt="${actor.name}">
                    </div>
                    <div class="actor-info">
                        <h3>${actor.name}</h3>
                        <div class="actor-meta" style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.25rem;">${actor.id.split('--')[1] || actor.id}</div>
                    </div>
                </div>

                <div class="actor-body">
                    <div class="actor-stats">
                        <div class="stat-box">
                            <div class="stat-label">${getIcon('globe', 14)} Origin</div>
                            <div class="stat-value" style="font-size: 0.85rem;">${originText}</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-label">${getIcon('flame', 14)} Popularity</div>
                            <div class="stat-value" style="font-size: 1.1rem; color: ${popularity > 1000 ? 'var(--danger)' : 'var(--success)'}">${popularity}</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-label">${getIcon('bug', 14)} Malware</div>
                            <div class="stat-value" style="font-size: 0.85rem;">${malwareCount}</div>
                        </div>
                        <div class="stat-box">
                            <div class="stat-label">${getIcon('target', 14)} Targets</div>
                            <div class="stat-value" style="font-size: 0.85rem;">${sectorCount}</div>
                        </div>
                    </div>

                    <div style="margin-top: 0.75rem; display: flex; gap: 0.5rem; flex-wrap: wrap;">
                        ${tagsHtml}
                    </div>
                </div>

                <a href="/actor/${actor.id}" class="btn btn-outline btn-sm" style="width: 100%; margin-top: 0.75rem;">View Profile</a>
            `;
        }

        container.appendChild(card);
    });
}

// Export Modal Functions
let allActors = [];
let relevantActorIds = [];

// Helper function to get cookie value
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return null;
}

async function openExportModal() {
    const modal = document.getElementById('export-modal');
    modal.style.display = 'flex';

    // Load all actors for selection
    await loadActorsForExport();

    // Show custom date range if custom is selected
    document.getElementById('timeframe-select').addEventListener('change', function() {
        const customRange = document.getElementById('custom-date-range');
        if (this.value === 'custom') {
            customRange.style.display = 'grid';
        } else {
            customRange.style.display = 'none';
        }
    });
}

function closeExportModal() {
    const modal = document.getElementById('export-modal');
    modal.style.display = 'none';
}

async function loadActorsForExport() {
    const actorList = document.getElementById('actor-selection-list');
    actorList.innerHTML = '<p class="text-secondary">Loading actors...</p>';

    try {
        // Fetch all actors
        const response = await fetch('/api/actors');
        const data = await response.json();
        allActors = data.actors;

        // Fetch relevant actors
        const relevantResponse = await fetch('/api/relevant_actors');
        const relevantData = await relevantResponse.json();
        relevantActorIds = relevantData.actors.map(a => a.id);

        // Build actor selection list
        let html = '';
        allActors.forEach(actor => {
            const isRelevant = relevantActorIds.includes(actor.id);
            const checked = isRelevant ? 'checked' : '';
            const relevantBadge = isRelevant ? '<span style="color: var(--danger); font-size: 0.85rem; margin-left: 0.5rem;">[High Priority]</span>' : '';

            html += `
                <label class="filter-option" style="display: flex; align-items: center; margin-bottom: 0.5rem;">
                    <input type="checkbox" class="actor-cb" value="${actor.id}" ${checked}>
                    <span style="flex: 1;">${actor.name}</span>
                    ${relevantBadge}
                </label>
            `;
        });

        actorList.innerHTML = html;
    } catch (error) {
        console.error('Error loading actors for export:', error);
        actorList.innerHTML = '<p style="color: var(--danger);">Error loading actors</p>';
    }
}

function selectAllActors() {
    document.querySelectorAll('.actor-cb').forEach(cb => cb.checked = true);
}

function deselectAllActors() {
    document.querySelectorAll('.actor-cb').forEach(cb => cb.checked = false);
}

function selectRelevantOnly() {
    console.log('selectRelevantOnly called');
    console.log('relevantActorIds:', relevantActorIds);

    // First deselect all, then select only relevant actors
    const checkboxes = document.querySelectorAll('.actor-cb');
    console.log('Found checkboxes:', checkboxes.length);

    checkboxes.forEach(cb => {
        // Actor IDs are STIX strings (intrusion-set--xxx), not integers
        const actorId = cb.value;
        const isRelevant = relevantActorIds.includes(actorId);
        cb.checked = isRelevant;
        if (isRelevant) {
            console.log(`Selecting actor: ${actorId}`);
        }
    });

    const selectedCount = document.querySelectorAll('.actor-cb:checked').length;
    console.log('Selected count:', selectedCount);
}

function selectAllTactics() {
    document.querySelectorAll('.tactic-cb').forEach(cb => cb.checked = true);
}

function deselectAllTactics() {
    document.querySelectorAll('.tactic-cb').forEach(cb => cb.checked = false);
}

async function performExport(event) {
    // Collect selected actors (IDs are STIX strings, not integers)
    const selectedActorIds = Array.from(document.querySelectorAll('.actor-cb:checked')).map(cb => cb.value);

    if (selectedActorIds.length === 0) {
        alert('Please select at least one threat actor');
        return;
    }

    // Collect selected tactics
    const selectedTactics = Array.from(document.querySelectorAll('.tactic-cb:checked')).map(cb => cb.value);

    if (selectedTactics.length === 0) {
        alert('Please select at least one tactic');
        return;
    }

    // Collect timeframe
    const timeframe = document.getElementById('timeframe-select').value;
    let startDate = null;
    let endDate = null;

    if (timeframe === 'custom') {
        startDate = document.getElementById('start-date').value;
        endDate = document.getElementById('end-date').value;

        if (!startDate || !endDate) {
            alert('Please select both start and end dates for custom range');
            return;
        }
    }

    // Collect layer customization
    const layerName = document.getElementById('layer-name').value;
    const layerDescription = document.getElementById('layer-description').value;

    // Collect additional options
    const showSubtechniques = document.getElementById('show-subtechniques').checked;
    const aggregateScores = document.getElementById('aggregate-scores').checked;
    const includeMetadata = document.getElementById('include-metadata').checked;

    // Build request payload
    const payload = {
        actor_ids: selectedActorIds,
        tactics: selectedTactics,
        timeframe: timeframe,
        start_date: startDate,
        end_date: endDate,
        layer_name: layerName,
        layer_description: layerDescription,
        show_subtechniques: showSubtechniques,
        aggregate_scores: aggregateScores,
        include_metadata: includeMetadata
    };

    try {
        // Show loading state
        const exportBtn = event.target;
        const originalText = exportBtn.textContent;
        exportBtn.textContent = 'Generating...';
        exportBtn.disabled = true;

        // Get CSRF token from meta tag or cookie
        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') ||
                         getCookie('csrf_token');

        // Call export API
        const headers = {
            'Content-Type': 'application/json'
        };

        if (csrfToken) {
            headers['X-CSRFToken'] = csrfToken;
        }

        const response = await fetch('/api/export_ttps', {
            method: 'POST',
            headers: headers,
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            const errorText = await response.text();
            console.error('Export API error:', response.status, errorText);
            throw new Error(`Export failed: ${response.status}`);
        }

        // Download the file
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `mitre_attack_layer_${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);

        // Close modal
        closeExportModal();

        // Reset button
        exportBtn.textContent = originalText;
        exportBtn.disabled = false;
    } catch (error) {
        console.error('Error performing export:', error);
        alert('Export failed. Please try again.');

        // Reset button
        const exportBtn = event.target;
        exportBtn.textContent = 'Generate & Download';
        exportBtn.disabled = false;
    }
}

// Close modal when clicking outside
window.addEventListener('click', function(event) {
    const modal = document.getElementById('export-modal');
    if (event.target === modal) {
        closeExportModal();
    }
});
