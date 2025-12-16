import hashlib
import random
import json
import math

def generate_actor_avatar(actor):
    """
    Generates a professional, abstract geometric 'fingerprint' avatar.
    Uses a monochrome/stealth palette for the enterprise theme.
    """
    # 1. Deterministic Seed
    seed_str = f"{actor.id}-{actor.name}"
    seed_int = int(hashlib.sha256(seed_str.encode('utf-8')).hexdigest(), 16)
    random.seed(seed_int)

    # 2. Color Palette (Monochrome/Stealth with Dark Red Accents)
    # Format: (Primary, Secondary, Accent)
    # Primary: Dark Grey, Secondary: Black/Darker Grey, Accent: Dark Red/Silver
    palettes = {
        "China": ("#525252", "#262626", "#7f1d1d"),      # Grey / Black / Dark Red
        "Russia": ("#404040", "#171717", "#991b1b"),     # Darker Grey / Black / Red
        "Iran": ("#525252", "#262626", "#7f1d1d"),       # Grey / Black / Dark Red
        "North Korea": ("#404040", "#171717", "#991b1b"),# Darker Grey / Black / Red
        "Vietnam": ("#525252", "#262626", "#7f1d1d"),    # Grey / Black / Dark Red
        "Unknown": ("#404040", "#171717", "#7f1d1d")     # Darker Grey / Black / Dark Red
    }
    
    origins = []
    if actor.origin_countries:
        try: origins = json.loads(actor.origin_countries)
        except: pass
        
    palette = palettes["Unknown"]
    if origins:
        for origin in origins:
            for key in palettes:
                if key in origin:
                    palette = palettes[key]
                    break
    
    primary, secondary, light = palette
    
    # 3. Generate Abstract Shapes (The "Fingerprint")
    svg_elements = []
    
    # Background - Dark Grey
    svg_elements.append(f'<rect width="100%" height="100%" fill="#171717"/>')
    
    # Center point
    cx, cy = 100, 100
    
    # Pattern Type determined by seed
    pattern_type = seed_int % 4
    
    if pattern_type == 0:
        # Concentric Tech Rings
        for i in range(3, 0, -1):
            r = i * 25
            dash = random.randint(10, 60)
            stroke = random.choice([light, secondary])
            width = random.randint(1, 4)
            opacity = random.uniform(0.3, 0.8)
            rotation = random.randint(0, 360)
            svg_elements.append(f'''
                <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="{stroke}" stroke-width="{width}" 
                stroke-dasharray="{dash} {dash/2}" opacity="{opacity}" transform="rotate({rotation} {cx} {cy})"/>
            ''')
            
    elif pattern_type == 1:
        # Hexagonal Grid
        size = 40
        for i in range(3):
            for j in range(3):
                x = 40 + i * 60
                y = 40 + j * 60
                if random.random() > 0.4:
                    color = random.choice([light, primary])
                    opacity = random.uniform(0.2, 0.6)
                    # Hexagon path
                    svg_elements.append(f'''
                        <path d="M{x} {y-20} L{x+17} {y-10} L{x+17} {y+10} L{x} {y+20} L{x-17} {y+10} L{x-17} {y-10} Z" 
                        fill="{color}" opacity="{opacity}"/>
                    ''')

    elif pattern_type == 2:
        # Data Nodes (Connected dots)
        points = []
        for _ in range(6):
            angle = random.uniform(0, 2 * math.pi)
            dist = random.uniform(20, 80)
            px = cx + math.cos(angle) * dist
            py = cy + math.sin(angle) * dist
            points.append((px, py))
            
        # Draw lines
        for i in range(len(points)):
            p1 = points[i]
            p2 = points[(i + 1) % len(points)]
            svg_elements.append(f'<line x1="{p1[0]}" y1="{p1[1]}" x2="{p2[0]}" y2="{p2[1]}" stroke="{light}" stroke-width="1" opacity="0.4"/>')
            
        # Draw dots
        for px, py in points:
            svg_elements.append(f'<circle cx="{px}" cy="{py}" r="4" fill="{light}" opacity="0.8"/>')
            
    else:
        # Abstract Glyphs
        for _ in range(4):
            w = random.randint(20, 80)
            h = random.randint(20, 80)
            x = random.randint(20, 180-w)
            y = random.randint(20, 180-h)
            color = random.choice([light, primary])
            svg_elements.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="2" fill="none" stroke="{color}" stroke-width="2" opacity="0.5" transform="rotate({random.randint(-45, 45)} {x+w/2} {y+h/2})"/>')

    # Overlay Initials
    initials = actor.name[:2].upper()
    svg_elements.append(f'''
        <text x="50%" y="50%" dy=".35em" text-anchor="middle" font-family="Arial, sans-serif" font-weight="bold" font-size="60" fill="{light}" opacity="0.1">{initials}</text>
    ''')

    # Final SVG Assembly
    svg_content = f'''
    <svg width="200" height="200" viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg">
        {''.join(svg_elements)}
    </svg>
    '''
    
    return svg_content.strip()
