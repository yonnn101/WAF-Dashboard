from urllib.parse import urlparse

def analyze_bot(event: dict) -> dict:
    score = 0
    bot_class = 'human'
    signals = []
    is_bot = False
    is_ai_agent = False

    ua = str(event.get('user_agent') or '').lower()
    path = str(event.get('path') or '').lower()
    headers = event.get('headers') or {}
    
    lower_headers = {k.lower(): v for k, v in headers.items()}

    # 1. AI-specific patterns
    is_ai_pattern = False
    if 'mcp-session-id' in lower_headers or '/mcp/' in path:
        is_ai_pattern = True
        signals.append("MCP protocol detected")
        
    if 'x-openai-client' in lower_headers:
        is_ai_pattern = True
        signals.append("OpenAI client header detected")
        
    if 'x-anthropic-client' in lower_headers:
        is_ai_pattern = True
        signals.append("Anthropic client header detected")

    ai_agents = ['gptbot', 'chatgpt-user', 'claude-web', 'perplexitybot', 'anthropic-ai', 'cohere-ai', 'bytespider', 'amazonbot']
    for agent in ai_agents:
        if agent in ua:
            is_ai_pattern = True
            signals.append(f"AI agent User-Agent detected ({agent})")
            break

    if is_ai_pattern:
        return {
            'bot_score': 100,
            'bot_class': 'ai_agent',
            'bot_signals': signals,
            'is_bot': True,
            'is_ai_agent': True
        }

    # 2. Verified bots
    verified_bots = ['googlebot', 'bingbot', 'duckduckbot', 'slurp', 'baiduspider']
    for bot in verified_bots:
        if bot in ua:
            return {
                'bot_score': 0,
                'bot_class': 'verified_bot',
                'bot_signals': [f"Verified bot User-Agent detected ({bot})"],
                'is_bot': True,
                'is_ai_agent': False
            }

    # 3. Tools / scrapers
    tools_scrapers = ['curl', 'wget', 'python-requests', 'httpclient', 'axios', 'postman', 'mj12bot', 'ahrefsbot', 'semrushbot', 'dotbot', 'petalbot']
    for tool in tools_scrapers:
        if tool in ua:
            score += 60
            signals.append(f"Known tool/scraper User-Agent detected ({tool})")
            break

    # UA heuristics
    if len(ua) < 20:
        score += 40
        signals.append("Missing or unusually short User-Agent")

    if 'mozilla' in ua and 'applewebkit' not in ua and 'gecko' not in ua and 'trident' not in ua and 'chrome' not in ua:
        score += 25
        signals.append("Fake/anomalous Mozilla User-Agent")

    # 4. Behavioral heuristics
    sensitive_paths = ['wp-login', 'wp-admin', 'xmlrpc', 'administrator', 'phpmyadmin', '.env', 'config.xml']
    for sp in sensitive_paths:
        if sp in path:
            score += 15
            signals.append(f"Probing sensitive path ({sp})")
            break

    if score >= 60:
        bot_class = 'likely_bot'
        is_bot = True

    if score > 100:
        score = 100

    return {
        'bot_score': score,
        'bot_class': bot_class,
        'bot_signals': signals,
        'is_bot': is_bot,
        'is_ai_agent': is_ai_agent
    }

def analyze_ip_behavior(events: list) -> dict:
    ip_behavior = {}
    static_extensions = {'css', 'js', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico', 'woff', 'woff2', 'ttf', 'eot'}

    for event in events:
        ip = event.get('client_ip') or '0.0.0.0'
        path = event.get('path') or '/'
        
        if ip not in ip_behavior:
            ip_behavior[ip] = {
                'count': 0,
                'static_assets': 0,
                'html_requests': 0,
                'unique_paths': set(),
                'unique_paths_count': 0
            }

        ip_behavior[ip]['count'] += 1
        ip_behavior[ip]['unique_paths'].add(path)

        path_only = urlparse(path).path or ''
        parts = path_only.split('.')
        ext = parts[-1].lower() if len(parts) > 1 else ''
        
        if ext in static_extensions:
            ip_behavior[ip]['static_assets'] += 1
        else:
            ip_behavior[ip]['html_requests'] += 1

    for ip, data in ip_behavior.items():
        data['unique_paths_count'] = len(data['unique_paths'])
        del data['unique_paths']
    
    return ip_behavior

def apply_behavioral_scores(events: list, ip_behavior: dict) -> list:
    updated_events = []

    for event in events:
        ip = event.get('client_ip') or '0.0.0.0'
        behavior = ip_behavior.get(ip)

        if behavior:
            score_added = False
            
            if 'bot_score' not in event:
                event['bot_score'] = 0
            if 'bot_signals' not in event:
                event['bot_signals'] = []
            if 'bot_class' not in event:
                event['bot_class'] = 'human'
            if 'is_bot' not in event:
                event['is_bot'] = False
                
            if behavior['count'] > 5 and behavior['static_assets'] == 0:
                event['bot_score'] += 20
                event['bot_signals'].append("No static asset requests (headless)")
                score_added = True

            if behavior['count'] > 10 and behavior['unique_paths_count'] / behavior['count'] > 0.8:
                event['bot_score'] += 15
                event['bot_signals'].append("High path diversity (scanner)")
                score_added = True
            
            if score_added:
                event['bot_score'] = min(100, event['bot_score'])
                
                if event['bot_score'] >= 60 and event['bot_class'] == 'human':
                    event['bot_class'] = 'likely_bot'
                    event['is_bot'] = True

        updated_events.append(event)

    return updated_events
