import json
import os
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse
from flask import session

import config
from supabase_client import supabase_get
from bot_detector import analyze_bot, analyze_ip_behavior, apply_behavioral_scores
from insights_engine import InsightsEngine
from threat_index import ThreatIndexEngine

DISMISSED_INSIGHTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.dismissed_insights.json')

def get_dismissed_insights():
    dismissed = set()
    try:
        sess_items = session.get('dismissed_insights', [])
        if isinstance(sess_items, list):
            dismissed.update(sess_items)
    except RuntimeError:
        pass
    try:
        if os.path.exists(DISMISSED_INSIGHTS_FILE):
            with open(DISMISSED_INSIGHTS_FILE, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    dismissed.update(data)
    except Exception:
        pass
    return list(dismissed)

def add_dismissed_insights(insight_ids):
    if isinstance(insight_ids, str):
        insight_ids = [x.strip() for x in insight_ids.split(',') if x.strip()]
    elif not isinstance(insight_ids, list):
        insight_ids = [str(insight_ids)]
        
    current = set(get_dismissed_insights())
    for item in insight_ids:
        if item:
            current.add(str(item).strip())
            
    res_list = list(current)
    try:
        with open(DISMISSED_INSIGHTS_FILE, 'w') as f:
            json.dump(res_list, f)
    except Exception:
        pass
        
    try:
        session['dismissed_insights'] = res_list[-50:]
        session.modified = True
    except RuntimeError:
        pass
        
    return res_list

def build_filters(request_args):
    f = {}
    f['server'] = request_args.get('server', 'all')
    if f['server'] not in ['nginx', 'apache', 'all']:
        f['server'] = 'all'
        
    f['severity'] = request_args.get('severity', 'all')
    if f['severity'] not in ['CRITICAL', 'ERROR', 'WARNING', 'NOTICE', 'all']:
        f['severity'] = 'all'
        
    f['status'] = request_args.get('status', 'all')
    f['ip'] = request_args.get('ip', '').strip()
    f['rule_id'] = request_args.get('rule_id', '').strip()
    f['search'] = request_args.get('search', '').strip()
    
    f['range'] = request_args.get('range', '30d')
    if f['range'] not in ['1h', '6h', '24h', '7d', '30d']:
        f['range'] = '30d'
        
    try:
        raw_limit = str(request_args.get('limit', config.DEFAULT_EVENT_LIMIT)).lower().strip()
        if raw_limit in ['all', '0', 'unlimited', 'none']:
            f['limit'] = None
        else:
            limit = int(raw_limit)
            f['limit'] = min(max(limit, 10), config.MAX_EVENT_LIMIT)
    except:
        f['limit'] = config.DEFAULT_EVENT_LIMIT
        
    try:
        f['offset'] = max(int(request_args.get('offset', 0)), 0)
    except:
        f['offset'] = 0
        
    f['blocked'] = request_args.get('blocked', 'all')
    if f['blocked'] not in ['1', '0', 'all']:
        f['blocked'] = 'all'
        
    return f

def time_ago_iso(range_str):
    now = datetime.utcnow()
    if range_str == '1h': delta = timedelta(hours=1)
    elif range_str == '6h': delta = timedelta(hours=6)
    elif range_str == '24h': delta = timedelta(hours=24)
    elif range_str == '7d': delta = timedelta(days=7)
    elif range_str == '30d': delta = timedelta(days=30)
    else: delta = timedelta(days=24)
    return (now - delta).isoformat()

def fetch_dashboard_data(request_args):
    f = build_filters(request_args)
    since = time_ago_iso(f['range'])
    
    mod_params = {
        'select': '*',
        'order': 'event_time.desc',
        'offset': f['offset'],
        'or': f'(event_time.gte.{since},event_time.is.null)'
    }
    if f['limit'] is not None:
        mod_params['limit'] = f['limit']
    
    access_params = {
        'select': '*',
        'order': 'created_at.desc',
        'limit': min(f['limit'], 5000) if f['limit'] is not None else 1000,
        'created_at': f'gte.{since}'
    }
    
    error_params = {
        'select': '*',
        'order': 'created_at.desc',
        'limit': min(f['limit'], 5000) if f['limit'] is not None else 1000,
        'created_at': f'gte.{since}'
    }
    
    if f['server'] != 'all':
        mod_params['server'] = f"eq.{f['server']}"
        access_params['server'] = f"eq.{f['server']}"
        error_params['server'] = f"eq.{f['server']}"
        
    if f['blocked'] != 'all':
        val = 'true' if f['blocked'] == '1' else 'false'
        mod_params['blocked'] = f"eq.{val}"
        
    events, lat1, err1 = supabase_get('modsec_events', mod_params)
    access_rows, lat2, err2 = supabase_get('access_logs', access_params)
    error_rows, lat3, err3 = supabase_get('error_logs', error_params)
    geo_rows, lat4, err4 = supabase_get('ip_geo_cache', {'select': '*', 'limit': 5000})
    
    latency = max(lat1, lat2, lat3, lat4)
    
    if err4:
        geo_rows = []
        
    conn_error = err1 or err2 or err3
    if conn_error:
        return {'error': conn_error, 'latency': latency}
        
    filtered_events = []
    for e in events:
        if f['severity'] != 'all':
            rules = e.get('rules', [])
            if isinstance(rules, str):
                try: rules = json.loads(rules)
                except: rules = []
            has_sev = False
            for r in rules:
                if str(r.get('severity', '')).upper() == f['severity']:
                    has_sev = True
                    break
            if not has_sev: continue
            
        if f['ip'] != '' and f['ip'].lower() not in str(e.get('client_ip', '')).lower():
            continue
            
        if f['rule_id'] != '':
            rules = e.get('rules', [])
            if isinstance(rules, str):
                try: rules = json.loads(rules)
                except: rules = []
            has_rule = False
            for r in rules:
                if f['rule_id'].lower() in str(r.get('id', '')).lower():
                    has_rule = True
                    break
            if not has_rule: continue
            
        if f['search'] != '':
            hay = f"{e.get('request_line', '')} {e.get('client_ip', '')} {e.get('server', '')}".lower()
            if f['search'].lower() not in hay:
                continue
                
        filtered_events.append(e)
        
    events = filtered_events
    
    for i, e in enumerate(events):
        bot_class = e.get('client_type', 'human')
        if not bot_class or bot_class == 'unknown': bot_class = 'human'
        
        if e.get('verified_bot') and bot_class == 'human':
            bot_class = 'verified_bot'
            
        is_ai_agent = (bot_class == 'ai_agent')
        is_bot = bot_class in ['likely_bot', 'ai_agent', 'verified_bot']
        
        signals = e.get('classification_reasons', [])
        if isinstance(signals, str):
            try: signals = json.loads(signals)
            except: signals = []
            
        bot_analysis = {
            'bot_score': int(e.get('bot_score', 0) or 0),
            'bot_class': bot_class,
            'bot_signals': signals or [],
            'is_bot': is_bot,
            'is_ai_agent': is_ai_agent
        }
        
        e.update(bot_analysis)
        e['bot_analysis'] = bot_analysis
        
    ip_behavior = analyze_ip_behavior(events)
    events = apply_behavioral_scores(events, ip_behavior)
    
    bot_counts = {}
    ai_agents = []
    bot_score_by_ip = {}
    
    for e in events:
        c = e.get('bot_class', 'human')
        bot_counts[c] = bot_counts.get(c, 0) + 1
        if e.get('is_ai_agent'):
            ai_agents.append(e)
        ip = e.get('client_ip', '')
        if ip:
            if ip not in bot_score_by_ip:
                bot_score_by_ip[ip] = {'score': 0, 'count': 0, 'classes': []}
            bot_score_by_ip[ip]['score'] += float(e.get('bot_score', 0) or 0)
            bot_score_by_ip[ip]['count'] += 1
            bot_score_by_ip[ip]['classes'].append(c)
            
    top_bot_ips = {}
    for ip, data in bot_score_by_ip.items():
        avg_score = round(data['score'] / data['count'], 2)
        from collections import Counter
        class_counts = Counter(data['classes'])
        primary_class = class_counts.most_common(1)[0][0]
        
        if 'ai_agent' in class_counts: primary_class = 'ai_agent'
        elif 'likely_bot' in class_counts: primary_class = 'likely_bot'
        elif 'verified_bot' in class_counts: primary_class = 'verified_bot'
        
        top_bot_ips[ip] = {'score': avg_score, 'class': primary_class}
        
    top_bot_ips = dict(sorted(top_bot_ips.items(), key=lambda item: item[1]['score'], reverse=True)[:8])
    
    total = len(events)
    blocked = sum(1 for e in events if e.get('blocked'))
    passed = total - blocked
    block_rate = round((blocked / total) * 100, 1) if total > 0 else 0
    
    rule_counts = {}
    ip_counts = {}
    url_counts = {}
    sev_counts = {'CRITICAL':0, 'ERROR':0, 'WARNING':0, 'NOTICE':0, 'OTHER':0}
    server_counts = {'nginx':0, 'apache':0}
    status_counts = {}
    hourly_buckets = {}
    ip_reputation = {}
    
    for e in events:
        if e.get('server'):
            srv = str(e['server']).lower().strip()
            if srv in server_counts:
                server_counts[srv] += 1
        if e.get('client_ip'):
            ip = e['client_ip']
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
            ip_reputation[ip] = ip_reputation.get(ip, 0) + (3 if e.get('blocked') else 1)
        if e.get('request_line'):
            path = urlparse(e['request_line']).path or e['request_line']
            url_counts[path] = url_counts.get(path, 0) + 1
        if e.get('http_status'):
            st = e['http_status']
            status_counts[st] = status_counts.get(st, 0) + 1
        if e.get('event_time'):
            hour = str(e['event_time'])[:13]
            hourly_buckets[hour] = hourly_buckets.get(hour, 0) + 1
            
        rules = e.get('rules', [])
        if isinstance(rules, str):
            try: rules = json.loads(rules)
            except: rules = []
        for r in rules:
            key = f"{r.get('id', '?')} -- {r.get('msg', '')}"
            rule_counts[key] = rule_counts.get(key, 0) + 1
            sev = str(r.get('severity', 'OTHER')).upper()
            if sev not in sev_counts: sev = 'OTHER'
            sev_counts[sev] += 1
        if not rules:
            sev_counts['OTHER'] += 1
            
    rule_counts = dict(sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:10])
    ip_counts = dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:8])
    url_counts = dict(sorted(url_counts.items(), key=lambda x: x[1], reverse=True)[:8])
    ip_reputation = dict(sorted(ip_reputation.items(), key=lambda x: x[1], reverse=True)[:8])
    hourly_buckets = dict(sorted(hourly_buckets.items()))
    
    geo_by_ip = {}
    for g in geo_rows:
        if not isinstance(g, dict) or not g.get('ip'): continue
        geo_by_ip[g['ip']] = g
        
    country_counts = {}
    geo_markers = []
    seen_ips_for_markers = set()
    
    for e in events:
        ip = e.get('client_ip', '')
        if not ip or ip not in geo_by_ip: continue
        g = geo_by_ip[ip]
        cc = g.get('country_code', 'XX')
        cn = g.get('country') or g.get('country_name', cc)
        key = f"{cc}|{cn}"
        
        if key not in country_counts:
            country_counts[key] = {'code': cc, 'name': cn, 'count': 0, 'blocked': 0}
        country_counts[key]['count'] += 1
        if e.get('blocked'):
            country_counts[key]['blocked'] += 1
            
        if ip not in seen_ips_for_markers:
            lat = g.get('latitude') or g.get('lat')
            lng = g.get('longitude') or g.get('lon') or g.get('lng')
            if lat is not None and lng is not None:
                geo_markers.append({
                    'ip': ip,
                    'lat': float(lat),
                    'lng': float(lng),
                    'country': cn,
                    'countryCode': cc,
                    'city': g.get('city', ''),
                    'hits': ip_counts.get(ip, 1),
                    'blocked': bool(e.get('blocked'))
                })
                seen_ips_for_markers.add(ip)
                
    cc_list = list(country_counts.values())
    cc_list.sort(key=lambda x: x['count'], reverse=True)
    
    engine = InsightsEngine()
    insights = engine.analyze(events, access_rows, error_rows)
    
    dismissed = set(get_dismissed_insights())
    insights = [i for i in insights if i['id'] not in dismissed]
    
    critical_insights = [i for i in insights if i['severity'] >= 5]
    high_insights = [i for i in insights if i['severity'] == 4]
    open_insights = [i for i in insights if i['severity'] >= 3]
    
    events_by_hour = {}
    for e in events:
        hour = str(e.get('event_time') or '')[:13]
        if hour not in events_by_hour:
            events_by_hour[hour] = []
        events_by_hour[hour].append(e)
        
    stats_array = {
        'total': total,
        'blocked': blocked,
        'passed': passed,
        'block_rate': block_rate,
        'sev_counts': sev_counts
    }
    
    threat_engine = ThreatIndexEngine()
    threat_index = threat_engine.compute(events, stats_array, hourly_buckets, f)
    hourly_threat_index = threat_engine.compute_hourly_threat_index(hourly_buckets, events_by_hour)
    
    return {
        'ok': True,
        'latency': latency,
        'filters': f,
        'stats': stats_array,
        'server_counts': server_counts,
        'status_counts': status_counts,
        'sev_counts': sev_counts,
        'top_rules': rule_counts,
        'top_ips': ip_counts,
        'top_urls': url_counts,
        'ip_reputation': ip_reputation,
        'hourly': hourly_buckets,
        'events': events if f['limit'] is None else events[:f['limit']],
        'access_rows': access_rows,
        'error_rows': error_rows,
        'has_more': False if f['limit'] is None else len(events) > f['limit'],
        'geo_countries': cc_list[:30],
        'geo_markers': geo_markers,
        'bot_counts': bot_counts,
        'ai_agents': ai_agents,
        'top_bot_ips': top_bot_ips,
        'insights': insights,
        'insight_summary': {
            'total': len(insights),
            'critical': len(critical_insights),
            'high': len(high_insights),
            'medium': len([i for i in insights if i['severity'] == 3]),
            'needs_action': len(open_insights)
        },
        'threat_index': threat_index.to_dict(),
        'hourly_threat_index': hourly_threat_index
    }
