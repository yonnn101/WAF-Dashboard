import hashlib
import json
from datetime import datetime
from urllib.parse import urlparse
import time

class Insight:
    def __init__(self, data):
        self.type = data.get('type') or 'unknown'
        self.severity = data.get('severity', 1)
        self.title = data.get('title') or ''
        self.description = data.get('description') or ''
        self.affected_ips = [str(x) for x in (data.get('affected_ips') or []) if x is not None]
        self.affected_paths = [str(x) for x in (data.get('affected_paths') or []) if x is not None]
        self.affected_rules = [str(x) for x in (data.get('affected_rules') or []) if x is not None]
        self.recommendation = data.get('recommendation') or ''
        self.confidence = data.get('confidence', 0.0)
        self.first_seen = data.get('first_seen') or datetime.utcnow().isoformat()
        self.event_count = data.get('event_count', 0)
        
        self.id = self.generate_insight_id(data)
        
    @staticmethod
    def generate_insight_id(data):
        t = str(data.get('type') or 'unknown')
        raw_ips = sorted(list(set([str(x) for x in (data.get('affected_ips') or []) if x is not None])))
        raw_paths = sorted(list(set([str(x) for x in (data.get('affected_paths') or []) if x is not None])))
        raw_rules = sorted(list(set([str(x) for x in (data.get('affected_rules') or []) if x is not None])))
        title = str(data.get('title') or '')
        ips = ','.join(raw_ips)
        paths = ','.join(raw_paths)
        rules = ','.join(raw_rules)
        return hashlib.md5(f"{t}|{ips}|{paths}|{rules}|{title}".encode('utf-8')).hexdigest()
        
    def to_dict(self):
        return {
            'id': self.id,
            'type': self.type,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'affected_ips': self.affected_ips,
            'affected_paths': self.affected_paths,
            'affected_rules': self.affected_rules,
            'recommendation': self.recommendation,
            'confidence': round(self.confidence, 2),
            'first_seen': self.first_seen,
            'event_count': self.event_count,
            'severity_label': self.severity_label(self.severity),
            'severity_color': self.severity_color(self.severity)
        }

    @staticmethod
    def severity_label(sev):
        if sev >= 5: return 'Critical'
        if sev == 4: return 'High'
        if sev == 3: return 'Medium'
        if sev == 2: return 'Low'
        return 'Low'

    @staticmethod
    def severity_color(sev):
        if sev >= 5: return '#f85149'
        if sev == 4: return '#ff8a3d'
        if sev == 3: return '#e3b341'
        if sev == 2: return '#58a6ff'
        return '#8b949e'

class InsightsEngine:
    
    @staticmethod
    def extract_path(request_line):
        parts = request_line.strip().split(' ')
        if len(parts) >= 2:
            uri = parts[1]
            return urlparse(uri).path or uri
        return urlparse(request_line).path or request_line

    @staticmethod
    def parse_timestamp(time_str):
        if not time_str:
            return time.time()
        if isinstance(time_str, (int, float)):
            return float(time_str)
        try:
            ts = str(time_str).replace('Z', '+00:00')
            return datetime.fromisoformat(ts).timestamp()
        except Exception:
            pass
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S.%f"):
            try:
                return datetime.strptime(str(time_str)[:19], fmt[:len(str(time_str)[:19])]).timestamp()
            except Exception:
                pass
        return time.time()
        
    def analyze(self, events, access_logs=None, error_logs=None):
        access_logs = access_logs or []
        error_logs = error_logs or []
        
        insights = []
        insights.extend(self.detect_brute_force(events))
        insights.extend(self.detect_escalation(events))
        insights.extend(self.detect_new_attack_patterns(events))
        insights.extend(self.detect_sensitive_probe(events))
        insights.extend(self.detect_bot_campaign(events))
        insights.extend(self.detect_coverage_gap(events, access_logs, error_logs))
        insights.extend(self.detect_false_positives(events))
        
        # Deduplicate insights by ID
        unique_insights = {}
        for i in insights:
            if i.id not in unique_insights:
                unique_insights[i.id] = i
        
        insight_list = list(unique_insights.values())
        # Sort by severity DESC, confidence DESC, event_count DESC
        insight_list.sort(key=lambda x: (x.severity, x.confidence, x.event_count), reverse=True)
        return [i.to_dict() for i in insight_list]

    def detect_brute_force(self, events):
        insights = []
        auth_paths = ['login', 'admin', 'wp-login', 'api/auth', 'auth', 'signin', 'password', 'token', 'session']
        ip_path_times = {}
        
        for e in events:
            req_line = str(e.get('request_line') or '')
            path = self.extract_path(req_line).lower()
            
            is_auth = any(ap in path for ap in auth_paths)
            if is_auth:
                ip = e.get('client_ip', 'unknown')
                t = self.parse_timestamp(e.get('event_time'))
                
                if ip not in ip_path_times:
                    ip_path_times[ip] = {}
                if path not in ip_path_times[ip]:
                    ip_path_times[ip][path] = {'times': [], 'blocked': 0}
                    
                ip_path_times[ip][path]['times'].append(t)
                if e.get('blocked'):
                    ip_path_times[ip][path]['blocked'] += 1
                    
        for ip, paths in ip_path_times.items():
            for uri, data in paths.items():
                times = sorted(data['times'])
                for i in range(len(times)):
                    count_in_window = 1
                    for j in range(i+1, len(times)):
                        if times[j] - times[i] <= 300:
                            count_in_window += 1
                        else:
                            break
                    if count_in_window >= 5:
                        blocked_count = data['blocked']
                        sev = 5 if blocked_count > 0 else 4
                        conf = min(count_in_window / 15.0, 1.0)
                        insights.append(Insight({
                            'type': 'brute_force',
                            'severity': sev,
                            'title': f"Brute force attack detected on {uri}",
                            'description': f"IP {ip} performed {count_in_window} auth-related requests within a short timeframe.",
                            'affected_ips': [ip],
                            'affected_paths': [uri],
                            'recommendation': "Implement rate limiting on authentication endpoints or temporarily block the offending IP address.",
                            'confidence': conf,
                            'first_seen': datetime.fromtimestamp(times[0]).isoformat(),
                            'event_count': len(times)
                        }))
                        break
        return insights

    def detect_escalation(self, events):
        insights = []
        ip_history = {}
        for e in events:
            ip = e.get('client_ip', 'unknown')
            t = self.parse_timestamp(e.get('event_time'))
                
            rules = e.get('rules', [])
            if isinstance(rules, str):
                try:
                    rules = json.loads(rules)
                except:
                    rules = []
                    
            if ip not in ip_history:
                ip_history[ip] = []
            ip_history[ip].append({'time': t, 'rule_count': len(rules) if isinstance(rules, list) else 0})
            
        for ip, history in ip_history.items():
            if len(history) < 2: continue
            history.sort(key=lambda x: x['time'])
            
            escalated = False
            max_multiplier = 0
            base_count = history[0]['rule_count']
            max_count = base_count
            
            for i in range(1, len(history)):
                if history[i]['time'] - history[0]['time'] <= 3600:
                    curr = history[i]['rule_count']
                    if base_count > 0 and curr >= base_count * 3:
                        escalated = True
                        max_multiplier = max(max_multiplier, curr / base_count)
                        max_count = max(max_count, curr)
                    elif base_count == 0 and curr >= 3:
                        escalated = True
                        max_multiplier = max(max_multiplier, curr)
                        max_count = max(max_count, curr)
                        
            if escalated:
                conf = min(0.7 + (0.3 * (max_count / 10.0)), 1.0)
                insights.append(Insight({
                    'type': 'escalation',
                    'severity': 4,
                    'title': f"IP {ip} escalated attack intensity ({base_count} -> {max_count} rule matches)",
                    'description': f"Attack intensity from IP {ip} increased significantly to {max_count} rule matches within an hour.",
                    'affected_ips': [ip],
                    'recommendation': "Review the IP's recent payload signatures. The attacker is actively probing and escalating payload complexity.",
                    'confidence': conf,
                    'first_seen': datetime.fromtimestamp(history[0]['time']).isoformat(),
                    'event_count': len(history)
                }))
        return insights
        
    def detect_new_attack_patterns(self, events):
        insights = []
        patterns = {}
        static_exts = ('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf', '.map')
        
        for e in events:
            path = self.extract_path(str(e.get('request_line') or ''))
            if any(path.lower().endswith(ext) for ext in static_exts):
                continue
                
            rules = e.get('rules', [])
            if isinstance(rules, str):
                try:
                    rules = json.loads(rules)
                except:
                    rules = []
            ip = e.get('client_ip') or 'unknown'
            time_str = e.get('event_time') or datetime.utcnow().isoformat()
            
            if not isinstance(rules, list):
                continue
                
            for r in rules:
                rule_id = str(r.get('id', 'unknown'))
                
                key = (rule_id, path)
                if key not in patterns:
                    patterns[key] = {
                        'count': 0,
                        'first_seen': time_str,
                        'ips': set(),
                        'rule_id': rule_id,
                        'path': path,
                        'rule_msg': r.get('msg', '')
                    }
                patterns[key]['count'] += 1
                patterns[key]['ips'].add(ip)
                
        for (rule_id, path), data in patterns.items():
            affected_ips = sorted(list(data['ips']))
            msg_str = f" ({data['rule_msg']})" if data['rule_msg'] else ""
            insights.append(Insight({
                'type': 'new_attack_pattern',
                'severity': 3,
                'title': f"New Attack Pattern on {path or '/'} (Rule {rule_id})",
                'description': f"Rule {rule_id}{msg_str} was triggered {data['count']} time(s) on path '{path or '/'}'.",
                'affected_ips': affected_ips,
                'affected_paths': [path],
                'affected_rules': [rule_id],
                'recommendation': "Investigate if this represents a new exploit campaign or a pattern requiring custom rules.",
                'confidence': min(0.5 + (data['count'] * 0.05), 0.95),
                'first_seen': data['first_seen'],
                'event_count': data['count']
            }))
        return insights

    def detect_sensitive_probe(self, events):
        insights = []
        sensitive_keywords = ['.env', '.git', 'wp-config', 'config.php', 'config.json', 'id_rsa', '/etc/passwd', 'backup.sql', 'phpmyadmin', '.aws', 'credentials', 'eval-using-main', '.htaccess']
        
        path_targets = {}
        for e in events:
            path = self.extract_path(str(e.get('request_line') or '')).lower()
            ip = e.get('client_ip', 'unknown')
            time_str = e.get('event_time') or datetime.utcnow().isoformat()
            
            matched_kw = [kw for kw in sensitive_keywords if kw in path]
            if matched_kw:
                kw = matched_kw[0]
                if kw not in path_targets:
                    path_targets[kw] = {'ips': set(), 'paths': set(), 'count': 0, 'first_seen': time_str}
                path_targets[kw]['ips'].add(ip)
                path_targets[kw]['paths'].add(path)
                path_targets[kw]['count'] += 1
                
        for kw, data in path_targets.items():
            ips = sorted(list(data['ips']))
            paths = sorted(list(data['paths']))
            insights.append(Insight({
                'type': 'sensitive_probe',
                'severity': 4,
                'title': f"Sensitive file probe detected ({kw})",
                'description': f"Detected {data['count']} probe request(s) targeting sensitive paths like '{paths[0]}'.",
                'affected_ips': ips,
                'affected_paths': paths,
                'recommendation': "Ensure directory listing is disabled, sensitive configuration files are restricted, and block repeated probers.",
                'confidence': 0.85,
                'first_seen': data['first_seen'],
                'event_count': data['count']
            }))
        return insights

    def detect_bot_campaign(self, events):
        insights = []
        bot_events_by_path = {}
        static_exts = ('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf', '.map')
        
        for e in events:
            path = self.extract_path(str(e.get('request_line') or ''))
            if any(path.lower().endswith(ext) for ext in static_exts):
                continue
                
            bot_class = e.get('bot_class') or e.get('client_type', 'human')
            bot_score = float(e.get('bot_score', 0) or 0)
            
            if bot_class in ['likely_bot', 'ai_agent'] or bot_score >= 60:
                ip = e.get('client_ip', 'unknown')
                time_str = e.get('event_time') or datetime.utcnow().isoformat()
                
                if path not in bot_events_by_path:
                    bot_events_by_path[path] = {'ips': set(), 'count': 0, 'first_seen': time_str}
                bot_events_by_path[path]['ips'].add(ip)
                bot_events_by_path[path]['count'] += 1
                
        for path, data in bot_events_by_path.items():
            if data['count'] >= 2:
                ips = sorted(list(data['ips']))
                insights.append(Insight({
                    'type': 'bot_campaign',
                    'severity': 4,
                    'title': f"Coordinated Bot Campaign targeting {path or '/'}",
                    'description': f"Automated bot activity detected targeting '{path or '/'}' with {data['count']} requests across {len(ips)} IP address(es).",
                    'affected_ips': ips,
                    'affected_paths': [path],
                    'recommendation': "Deploy CAPTCHA or bot verification challenges for this path, or restrict access via rate-limiting.",
                    'confidence': 0.8,
                    'first_seen': data['first_seen'],
                    'event_count': data['count']
                }))
        return insights

    def detect_coverage_gap(self, events, access_logs, error_logs):
        insights = []
        unblocked_suspicious = {}
        
        for e in events:
            if not e.get('blocked'):
                path = self.extract_path(str(e.get('request_line') or ''))
                ip = e.get('client_ip', 'unknown')
                time_str = e.get('event_time') or datetime.utcnow().isoformat()
                rules = e.get('rules', [])
                if isinstance(rules, str):
                    try: rules = json.loads(rules)
                    except: rules = []
                
                if len(rules) > 0:
                    if path not in unblocked_suspicious:
                        unblocked_suspicious[path] = {'ips': set(), 'count': 0, 'first_seen': time_str, 'rules': set()}
                    unblocked_suspicious[path]['ips'].add(ip)
                    unblocked_suspicious[path]['count'] += 1
                    for r in rules:
                        if 'id' in r: unblocked_suspicious[path]['rules'].add(str(r['id']))

        for path, data in unblocked_suspicious.items():
            if data['count'] >= 3:
                insights.append(Insight({
                    'type': 'coverage_gap',
                    'severity': 3,
                    'title': f"Potential WAF Coverage Gap on {path or '/'}",
                    'description': f"Path '{path or '/'}' allowed {data['count']} suspicious request(s) without active blocking.",
                    'affected_ips': sorted(list(data['ips'])),
                    'affected_paths': [path],
                    'affected_rules': sorted(list(data['rules'])),
                    'recommendation': "Enable blocking mode or create a specific rule for this endpoint to prevent evasion.",
                    'confidence': 0.7,
                    'first_seen': data['first_seen'],
                    'event_count': data['count']
                }))
        return insights

    def detect_false_positives(self, events):
        insights = []
        fp_candidates = {}
        
        static_exts = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf']
        
        for e in events:
            path = self.extract_path(str(e.get('request_line') or '')).lower()
            bot_class = e.get('bot_class', 'human')
            
            is_static = any(path.endswith(ext) for ext in static_exts)
            if is_static or bot_class == 'human':
                rules = e.get('rules', [])
                if isinstance(rules, str):
                    try: rules = json.loads(rules)
                    except: rules = []
                    
                for r in rules:
                    rule_id = str(r.get('id', 'unknown'))
                    key = (rule_id, path)
                    if key not in fp_candidates:
                        fp_candidates[key] = {'count': 0, 'first_seen': e.get('event_time') or datetime.utcnow().isoformat(), 'path': path, 'rule_id': rule_id, 'ips': set()}
                    fp_candidates[key]['count'] += 1
                    if e.get('client_ip'): fp_candidates[key]['ips'].add(e['client_ip'])

        for (rule_id, path), data in fp_candidates.items():
            if is_static and data['count'] >= 1:
                insights.append(Insight({
                    'type': 'false_positive',
                    'severity': 2,
                    'title': f"Likely False Positive on static resource {path} (Rule {rule_id})",
                    'description': f"Rule {rule_id} triggered on static asset '{path}'. This is likely a false positive.",
                    'affected_ips': sorted(list(data['ips'])),
                    'affected_paths': [path],
                    'affected_rules': [rule_id],
                    'recommendation': "Consider excluding rule " + rule_id + " for static asset paths.",
                    'confidence': 0.85,
                    'first_seen': data['first_seen'],
                    'event_count': data['count']
                }))
        return insights

