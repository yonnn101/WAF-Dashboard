import math
import json

class ThreatIndex:
    def __init__(self, data):
        self.score = data.get('score', 0)
        self.level = data.get('level', 'Low')
        self.color = data.get('color', '#3fb950')
        self.components = data.get('components', {})
        self.trend = data.get('trend', 'stable')
        self.trend_percent = data.get('trend_percent', 0.0)
        self.safety_score = data.get('safety_score', 100)
        
    def to_dict(self):
        return {
            'score': self.score,
            'level': self.level,
            'color': self.color,
            'components': self.components,
            'trend': self.trend,
            'trend_percent': self.trend_percent,
            'safety_score': self.safety_score
        }

class ThreatIndexEngine:

    @staticmethod
    def get_level(score):
        if score <= 30: return 'Low'
        if score <= 60: return 'Medium'
        if score <= 80: return 'High'
        return 'Critical'

    @staticmethod
    def get_color(score):
        if score <= 30: return '#3fb950'
        if score <= 60: return '#e3b341'
        if score <= 80: return '#ff8a3d'
        return '#f85149'

    def compute(self, events, stats, hourly, filters):
        current_events = len(events)
        hourly_values = list(hourly.values())
        hourly_count = len(hourly_values)
        baseline = 1
        
        if hourly_count > 2:
            sum_prev = sum(hourly_values[:-1])
            baseline = max(sum_prev / (hourly_count - 1), 1)
        else:
            baseline = max(current_events * 0.3, 1)
            
        ratio = current_events / baseline
        volume_score = min(ratio * 5, 25)
        
        sev_counts = stats.get('sev_counts', {'CRITICAL':0, 'ERROR':0, 'WARNING':0, 'NOTICE':0, 'OTHER':0})
        weighted = 0
        if current_events > 0:
            weighted = (
                sev_counts.get('CRITICAL', 0) * 4 + 
                sev_counts.get('ERROR', 0) * 3 + 
                sev_counts.get('WARNING', 0) * 2 + 
                sev_counts.get('NOTICE', 0) * 1
            ) / current_events
        severity_score = min(weighted * 6.25, 25)
        
        unique_ips = set()
        unique_rules = set()
        unique_subnets = set()
        
        for e in events:
            ip = e.get('client_ip')
            if ip:
                unique_ips.add(ip)
                parts = ip.split('.')
                if len(parts) == 4:
                    unique_subnets.add(f"{parts[0]}.{parts[1]}")
                    
            rules = e.get('rules', [])
            if isinstance(rules, str):
                try:
                    rules = json.loads(rules)
                except:
                    rules = []
            if isinstance(rules, list):
                for r in rules:
                    if 'id' in r:
                        unique_rules.add(r['id'])
                        
        c_ips = max(len(unique_ips), 1)
        c_rules = max(len(unique_rules), 1)
        c_subnets = max(len(unique_subnets), 1)
        
        spread_raw = math.log10(c_ips) + math.log10(c_rules) + math.log10(c_subnets)
        spread_score = min(spread_raw * 4, 25)
        
        velocity_score = 0
        if hourly_count >= 3:
            latest = hourly_values[-1]
            avg_prev = max((hourly_values[-2] + hourly_values[-3]) / 2, 1)
            velocity_ratio = latest / avg_prev
            
            if velocity_ratio >= 1:
                velocity_score = min((velocity_ratio - 1) * 10, 25)
            else:
                velocity_score = 0
        else:
            velocity_score = volume_score * 0.5
            
        total_score = int(round(volume_score + severity_score + spread_score + velocity_score))
        total_score = min(max(total_score, 0), 100)
        
        trend_percent = 0.0
        trend = 'stable'
        
        if hourly_count >= 4:
            half = hourly_count // 2
            first_half_sum = sum(hourly_values[:half])
            second_half_sum = sum(hourly_values[-half:])
            
            first_half_avg = max(first_half_sum / half, 1)
            second_half_avg = second_half_sum / half
            
            trend_percent = ((second_half_avg - first_half_avg) / first_half_avg) * 100
            
            if trend_percent > 15: trend = 'rising'
            elif trend_percent < -15: trend = 'falling'
            
        coverage = 40
        total_stats = stats.get('total', 0)
        
        if total_stats > 0:
            critical_total = 0
            critical_blocked = 0
            
            for e in events:
                rules = e.get('rules', [])
                if isinstance(rules, str):
                    try:
                        rules = json.loads(rules)
                    except:
                        rules = []
                
                is_crit = False
                if isinstance(rules, list):
                    for r in rules:
                        if str(r.get('severity', '')).upper() == 'CRITICAL':
                            is_crit = True
                            break
                if is_crit:
                    critical_total += 1
                    if e.get('blocked'):
                        critical_blocked += 1
                        
            if critical_total > 0:
                coverage = (critical_blocked / critical_total) * 40
            else:
                block_rate = stats.get('block_rate', 0)
                coverage = (block_rate / 100.0) * 40
                
        unique_attacks = len(unique_rules)
        rule_cov = 10
        if unique_attacks <= 3: rule_cov = 30
        elif unique_attacks <= 8: rule_cov = 20
        
        passed_critical = 0
        for e in events:
            if not e.get('blocked'):
                rules = e.get('rules', [])
                if isinstance(rules, str):
                    try:
                        rules = json.loads(rules)
                    except:
                        rules = []
                if isinstance(rules, list):
                    for r in rules:
                        if str(r.get('severity', '')).upper() == 'CRITICAL':
                            passed_critical += 1
                            break
                            
        health = 10
        if passed_critical == 0: health = 30
        elif passed_critical <= 3: health = 20
        
        safety_score = int(round(coverage + rule_cov + health))
        safety_score = min(max(safety_score, 0), 100)
        
        return ThreatIndex({
            'score': total_score,
            'level': self.get_level(total_score),
            'color': self.get_color(total_score),
            'components': {
                'Volume': round(volume_score, 1),
                'Severity': round(severity_score, 1),
                'Spread': round(spread_score, 1),
                'Velocity': round(velocity_score, 1)
            },
            'trend': trend,
            'trend_percent': round(trend_percent, 1),
            'safety_score': safety_score
        })

    def compute_hourly_threat_index(self, hourly, events_by_hour):
        results = {}
        previous_volumes = []
        
        for hour, count in hourly.items():
            hour_events = events_by_hour.get(hour, [])
            
            baseline = 1
            prev_count = len(previous_volumes)
            if prev_count > 0:
                baseline = max(sum(previous_volumes) / prev_count, 1)
            else:
                baseline = max(count * 0.3, 1)
                
            ratio = count / baseline
            volume_score = min(ratio * 5, 25)
            
            weighted = 0
            crit=0; err=0; warn=0; noti=0
            for e in hour_events:
                rules = e.get('rules', [])
                if isinstance(rules, str):
                    try:
                        rules = json.loads(rules)
                    except:
                        rules = []
                if isinstance(rules, list):
                    for r in rules:
                        s = str(r.get('severity', 'OTHER')).upper()
                        if s == 'CRITICAL': crit += 1
                        elif s == 'ERROR': err += 1
                        elif s == 'WARNING': warn += 1
                        elif s == 'NOTICE': noti += 1
                        
            if count > 0:
                weighted = (crit*4 + err*3 + warn*2 + noti*1) / count
            severity_score = min(weighted * 6.25, 25)
            
            u_ips = set()
            u_rules = set()
            u_subs = set()
            for e in hour_events:
                ip = e.get('client_ip')
                if ip:
                    u_ips.add(ip)
                    p = ip.split('.')
                    if len(p) == 4:
                        u_subs.add(f"{p[0]}.{p[1]}")
                rules = e.get('rules', [])
                if isinstance(rules, str):
                    try:
                        rules = json.loads(rules)
                    except:
                        rules = []
                if isinstance(rules, list):
                    for r in rules:
                        if 'id' in r:
                            u_rules.add(r['id'])
                            
            spread_raw = math.log10(max(len(u_ips), 1)) + math.log10(max(len(u_rules), 1)) + math.log10(max(len(u_subs), 1))
            spread_score = min(spread_raw * 4, 25)
            
            velocity_score = 0
            if prev_count >= 2:
                avg_prev = max((previous_volumes[-1] + previous_volumes[-2]) / 2, 1)
                vr = count / avg_prev
                if vr >= 1:
                    velocity_score = min((vr - 1) * 10, 25)
            else:
                velocity_score = volume_score * 0.5
                
            total = int(round(volume_score + severity_score + spread_score + velocity_score))
            results[hour] = min(max(total, 0), 100)
            
            previous_volumes.append(count)
            
        return results
