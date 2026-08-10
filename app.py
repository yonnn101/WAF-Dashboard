from flask import Flask, request, jsonify, Response, render_template, redirect, url_for, session
import csv
import io
import json
from datetime import datetime
import subprocess

import config
from auth import login_required
from data import fetch_dashboard_data, build_filters, add_dismissed_insights
from supabase_client import health_check
app = Flask(__name__, static_url_path='', static_folder='static')
app.secret_key = config.APP_PASSWORD # Used for session signing
MANAGE_RULES_PATH = '/opt/waf-admin/scripts/manage_rules.py'

@app.route('/', methods=['GET', 'POST'])
def index():
    if config.AUTH_ENABLED:
        if request.args.get('logout') is not None:
            session.clear()
            return redirect(url_for('index'))
            
        if request.method == 'POST' and 'login_pass' in request.form:
            if request.form['login_pass'] == config.APP_PASSWORD:
                session['waf_auth'] = True
                session['auth_ip'] = request.remote_addr
                session['auth_at'] = int(datetime.utcnow().timestamp())
                return redirect(url_for('index'))
            else:
                return render_template('login.html', error='Invalid credentials. Access denied.'), 401
                
        if not session.get('waf_auth'):
            return render_template('login.html', error=None)
            
        if session.get('auth_ip') != request.remote_addr:
            session.clear()
            return redirect(url_for('index'))
            
    # Parse initial filters if any, just pass them to the template if needed
    # The PHP version built filters to inject initial variables, but JS loads them
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    return index() # Reuse the logic above

def _ensure_restore_script_fixed():
    script_path = '/opt/waf-admin/scripts/restore-rule.sh'
    fixed_script = """#!/bin/bash
# restore-rule.sh <rule_id> — removes a previously added SecRuleRemoveById
# exclusion, re-enabling that rule.
set -euo pipefail

LOG="/var/log/waf-admin/restore-rule.log"
RULE_ID="${1:-}"
EXCLUSIONS_FILE="/usr/local/modsecurity-crs/rules/custom/rule-exclusions.conf"

log() { echo "[$(date -Iseconds)] $1" >> "$LOG"; }

if ! [[ "$RULE_ID" =~ ^[0-9]+$ ]]; then
    echo "ERROR: rule id must be numeric, got: '$RULE_ID'"
    log "REJECTED invalid rule id '$RULE_ID' (restore)"
    exit 1
fi

if [[ ! -f "$EXCLUSIONS_FILE" ]] || ! grep -qE "SecRuleRemoveById[[:space:]]+$RULE_ID([[:space:]]|$)" "$EXCLUSIONS_FILE"; then
    echo "NOT_EXCLUDED: $RULE_ID"
    log "no-op, $RULE_ID was not excluded"
    exit 0
fi

cp "$EXCLUSIONS_FILE" "$EXCLUSIONS_FILE.bak"
grep -vE "SecRuleRemoveById[[:space:]]+$RULE_ID([[:space:]]|$)" "$EXCLUSIONS_FILE.bak" > "$EXCLUSIONS_FILE" || true

if command -v nginx >/dev/null && ! NGINX_MSG=$(nginx -t 2>&1); then
    mv "$EXCLUSIONS_FILE.bak" "$EXCLUSIONS_FILE"
    echo "ROLLED_BACK: removing exclusion for $RULE_ID broke config"
    echo "$NGINX_MSG"
    log "FAILED to restore $RULE_ID, rolled back. nginx -t output: $NGINX_MSG"
    exit 1
fi
rm -f "$EXCLUSIONS_FILE.bak"
chmod 644 "$EXCLUSIONS_FILE"

systemctl reload nginx

echo "RESTORED: $RULE_ID"
log "SUCCESS restored rule $RULE_ID"
exit 0
"""
    try:
        with open(script_path, 'r') as f:
            content = f.read()
        if '|| true' not in content or 'remove-rule.log' in content:
            try:
                with open(script_path, 'w') as f:
                    f.write(fixed_script)
            except Exception:
                subprocess.run(['sudo', '-n', 'tee', script_path], input=fixed_script, text=True, capture_output=True)
                subprocess.run(['sudo', '-n', 'chmod', '+x', script_path])
    except Exception:
        pass


@app.route('/api.php', methods=['POST'])
@app.route('/api', methods=['POST'])
@login_required
def api():
    # Simulate the api.php router logic
    action = request.form.get('action') or request.json.get('action') if request.is_json else None
    if not action and request.form:
        action = request.form.get('action')
        
    if action == 'fetch_data':
        data = fetch_dashboard_data(request.form)
        return jsonify(data)
        
    elif action == 'export_csv':
        # Need to override limit
        args = request.form.to_dict()
        args['limit'] = 'all'
        data = fetch_dashboard_data(args)
        
        if data.get('error'):
            return jsonify({'error': data['error']}), 500
            
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Event Time','Server','Client IP','Blocked','HTTP Status','Request Line','Rules Matched','Severity'])
        
        for e in data.get('events', []):
            rules = e.get('rules', [])
            if isinstance(rules, str):
                try: rules = json.loads(rules)
                except: rules = []
                
            rule_str = '; '.join([f"{r.get('id', '?')}:{r.get('msg', '')}" for r in rules])
            sevs = ', '.join(list(set([str(r.get('severity', '?')) for r in rules])))
            
            writer.writerow([
                e.get('event_time', ''),
                e.get('server', ''),
                e.get('client_ip', ''),
                'YES' if e.get('blocked') else 'NO',
                e.get('http_status', ''),
                e.get('request_line', ''),
                rule_str,
                sevs
            ])
            
        filename = f"waf-events-{datetime.now().strftime('%Y-%m-%d-%H%M%S')}.csv"
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"}
        )
        
    elif action == 'health_check':
        return jsonify(health_check())
        
    elif action == 'dismiss_insight':
        insight_id = request.form.get('insight_id') or (request.json.get('insight_id') if request.is_json else None)
        if insight_id:
            add_dismissed_insights(insight_id)
            return jsonify({'success': True})
        return jsonify({'error': 'Missing insight_id'}), 400
        
    elif action == 'add_custom_rule':
        raw_text = request.form.get('raw_text') or (request.json.get('raw_text') if request.is_json else None)
        if not raw_text: return jsonify({'error': 'Missing raw_text'}), 400
        try:
            result = subprocess.run(['sudo', '-n', MANAGE_RULES_PATH, 'add', raw_text], capture_output=True, text=True, check=True)
            import re
            id_match = re.search(r"id\s*:\s*'?(\d+)'?", raw_text)
            if id_match:
                subprocess.run(['sudo', '-n', MANAGE_RULES_PATH, 'enable', id_match.group(1)], capture_output=True, text=True)
            try:
                return jsonify(json.loads(result.stdout))
            except json.JSONDecodeError:
                return jsonify({'success': True, 'output': 'Rule added successfully'})
        except subprocess.CalledProcessError as e:
            return jsonify({'error': 'Command failed', 'details': e.stderr.strip() or e.stdout.strip()}), 500

    elif action == 'remove_rule':
        rule_id = request.form.get('rule_id') or (request.json.get('rule_id') if request.is_json else None)
        if not rule_id: return jsonify({'error': 'Missing rule_id'}), 400
        try:
            result = subprocess.run(['sudo', '-n', MANAGE_RULES_PATH, 'disable', str(rule_id)], capture_output=True, text=True, check=True)
            try:
                return jsonify(json.loads(result.stdout))
            except json.JSONDecodeError:
                return jsonify({'success': True, 'output': f'Rule {rule_id} disabled'})
        except subprocess.CalledProcessError as e:
            return jsonify({'error': 'Command failed', 'details': e.stderr.strip() or e.stdout.strip()}), 500

    elif action == 'restore_rule':
        rule_id = request.form.get('rule_id') or (request.json.get('rule_id') if request.is_json else None)
        if not rule_id: return jsonify({'error': 'Missing rule_id'}), 400
        try:
            result = subprocess.run(['sudo', '-n', MANAGE_RULES_PATH, 'enable', str(rule_id)], capture_output=True, text=True, check=True)
            try:
                return jsonify(json.loads(result.stdout))
            except json.JSONDecodeError:
                return jsonify({'success': True, 'output': f'Rule {rule_id} restored'})
        except subprocess.CalledProcessError as e:
            return jsonify({'error': 'Command failed', 'details': e.stderr.strip() or e.stdout.strip()}), 500

    elif action == 'edit_rule':
        rule_id = request.form.get('rule_id') or (request.json.get('rule_id') if request.is_json else None)
        raw_text = request.form.get('raw_text') or (request.json.get('raw_text') if request.is_json else None)
        if not rule_id or not raw_text: return jsonify({'error': 'Missing rule_id or raw_text'}), 400
        try:
            result = subprocess.run(['sudo', '-n', MANAGE_RULES_PATH, 'edit', str(rule_id), raw_text], capture_output=True, text=True, check=True)
            try:
                return jsonify(json.loads(result.stdout))
            except json.JSONDecodeError:
                return jsonify({'success': True, 'output': f'Rule {rule_id} edited successfully'})
        except subprocess.CalledProcessError as e:
            return jsonify({'error': 'Command failed', 'details': e.stderr.strip() or e.stdout.strip()}), 500

    elif action == 'delete_rule':
        rule_id = request.form.get('rule_id') or (request.json.get('rule_id') if request.is_json else None)
        if not rule_id: return jsonify({'error': 'Missing rule_id'}), 400
        if str(rule_id) in ["949110", "959110"]:
            return jsonify({'success': False, 'error': 'Rule 949110 / 959110 is the core WAF engine and cannot be deleted.'})
        try:
            result = subprocess.run(['sudo', '-n', MANAGE_RULES_PATH, 'edit', str(rule_id), ''], capture_output=True, text=True, check=True)
            
            # Auto-restore the original CRS rule if an override rule (e.g. 1942100) is deleted
            if str(rule_id).startswith('1') and len(str(rule_id)) > 6:
                original_id = str(rule_id)[1:]
                subprocess.run(['sudo', '-n', MANAGE_RULES_PATH, 'enable', original_id], capture_output=True, text=True)
                
            try:
                res_data = json.loads(result.stdout)
                res_data['message'] = f'Rule {rule_id} deleted successfully'
                return jsonify(res_data)
            except json.JSONDecodeError:
                return jsonify({'success': True, 'output': f'Rule {rule_id} deleted successfully'})
        except subprocess.CalledProcessError as e:
            return jsonify({'error': 'Command failed', 'details': e.stderr.strip() or e.stdout.strip()}), 500

    elif action == 'get_all_rules':
        try:
            result = subprocess.run(['sudo', '-n', MANAGE_RULES_PATH, 'list'], capture_output=True, text=True, check=True)
            try:
                parsed = json.loads(result.stdout)
                rules = parsed.get("data", [])
            except:
                return jsonify({'error': 'Failed to parse rules from script', 'details': result.stdout}), 500
            
            # Fetch events to determine which rules "happened"
            events_data = fetch_dashboard_data({})
            hit_rules = set()
            for e in events_data.get('events', []):
                for r in (json.loads(e['rules']) if isinstance(e.get('rules'), str) else e.get('rules', [])):
                    if 'id' in r: hit_rules.add(str(r['id']))
            
            # Decorate rules with hit status and sort
            for rule in rules:
                rule['hit'] = rule['id'] in hit_rules
            
            rules.sort(key=lambda x: (not x['hit'], x['id']))
            return jsonify({'success': True, 'data': rules})
        except subprocess.CalledProcessError as e:
            return jsonify({'error': 'Command failed', 'details': e.stderr.strip() or e.stdout.strip()}), 500

    elif action == 'update_crs':
        try:
            result = subprocess.run(['sudo', '-n', '/opt/waf-admin/scripts/update-crs.sh'], capture_output=True, text=True, check=True)
            return jsonify({'success': True, 'output': result.stdout.strip()})
        except subprocess.CalledProcessError as e:
            return jsonify({'error': 'Command failed', 'details': e.stderr.strip() or e.stdout.strip()}), 500

    elif action == 'get_rules_info':
        import re
        custom_rules = []
        excluded_rules = []
        try:
            with open('/usr/local/modsecurity-crs/rules/custom/local-rules.conf', 'r') as f:
                content = f.read()
                matches = re.finditer(r'"id:(\d+).*?msg:\'([^\']+)\'', content)
                for m in matches:
                    custom_rules.append({'id': m.group(1), 'msg': m.group(2)})
        except Exception:
            pass
            
        try:
            with open('/usr/local/modsecurity-crs/rules/custom/rule-exclusions.conf', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('SecRuleRemoveById'):
                        parts = line.split()
                        if len(parts) >= 2:
                            excluded_rules.append(parts[1])
        except Exception:
            pass
            
        return jsonify({'success': True, 'custom_rules': custom_rules, 'excluded_rules': excluded_rules})

    elif action == 'crs_status':
        try:
            result = subprocess.run(['sudo', '-n', '/opt/waf-admin/scripts/crs-status.sh'], capture_output=True, text=True, check=True)
            lines = result.stdout.strip().split('\n')
            data = {}
            for line in lines:
                if '=' in line:
                    k, v = line.split('=', 1)
                    data[k] = v
            return jsonify({'success': True, 'data': data})
        except subprocess.CalledProcessError as e:
            return jsonify({'error': 'Command failed', 'details': e.stderr.strip() or e.stdout.strip()}), 500

    else:
        return jsonify({'error': 'Unknown action'}), 400

if __name__ == '__main__':
    app.run(debug=True, port=8082,host='0.0.0.0')
