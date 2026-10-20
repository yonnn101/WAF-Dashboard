#!/usr/bin/env python3
import sys
import os
import glob
import json
import re

CRS_DIR = "/usr/local/modsecurity-crs/rules/"
CUSTOM_RULES = "/usr/local/modsecurity-crs/rules/REQUEST-948-LOCAL-RULES.conf"
EXCLUSIONS = "/usr/local/modsecurity-crs/rules/custom/rule-exclusions.conf"

def get_all_rules():
    disabled_ids = set()
    if os.path.exists(EXCLUSIONS):
        with open(EXCLUSIONS, 'r', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if line.startswith("SecRuleRemoveById"):
                    parts = line.split()
                    for p in parts[1:]:
                        clean_id = p.strip("'\"")
                        if clean_id.isdigit():
                            disabled_ids.add(clean_id)

    rules = []
    conf_files = glob.glob(os.path.join(CRS_DIR, "REQUEST-*.conf")) + \
                 glob.glob(os.path.join(CRS_DIR, "RESPONSE-*.conf")) + \
                 [CUSTOM_RULES]
    custom_order_counter = 0
    for filepath in conf_files:
        if not os.path.exists(filepath): continue
        filename = os.path.basename(filepath)
        is_custom_file = (filename == os.path.basename(CUSTOM_RULES))
        with open(filepath, 'r', errors='ignore') as f: lines = f.readlines()
        current_rule_lines, in_rule, start_line = [], False, 0
        for i, line in enumerate(lines):
            line_str = line.strip()
            if not in_rule:
                if line_str.startswith("SecRule ") or line_str.startswith("SecAction "):
                    in_rule, start_line, current_rule_lines = True, i + 1, [line_str]
            else:
                current_rule_lines.append(line_str)
            if in_rule and not line_str.endswith("\\"):
                full_rule = " ".join(current_rule_lines)
                id_match = re.search(r"id\s*:\s*'?(\d+)'?", full_rule)
                msg_match = re.search(r"msg\s*:\s*'([^']+)'", full_rule)
                if id_match:
                    r_id = id_match.group(1)
                    if is_custom_file:
                        custom_order_counter += 1
                        c_order = custom_order_counter
                    else:
                        c_order = 0
                    rules.append({
                        "id": r_id,
                        "msg": msg_match.group(1) if msg_match else "No description",
                        "file": filename,
                        "raw": "".join(lines[start_line-1:i+1]),
                        "disabled": r_id in disabled_ids,
                        "custom_order": c_order,
                        "is_custom": is_custom_file
                    })
                in_rule = False
    return rules

def safe_reload(filepath):
    import subprocess
    import shutil
    # Detect web server (nginx vs apache2)
    if shutil.which("nginx"):
        res = subprocess.run(["nginx", "-t"], capture_output=True, text=True)
        reload_cmd = ["systemctl", "reload", "nginx"]
    elif shutil.which("apache2ctl"):
        res = subprocess.run(["apache2ctl", "configtest"], capture_output=True, text=True)
        reload_cmd = ["systemctl", "reload", "apache2"]
    else:
        return True, ""

    if res.returncode != 0:
        # Rollback
        if os.path.exists(filepath + ".bak"):
            shutil.move(filepath + ".bak", filepath)
        return False, res.stderr or res.stdout
    # Success
    subprocess.run(reload_cmd, check=False)
    if os.path.exists(filepath + ".bak"):
        os.remove(filepath + ".bak")
    return True, ""

def disable_rule(rule_id):
    if str(rule_id) in ["949110", "959110"]:
        return {"success": False, "error": "Rule 949110 / 959110 is the core WAF anomaly blocking engine and cannot be disabled."}
    import shutil
    os.makedirs(os.path.dirname(EXCLUSIONS), exist_ok=True)
    if os.path.exists(EXCLUSIONS):
        with open(EXCLUSIONS, 'r') as f:
            if f"SecRuleRemoveById {rule_id}" in f.read():
                return {"success": True, "message": "Already disabled"}
        shutil.copy2(EXCLUSIONS, EXCLUSIONS + ".bak")
    with open(EXCLUSIONS, 'a') as f: f.write(f"\nSecRuleRemoveById {rule_id}\n")
    
    ok, err = safe_reload(EXCLUSIONS)
    if not ok: return {"success": False, "error": "Nginx config error", "details": err}
    return {"success": True, "message": f"Rule {rule_id} disabled (override strategy)"}

def enable_rule(rule_id):
    import shutil
    if not os.path.exists(EXCLUSIONS): return {"success": True, "message": "Not disabled"}
    shutil.copy2(EXCLUSIONS, EXCLUSIONS + ".bak")
    with open(EXCLUSIONS, 'r') as f: lines = f.readlines()
    with open(EXCLUSIONS, 'w') as f:
        for line in lines:
            if not re.search(f"SecRuleRemoveById\\s+{rule_id}\\b", line): f.write(line)
            
    ok, err = safe_reload(EXCLUSIONS)
    if not ok: return {"success": False, "error": "Nginx config error", "details": err}
    return {"success": True, "message": f"Rule {rule_id} enabled"}

def remove_rule_from_custom_conf(rule_id):
    if not os.path.exists(CUSTOM_RULES):
        return
    with open(CUSTOM_RULES, 'r', errors='ignore') as f:
        lines = f.readlines()
    
    new_lines = []
    in_target_rule = False
    current_block = []
    
    for line in lines:
        line_str = line.strip()
        if not in_target_rule:
            if line_str.startswith("SecRule ") or line_str.startswith("SecAction "):
                current_block = [line]
                in_target_rule = True
            else:
                new_lines.append(line)
        else:
            current_block.append(line)
        
        if in_target_rule and not line_str.endswith("\\"):
            full_rule = " ".join([l.strip() for l in current_block])
            id_match = re.search(r"id\s*:\s*'?(\d+)'?", full_rule)
            if id_match and id_match.group(1) == str(rule_id):
                # Target rule found! Skip adding current_block to new_lines
                pass
            else:
                new_lines.extend(current_block)
            in_target_rule = False
            current_block = []
            
    if in_target_rule and current_block:
        new_lines.extend(current_block)

    with open(CUSTOM_RULES, 'w') as f:
        f.writelines(new_lines)

def add_custom_rule(raw_text):
    import shutil
    os.makedirs(os.path.dirname(CUSTOM_RULES), exist_ok=True)
    if os.path.exists(CUSTOM_RULES):
        shutil.copy2(CUSTOM_RULES, CUSTOM_RULES + ".bak")
    with open(CUSTOM_RULES, 'a') as f: f.write("\n" + raw_text.strip() + "\n")
    
    ok, err = safe_reload(CUSTOM_RULES)
    if not ok: return {"success": False, "error": "Invalid ModSecurity Syntax", "details": err}
    return {"success": True, "message": "Rule added"}

def edit_rule(rule_id, raw_text):
    if str(rule_id) in ["949110", "959110"]:
        return {"success": False, "error": "Rule 949110 / 959110 is the core WAF anomaly evaluation engine and cannot be edited or overridden."}
    import shutil
    os.makedirs(os.path.dirname(CUSTOM_RULES), exist_ok=True)
    if os.path.exists(CUSTOM_RULES):
        shutil.copy2(CUSTOM_RULES, CUSTOM_RULES + ".bak")
    if os.path.exists(EXCLUSIONS):
        shutil.copy2(EXCLUSIONS, EXCLUSIONS + ".bak")
        
    # Check if rule_id is an official CRS rule
    crs_files = glob.glob(os.path.join(CRS_DIR, "REQUEST-*.conf")) + glob.glob(os.path.join(CRS_DIR, "RESPONSE-*.conf"))
    is_crs_rule = False
    for cf in crs_files:
        if not os.path.exists(cf): continue
        with open(cf, 'r', errors='ignore') as f:
            content = f.read()
            if re.search(rf"\bid\s*:\s*'?{rule_id}'?\b", content):
                is_crs_rule = True
                break

    target_id = str(rule_id)
    if is_crs_rule:
        custom_id = f"1{rule_id}"
        # 1. Remove previous custom overrides for both IDs
        remove_rule_from_custom_conf(rule_id)
        remove_rule_from_custom_conf(custom_id)

        # 2. Exclude original CRS rule from runtime execution
        if os.path.exists(EXCLUSIONS):
            with open(EXCLUSIONS, 'r') as f: ex_content = f.read()
            if f"SecRuleRemoveById {rule_id}" not in ex_content:
                with open(EXCLUSIONS, 'a') as f:
                    f.write(f"\nSecRuleRemoveById {rule_id}\n")
        else:
            with open(EXCLUSIONS, 'w') as f:
                f.write(f"\nSecRuleRemoveById {rule_id}\n")

        # 3. Replace ID in raw_text with custom_id so ModSecurity compiler sees a unique ID
        raw_text = re.sub(rf"\bid\s*:\s*'?{rule_id}'?\b", f"id:{custom_id}", raw_text, count=1)
    else:
        # Custom rule edit: remove existing definition in local-rules.conf
        remove_rule_from_custom_conf(rule_id)
        # If disabled in exclusions, re-enable
        if os.path.exists(EXCLUSIONS):
            with open(EXCLUSIONS, 'r') as f: lines = f.readlines()
            with open(EXCLUSIONS, 'w') as f:
                for line in lines:
                    if not re.search(f"SecRuleRemoveById\\s+{rule_id}\\b", line):
                        f.write(line)

    # 4. Append modified rule text to local-rules.conf
    with open(CUSTOM_RULES, 'a') as f:
        f.write("\n" + raw_text.strip() + "\n")
        
    # 5. Validate syntax with safe_reload
    ok, err = safe_reload(CUSTOM_RULES)
    if not ok:
        if os.path.exists(EXCLUSIONS + ".bak"):
            shutil.move(EXCLUSIONS + ".bak", EXCLUSIONS)
        return {"success": False, "error": "Invalid ModSecurity Syntax", "details": err}
        
    if os.path.exists(EXCLUSIONS + ".bak"):
        os.remove(EXCLUSIONS + ".bak")
    return {"success": True, "message": f"Rule {rule_id} edited successfully"}

def delete_rule(rule_id):
    if str(rule_id) in ["949110", "959110"]:
        return {"success": False, "error": "Rule 949110 / 959110 is the core WAF engine and cannot be deleted."}
    import shutil
    os.makedirs(os.path.dirname(CUSTOM_RULES), exist_ok=True)
    if os.path.exists(CUSTOM_RULES):
        shutil.copy2(CUSTOM_RULES, CUSTOM_RULES + ".bak")
    if os.path.exists(EXCLUSIONS):
        shutil.copy2(EXCLUSIONS, EXCLUSIONS + ".bak")

    # 1. Remove from CUSTOM_RULES
    remove_rule_from_custom_conf(rule_id)
    if not str(rule_id).startswith("1"):
        remove_rule_from_custom_conf(f"1{rule_id}")

    # Check if rule_id is an official CRS rule
    crs_files = glob.glob(os.path.join(CRS_DIR, "REQUEST-*.conf")) + glob.glob(os.path.join(CRS_DIR, "RESPONSE-*.conf"))
    is_crs_rule = False
    for cf in crs_files:
        if not os.path.exists(cf): continue
        with open(cf, 'r', errors='ignore') as f:
            if re.search(rf"\bid\s*:\s*'?{rule_id}'?\b", f.read()):
                is_crs_rule = True
                break

    if is_crs_rule:
        # Add SecRuleRemoveById rule_id to EXCLUSIONS so original rule is disabled
        os.makedirs(os.path.dirname(EXCLUSIONS), exist_ok=True)
        ex_content = ""
        if os.path.exists(EXCLUSIONS):
            with open(EXCLUSIONS, 'r') as f: ex_content = f.read()
        if f"SecRuleRemoveById {rule_id}" not in ex_content:
            with open(EXCLUSIONS, 'a') as f:
                f.write(f"\nSecRuleRemoveById {rule_id}\n")
    else:
        # Custom rule deletion: clean up any SecRuleRemoveById from EXCLUSIONS
        if os.path.exists(EXCLUSIONS):
            with open(EXCLUSIONS, 'r') as f: lines = f.readlines()
            with open(EXCLUSIONS, 'w') as f:
                for line in lines:
                    if not re.search(rf"SecRuleRemoveById\s+{rule_id}\b", line):
                        f.write(line)

    ok, err = safe_reload(CUSTOM_RULES)
    if not ok:
        if os.path.exists(CUSTOM_RULES + ".bak"):
            shutil.move(CUSTOM_RULES + ".bak", CUSTOM_RULES)
        if os.path.exists(EXCLUSIONS + ".bak"):
            shutil.move(EXCLUSIONS + ".bak", EXCLUSIONS)
        return {"success": False, "error": "Invalid ModSecurity Syntax", "details": err}

    if os.path.exists(CUSTOM_RULES + ".bak"): os.remove(CUSTOM_RULES + ".bak")
    if os.path.exists(EXCLUSIONS + ".bak"): os.remove(EXCLUSIONS + ".bak")
    return {"success": True, "message": f"Rule {rule_id} deleted successfully"}

if __name__ == "__main__":
    if len(sys.argv) < 2: sys.exit(1)
    action = sys.argv[1]
    try:
        if action == "list": print(json.dumps({"success": True, "data": get_all_rules()}))
        elif action == "disable": print(json.dumps(disable_rule(sys.argv[2])))
        elif action == "enable": print(json.dumps(enable_rule(sys.argv[2])))
        elif action == "add": print(json.dumps(add_custom_rule(sys.argv[2])))
        elif action == "edit": print(json.dumps(edit_rule(sys.argv[2], sys.argv[3])))
        elif action == "delete": print(json.dumps(delete_rule(sys.argv[2])))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
