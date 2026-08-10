import time
import requests
import config
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def supabase_get(table: str, params: dict = None) -> tuple:
    """
    Returns (data, latency_ms, error_string)
    """
    if params is None:
        params = {}
    
    url = f"{config.SUPABASE_URL.rstrip('/')}/rest/v1/{table}"
    
    headers = {
        'apikey': config.SUPABASE_ANON_KEY,
        'Authorization': f'Bearer {config.SUPABASE_ANON_KEY}',
        'Accept': 'application/json'
    }
    
    start_time = time.time()
    try:
        response = requests.get(
            url, 
            params=params, 
            headers=headers, 
            timeout=config.AJAX_TIMEOUT, 
            verify=False
        )
        latency = int(round((time.time() - start_time) * 1000))
        
        if not response.ok:
            return (None, latency, f"HTTP {response.status_code}")
            
        data = response.json()
        return (data, latency, None)
        
    except Exception as e:
        latency = int(round((time.time() - start_time) * 1000))
        return (None, latency, f"Request Exception: {str(e)}")

def health_check() -> dict:
    start_time = time.time()
    data, latency, err = supabase_get('modsec_events', {'select': 'event_time', 'limit': 1})
    total_latency = int(round((time.time() - start_time) * 1000))
    return {
        'ok': err is None,
        'latency': total_latency,
        'error': err
    }
