import time
from functools import wraps
from flask import request, session, redirect, url_for, render_template
import config

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not config.AUTH_ENABLED:
            return f(*args, **kwargs)
            
        if not session.get('waf_auth'):
            return redirect(url_for('login', next=request.url))
            
        # Session IP guard
        if session.get('auth_ip') != request.remote_addr:
            session.clear()
            return redirect(url_for('login', next=request.url))
            
        return f(*args, **kwargs)
    return decorated_function
