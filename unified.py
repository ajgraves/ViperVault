#!/usr/bin/env python3
import cgi
import subprocess
import json
import os
import time
import secrets
import http.cookies
import html
import secrets

# ────────────────────────────────────────────────
#          CONFIGURATION ── LOADED FROM FILE
# ────────────────────────────────────────────────
CONFIG_FILE = "unified_config.json"
SESSION_DIR = ".sessions"  # Directory to store session files

# Load configuration from JSON file
def load_config():
    """Load configuration from JSON file"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, CONFIG_FILE)
    
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
        return config
    except FileNotFoundError:
        print("Content-Type: text/plain")
        print("")
        print(f"Error: Configuration file '{CONFIG_FILE}' not found.")
        exit(1)
    except json.JSONDecodeError as e:
        print("Content-Type: text/plain")
        print("")
        print(f"Error: Invalid JSON in configuration file: {e}")
        exit(1)

# Load configuration
config = load_config()
PASSWORD = config.get('password', 'correct horse battery staple')
REFRESH_INTERVAL = config.get('refresh_interval', 30)
SESSION_DURATION = config.get('session_duration', 86400)
INACTIVITY_TIMEOUT = config.get('inactivity_timeout', 3600)
LOG_VIEWS = config.get('log_views', {})

# Normalize LOG_VIEWS to ensure every entry has a 'cmd' and 'refresh'
NORMALIZED_VIEWS = {}
for name, view_config in LOG_VIEWS.items():
    if isinstance(view_config, str):
        NORMALIZED_VIEWS[name] = {
            "cmd": view_config,
            "refresh": REFRESH_INTERVAL,
            "safe_output": True,
            "bottom": False                     # ← new, default false
        }
    else:
        NORMALIZED_VIEWS[name] = {
            "cmd": view_config.get("cmd", ""),
            "refresh": view_config["refresh"] if "refresh" in view_config else REFRESH_INTERVAL,
            "safe_output": view_config.get("safe_output", True),
            "bottom": view_config.get("bottom", False)   # ← new
        }

SORTED_LOG_VIEWS = dict(sorted(NORMALIZED_VIEWS.items()))
# ────────────────────────────────────────────────

# ────────────────────────────────────────────────
#          SESSION MANAGEMENT FUNCTIONS
# ────────────────────────────────────────────────

def ensure_session_dir():
    """Create session directory if it doesn't exist"""
    if not os.path.exists(SESSION_DIR):
        os.makedirs(SESSION_DIR, mode=0o700)

def cleanup_old_sessions():
    """Remove expired sessions"""
    if not os.path.exists(SESSION_DIR):
        return
    
    current_time = time.time()
    for filename in os.listdir(SESSION_DIR):
        if filename.endswith('.json'):
            filepath = os.path.join(SESSION_DIR, filename)
            try:
                with open(filepath, 'r') as f:
                    session_data = json.load(f)
                
                created = session_data.get('created', 0)
                last_activity = session_data.get('last_activity', 0)
                
                # Check if session has exceeded max duration or inactivity timeout
                if (current_time - created > SESSION_DURATION or 
                    current_time - last_activity > INACTIVITY_TIMEOUT):
                    os.remove(filepath)
            except (json.JSONDecodeError, IOError):
                # Remove corrupted session files
                try:
                    os.remove(filepath)
                except:
                    pass

def create_session():
    """Create a new session and return the session token"""
    ensure_session_dir()
    cleanup_old_sessions()
    
    session_token = secrets.token_urlsafe(32)
    current_time = time.time()
    
    session_data = {
        'created': current_time,
        'last_activity': current_time
    }
    
    session_file = os.path.join(SESSION_DIR, f"{session_token}.json")
    with open(session_file, 'w') as f:
        json.dump(session_data, f)
    os.chmod(session_file, 0o600)
    
    return session_token

def validate_session(session_token):
    """Validate a session token and update last activity time"""
    if not session_token:
        return False
    
    session_file = os.path.join(SESSION_DIR, f"{session_token}.json")
    
    if not os.path.exists(session_file):
        return False
    
    try:
        with open(session_file, 'r') as f:
            session_data = json.load(f)
        
        current_time = time.time()
        created = session_data.get('created', 0)
        last_activity = session_data.get('last_activity', 0)
        
        # Check if session is still valid
        if (current_time - created > SESSION_DURATION or 
            current_time - last_activity > INACTIVITY_TIMEOUT):
            os.remove(session_file)
            return False
        
        # Update last activity time
        session_data['last_activity'] = current_time
        with open(session_file, 'w') as f:
            json.dump(session_data, f)
        
        return True
    except (json.JSONDecodeError, IOError):
        return False

def destroy_session(session_token):
    """Delete a session"""
    if not session_token:
        return
    
    session_file = os.path.join(SESSION_DIR, f"{session_token}.json")
    try:
        if os.path.exists(session_file):
            os.remove(session_file)
    except:
        pass

def get_session_cookie():
    """Extract session token from cookies"""
    cookie_header = os.environ.get('HTTP_COOKIE', '')
    if not cookie_header:
        return None
    
    try:
        cookie = http.cookies.SimpleCookie()
        cookie.load(cookie_header)
        if 'session_token' in cookie:
            return cookie['session_token'].value
    except:
        pass
    
    return None

def set_session_cookie(session_token):
    """Generate Set-Cookie header for session token"""
    cookie = http.cookies.SimpleCookie()
    cookie['session_token'] = session_token
    cookie['session_token']['path'] = '/'
    cookie['session_token']['max-age'] = SESSION_DURATION
    cookie['session_token']['httponly'] = True
    cookie['session_token']['samesite'] = 'Lax'  # Changed from Strict to allow same-site redirects
    
    # Add Secure flag if HTTPS is being used
    if os.environ.get('HTTPS') == 'on' or os.environ.get('REQUEST_SCHEME') == 'https':
        cookie['session_token']['secure'] = True
    
    return cookie.output()

def clear_session_cookie():
    """Generate Set-Cookie header to clear the session cookie"""
    cookie = http.cookies.SimpleCookie()
    cookie['session_token'] = ''
    cookie['session_token']['path'] = '/'
    cookie['session_token']['max-age'] = 0
    cookie['session_token']['httponly'] = True
    cookie['session_token']['samesite'] = 'Lax'  # Changed from Strict for consistency
    
    if os.environ.get('HTTPS') == 'on' or os.environ.get('REQUEST_SCHEME') == 'https':
        cookie['session_token']['secure'] = True
    
    return cookie.output()

# ────────────────────────────────────────────────

def get_log_output(command):
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True, text=True, check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error running command: {e.stderr}\nReturn code: {e.returncode}"
    except Exception as e:
        return f"Unexpected error: {str(e)}"

form = cgi.FieldStorage()
action = form.getvalue('action')
selected_view = form.getvalue('view')

# Handle login action
if action == 'login':
    password_attempt = form.getvalue('password', '')
    
    if password_attempt == PASSWORD:
        session_token = create_session()
        print(set_session_cookie(session_token))
        print("Content-Type: application/json")
        print("")
        print(json.dumps({"success": True}))
    else:
        print("Content-Type: application/json")
        print("")
        print(json.dumps({"success": False}))

# Handle logout action
elif action == 'logout':
    session_token = get_session_cookie()
    if session_token:
        destroy_session(session_token)
    print(clear_session_cookie())
    print("Content-Type: application/json")
    print("")
    print(json.dumps({"success": True}))

# Handle session check action
elif action == 'check_session':
    session_token = get_session_cookie()
    is_valid = validate_session(session_token)
    print("Content-Type: application/json")
    print("")
    print(json.dumps({"authenticated": is_valid}))

# Handle get_log action - requires authentication
elif action == 'get_log':
    session_token = get_session_cookie()
       
    if not validate_session(session_token):
        print("Content-Type: text/plain")
        print("")
        print("Unauthorized: Invalid or expired session.")
    elif not selected_view or selected_view not in SORTED_LOG_VIEWS:
        print("Content-Type: text/plain")
        print("")
        print("Invalid or missing log view selection.")
    else:
        try:
            view_config = SORTED_LOG_VIEWS[selected_view]
            command = view_config["cmd"]
            raw_output = get_log_output(command)

            # Conditional escaping — default is True (escaped)
            if view_config.get("safe_output", True):
                output = html.escape(raw_output, quote=False)
            else:
                output = raw_output

            print("Content-Type: text/plain; charset=utf-8")
            print("")
            print(output)
        except Exception as e:
            print("Content-Type: text/plain")
            print("")
            print(f"Error executing command: {str(e)}")

# Default: Show the main page
else:
    # Generate nonce (22 characters is typical after stripping padding)
    nonce = secrets.token_urlsafe(16)

    print(f"Content-Security-Policy: default-src 'self'; script-src 'self' https://code.jquery.com 'nonce-{nonce}'; style-src 'self' 'unsafe-inline';")  # ← ADDED CSP
    print("Content-Type: text/html; charset=utf-8")
    print("")
    log_config_json = json.dumps({
        name: {
            "refresh": v["refresh"],
            "bottom": v["bottom"]
        }
        for name, v in SORTED_LOG_VIEWS.items()
    })
    
    print(f"""\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Unified Log Viewer</title>
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <style>
        :root {{
            --bg-color: #ffffff;
            --text-color: #000000;
            --log-bg: #f8f8f8;
            --log-border: #ccc;
            --timer-color: #555;
            --heading-color: #0066cc;
            --select-bg: #fff;
            --select-border: #ccc;
            --btn-bg: #eee;
        }}
        body.dark {{
            --bg-color: #0d1117;
            --text-color: #c9d1d9;
            --log-bg: #161b22;
            --log-border: #30363d;
            --timer-color: #8b949e;
            --heading-color: #58a6ff;
            --select-bg: #21262d;
            --select-border: #30363d;
            --btn-bg: #30363d;
        }}
        html, body {{ height: 100%; margin: 0; padding: 0; overflow: hidden; }}
        body {{
            font-family: monospace;
            background-color: var(--bg-color);
            color: var(--text-color);
            transition: background-color 0.3s, color 0.3s;
        }}
        #login-screen {{
            display: flex; align-items: center; justify-content: center;
            height: 100vh; flex-direction: column; gap: 20px;
        }}
        #login-screen h1 {{ color: var(--heading-color); margin: 0; }}
        #login-form {{ display: flex; flex-direction: column; gap: 12px; min-width: 300px; }}
        #login-form input {{
            padding: 10px; font-family: monospace; font-size: 1em;
            background: var(--select-bg); color: var(--text-color);
            border: 1px solid var(--select-border); border-radius: 6px;
        }}
        #login-form button {{
            padding: 10px; font-family: monospace; font-size: 1em;
            background: var(--heading-color); color: white;
            border: none; border-radius: 6px; cursor: pointer;
        }}
        #login-error {{
            color: #d73a49; display: none; text-align: center;
        }}
        #content {{
            display: none; flex-direction: column;
            height: 100vh; padding: 20px; padding-top: 60px; box-sizing: border-box;
        }}
        #controls {{
            margin-bottom: 12px; display: flex; flex-wrap: wrap; gap: 12px; align-items: center;
        }}
        @media (max-width: 768px) {{
            #content {{
                padding-top: 20px;
            }}
        }}
        select, #log-search {{
            padding: 8px 12px; font-family: monospace;
            background: var(--select-bg); color: var(--text-color);
            border: 1px solid var(--select-border); border-radius: 6px;
        }}
        select {{ min-width: 260px; }}
        #search-container {{
            position: relative; flex-grow: 1; display: flex; align-items: center; min-width: 200px;
        }}
        #log-search {{ width: 100%; padding-right: 60px; }}
        #search-tools {{
            position: absolute; right: 10px; display: flex; align-items: center; gap: 8px;
            user-select: none; font-size: 0.8em;
        }}
        #clear-search {{ cursor: pointer; font-weight: bold; color: var(--timer-color); display: none; }}
        .regex-badge {{ color: var(--heading-color); opacity: 0.6; font-size: 0.7em; border: 1px solid; padding: 1px 3px; border-radius: 3px; }}
        
        #log-output {{
            flex-grow: 1; white-space: pre-wrap; background-color: var(--log-bg);
            border: 1px solid var(--log-border); padding: 12px; overflow-y: auto;
            border-radius: 6px; margin-bottom: 12px;
        }}
        #status-bar {{ display: flex; align-items: center; gap: 12px; font-size: 0.9em; color: var(--timer-color); }}
        #pause-btn {{
            padding: 4px 12px; cursor: pointer; border: 1px solid var(--log-border);
            border-radius: 4px; font-family: monospace; font-weight: bold; color: white;
            transition: background-color 0.2s;
        }}
        .btn-running {{ background-color: #d73a49 !important; }}
        .btn-paused {{ background-color: #28a745 !important; }}
        #top-controls {{
            position: fixed; top: 15px; right: 20px; display: flex; gap: 8px; z-index: 100;
        }}
        @media (max-width: 768px) {{
            #top-controls {{
                position: static; margin-bottom: 12px; justify-content: flex-end;
            }}
        }}
        #theme-toggle, #logout-btn {{
            padding: 8px 12px; background: var(--log-bg);
            border: 1px solid var(--log-border); color: var(--text-color);
            cursor: pointer; border-radius: 4px; font-size: 1.2em;
        }}
        h1 {{ color: var(--heading-color); margin: 0 0 8px 0; }}
        #log-output::-webkit-scrollbar {{ width: 8px; }}
        #log-output::-webkit-scrollbar-thumb {{ background: var(--log-border); border-radius: 4px; }}
    </style>
</head>
<body>
    <div id="login-screen">
        <h1>Log Viewer</h1>
        <form id="login-form">
            <input type="password" id="password-input" placeholder="Enter password" autocomplete="off">
            <button type="submit">Login</button>
            <div id="login-error">Invalid password. Please try again.</div>
        </form>
    </div>

    <div id="content">
        <div id="top-controls">
            <button id="theme-toggle">🌙</button>
            <button id="logout-btn" title="Logout">🚪</button>
        </div>
        <h1 id="log-title">Log Viewer</h1>
        <div id="controls">
            <select id="log-selector">
                <option value="" disabled selected>Select log source...</option>
""")

    for name in SORTED_LOG_VIEWS:
        print(f'                <option value="{name}">{name}</option>')

    print(f"""\
            </select>
            <div id="search-container">
                <input type="text" id="log-search" placeholder="Filter (supports Regex) - Press '/' to search..." autocomplete="off">
                <div id="search-tools">
                    <span class="regex-badge">REGEX</span>
                    <span id="clear-search">X</span>
                </div>
            </div>
        </div>
        <div id="log-output">Select a log source to begin...</div>
        <div id="status-bar">
            <button id="pause-btn" class="btn-running">Pause</button>
            <span id="timer"></span>
        </div>
    </div>

    <script nonce="{nonce}">
        const DEFAULT_INTERVAL = {REFRESH_INTERVAL};
        const LOG_CONFIG = {log_config_json};
        const STORAGE_KEY = "lastSelectedLogView";

        let rawLogData = "";
        let countdown;
        let refreshTimeout;
        let currentView = null;
        let isPaused = false;
        let isAuthenticated = false;

        const loginScreen = document.getElementById('login-screen');
        const contentDiv = document.getElementById('content');
        const loginForm = document.getElementById('login-form');
        const passwordInput = document.getElementById('password-input');
        const loginError = document.getElementById('login-error');
        const timerEl = document.getElementById('timer');
        const pauseBtn = document.getElementById('pause-btn');
        const searchInput = document.getElementById('log-search');
        const clearSearchBtn = document.getElementById('clear-search');
        const logoutBtn = document.getElementById('logout-btn');

        function getInterval() {{
            // Ensure we check if the value is strictly undefined/null 
            // rather than just 'Falsy'
            if (currentView && LOG_CONFIG[currentView] !== undefined) {{
                return LOG_CONFIG[currentView].refresh;
            }}
            return DEFAULT_INTERVAL;
        }}

        function applyFilter() {{
            const term = searchInput.value;
            clearSearchBtn.style.display = term ? 'block' : 'none';

            if (!term) {{
                $('#log-output').text(rawLogData);
                return;
            }}

            try {{
                // Try Regex first
                const regex = new RegExp(term, 'i');
                const filtered = rawLogData.split('\\n').filter(line => regex.test(line)).join('\\n');
                $('#log-output').text(filtered || "-- No regex matches found --");
            }} catch (e) {{
                // Fallback to simple include if regex is invalid/incomplete while typing
                const lowerTerm = term.toLowerCase();
                const filtered = rawLogData.split('\\n').filter(line => line.toLowerCase().includes(lowerTerm)).join('\\n');
                $('#log-output').text(filtered || "-- No matches found --");
            }}
        }}

        function startCountdown() {{
            const interval = getInterval();
            if (isPaused || interval <= 0) return;
            let timeLeft = interval;
            clearInterval(countdown);
            
            countdown = setInterval(() => {{
                if (isPaused) return;
                timeLeft--;
                timerEl.textContent = `Next refresh in ${{timeLeft}}s (Rate: ${{getInterval()}}s)`;
                if (timeLeft <= 0) {{
                    clearInterval(countdown);
                    timerEl.textContent = "Refreshing...";
                }}
            }}, 1000);
        }}

        function handleUnauthorized() {{
            isAuthenticated = false;
            contentDiv.style.display = 'none';
            loginScreen.style.display = 'flex';
            loginError.textContent = "Session expired. Please login again.";
            loginError.style.display = 'block';
            clearTimeout(refreshTimeout);
            clearInterval(countdown);
        }}

        function loadLogs() {{
            if (!currentView || !isAuthenticated) return;
            clearTimeout(refreshTimeout);

            if (isPaused) {{
                refreshTimeout = setTimeout(loadLogs, 1000);
                return;
            }}

            $.ajax({{
                url: `?action=get_log&view=${{encodeURIComponent(currentView)}}`,
                type: 'GET',
                success: function(data) {{
                    if (data.startsWith('Unauthorized:')) {{
                        handleUnauthorized();
                        return;
                    }}
                    rawLogData = data;
                    applyFilter();
    
                    // ── NEW ── Auto-scroll to bottom if configured for this view
                    if (LOG_CONFIG[currentView]?.bottom === true) {{
                        const logOutput = document.getElementById('log-output');
                        logOutput.scrollTop = logOutput.scrollHeight;
                    }}

                    const interval = getInterval();
                    if (interval > 0) {{
                        startCountdown();
                        refreshTimeout = setTimeout(loadLogs, interval * 1000);
                    }} else {{
                        clearInterval(countdown);
                        timerEl.textContent = "Auto-refresh disabled";
                    }}
                }},
                error: function(xhr, status, error) {{
                    console.error('AJAX error:', status, error);
                    timerEl.textContent = "Error — retrying...";
                    refreshTimeout = setTimeout(loadLogs, 5000);
                }}
            }});
        }}

        pauseBtn.addEventListener('click', () => {{
            isPaused = !isPaused;
            pauseBtn.textContent = isPaused ? "Resume" : "Pause";
            if (isPaused) {{
                pauseBtn.className = 'btn-paused';
                clearInterval(countdown);
                clearTimeout(refreshTimeout);
                timerEl.textContent = "(Paused)";
            }} else {{
                pauseBtn.className = 'btn-running';
                // Immediately refresh the logs when resuming
                loadLogs();
            }}
        }});

        function triggerSelection(viewName) {{
            currentView = viewName;
            if (currentView) {{
                const interval = getInterval();
                // Hide pause button if refresh is disabled (<= 0)
                pauseBtn.style.display = interval > 0 ? "block" : "none";

                isPaused = false;
                pauseBtn.className = 'btn-running';
                pauseBtn.textContent = "Pause";
                document.getElementById('log-title').textContent = currentView;
                localStorage.setItem(STORAGE_KEY, currentView);
                $('#log-output').text('Loading...');
                clearInterval(countdown);
                clearTimeout(refreshTimeout);
                if (interval > 0) {{
                    timerEl.textContent = "Loading... (Refresh rate: " + interval + "s)";
                }} else {{
                    timerEl.textContent = "Loading... (Auto-refresh disabled)";
                }}
                loadLogs();
            }}
        }}

        searchInput.addEventListener('input', applyFilter);
        clearSearchBtn.addEventListener('click', () => {{
            searchInput.value = "";
            applyFilter();
            searchInput.focus();
        }});

        document.addEventListener('keydown', (e) => {{
            // Escape key logic: Clear and unfocus search if already in the field
            if (e.key === "Escape" && document.activeElement === searchInput) {{
                searchInput.value = "";
                applyFilter();
                searchInput.blur(); // Optional: removes focus from the box after clearing
            }} 
            // Slash key logic: Focus search if not already typing elsewhere
            else if (e.key === "/" && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {{
                e.preventDefault(); 
                searchInput.focus();
            }}
        }});

        $('#log-selector').on('change', function() {{ triggerSelection(this.value); }});

        loginForm.addEventListener('submit', (e) => {{
            e.preventDefault();
            const password = passwordInput.value;
            
            $.ajax({{
                url: '?action=login',
                type: 'POST',
                data: {{ password: password }},
                dataType: 'json',
                success: function(response) {{
                    if (response.success) {{
                        isAuthenticated = true;
                        loginScreen.style.display = 'none';
                        contentDiv.style.display = 'flex';
                        loginError.style.display = 'none';
                        passwordInput.value = '';
                        initTheme();
                        
                        const saved = localStorage.getItem(STORAGE_KEY);
                        const selector = document.getElementById('log-selector');
                        if (saved && [...selector.options].some(o => o.value === saved)) {{
                            selector.value = saved;
                            triggerSelection(saved);
                        }} else if (selector.options.length > 1) {{
                            const first = selector.options[1].value;
                            selector.value = first;
                            triggerSelection(first);
                        }}
                    }} else {{
                        loginError.style.display = 'block';
                        passwordInput.value = '';
                        passwordInput.focus();
                    }}
                }},
                error: function() {{
                    loginError.textContent = "Login error. Please try again.";
                    loginError.style.display = 'block';
                }}
            }});
        }});

        logoutBtn.addEventListener('click', () => {{
            $.ajax({{
                url: '?action=logout',
                type: 'POST',
                dataType: 'json',
                success: function() {{
                    isAuthenticated = false;
                    contentDiv.style.display = 'none';
                    loginScreen.style.display = 'flex';
                    loginError.style.display = 'none';
                    clearTimeout(refreshTimeout);
                    clearInterval(countdown);
                    currentView = null;
                }}
            }});
        }});

        function setTheme(t) {{
            t === 'dark' ? document.body.classList.add('dark') : document.body.classList.remove('dark');
            document.getElementById('theme-toggle').textContent = t === 'dark' ? '☀️' : '🌙';
            localStorage.setItem('theme', t);
        }}
        function initTheme() {{
            setTheme(localStorage.getItem('theme') || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'));
        }}
        document.getElementById('theme-toggle').addEventListener('click', () => setTheme(document.body.classList.contains('dark') ? 'light' : 'dark'));

        function checkExistingSession() {{
            $.ajax({{
                url: '?action=check_session',
                type: 'GET',
                dataType: 'json',
                success: function(response) {{
                    if (response.authenticated) {{
                        isAuthenticated = true;
                        loginScreen.style.display = 'none';
                        contentDiv.style.display = 'flex';
                        initTheme();
                        
                        const saved = localStorage.getItem(STORAGE_KEY);
                        const selector = document.getElementById('log-selector');
                        if (saved && [...selector.options].some(o => o.value === saved)) {{
                            selector.value = saved;
                            triggerSelection(saved);
                        }} else if (selector.options.length > 1) {{
                            const first = selector.options[1].value;
                            selector.value = first;
                            triggerSelection(first);
                        }}
                    }} else {{
                        loginScreen.style.display = 'flex';
                        passwordInput.focus();
                    }}
                }},
                error: function() {{
                    loginScreen.style.display = 'flex';
                    passwordInput.focus();
                }}
            }});
        }}

        window.onload = () => {{
            initTheme();
            checkExistingSession();
        }};
    </script>
</body>
</html>
""")