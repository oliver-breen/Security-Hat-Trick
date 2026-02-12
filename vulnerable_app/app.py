"""
Vulnerable Web Application for Security Testing
This application intentionally contains security vulnerabilities for testing purposes.
DO NOT deploy this in production!
"""
import sqlite3
import os
import subprocess
from flask import Flask, request, render_template_string, jsonify, send_file

app = Flask(__name__)

# Initialize a simple SQLite database
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT)''')
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin@example.com')")
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'pass123', 'user@example.com')")
    conn.commit()
    conn.close()

@app.route('/')
def index():
    return '''
    <html>
    <head><title>Vulnerable App</title></head>
    <body>
        <h1>Vulnerable Web Application</h1>
        <p>This application intentionally contains security vulnerabilities for testing.</p>
        <ul>
            <li><a href="/search">Search Users (SQL Injection)</a></li>
            <li><a href="/greet">Greet User (XSS)</a></li>
            <li><a href="/ping">Ping Host (Command Injection)</a></li>
            <li><a href="/file">Read File (Path Traversal)</a></li>
        </ul>
    </body>
    </html>
    '''

@app.route('/search')
def search():
    """Vulnerable to SQL Injection"""
    query = request.args.get('q', '')
    if query:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        # VULNERABLE: Direct string concatenation
        sql = f"SELECT username, email FROM users WHERE username LIKE '%{query}%'"
        try:
            c.execute(sql)
            results = c.fetchall()
            conn.close()
            return jsonify({'results': results, 'query': sql})
        except Exception as e:
            conn.close()
            return jsonify({'error': str(e), 'query': sql})
    return '''
    <html>
    <body>
        <h2>Search Users</h2>
        <form action="/search" method="get">
            <input type="text" name="q" placeholder="Enter username">
            <input type="submit" value="Search">
        </form>
    </body>
    </html>
    '''

@app.route('/greet')
def greet():
    """Vulnerable to XSS (Cross-Site Scripting)"""
    name = request.args.get('name', 'Guest')
    # VULNERABLE: Unsanitized user input in HTML
    template = f'''
    <html>
    <body>
        <h2>Hello, {name}!</h2>
        <p>Welcome to our vulnerable application.</p>
        <form action="/greet" method="get">
            <input type="text" name="name" placeholder="Enter your name">
            <input type="submit" value="Greet">
        </form>
    </body>
    </html>
    '''
    return render_template_string(template)

@app.route('/ping')
def ping():
    """Vulnerable to Command Injection"""
    host = request.args.get('host', '')
    if host:
        # VULNERABLE: Direct command execution with user input
        try:
            result = subprocess.check_output(f'ping -c 1 {host}', shell=True, stderr=subprocess.STDOUT, timeout=5)
            return f'<pre>{result.decode()}</pre>'
        except subprocess.TimeoutExpired:
            return 'Request timeout'
        except Exception as e:
            return f'<pre>Error: {str(e)}</pre>'
    return '''
    <html>
    <body>
        <h2>Ping Host</h2>
        <form action="/ping" method="get">
            <input type="text" name="host" placeholder="Enter host">
            <input type="submit" value="Ping">
        </form>
    </body>
    </html>
    '''

@app.route('/file')
def read_file():
    """Vulnerable to Path Traversal"""
    filename = request.args.get('name', '')
    if filename:
        # VULNERABLE: No path validation
        try:
            filepath = os.path.join('files', filename)
            with open(filepath, 'r') as f:
                content = f.read()
            return f'<pre>{content}</pre>'
        except Exception as e:
            return f'Error: {str(e)}'
    return '''
    <html>
    <body>
        <h2>Read File</h2>
        <form action="/file" method="get">
            <input type="text" name="name" placeholder="Enter filename">
            <input type="submit" value="Read">
        </form>
    </body>
    </html>
    '''

if __name__ == '__main__':
    init_db()
    # Create sample files directory
    os.makedirs('files', exist_ok=True)
    with open('files/sample.txt', 'w') as f:
        f.write('This is a sample file.')
    
    # WARNING: NEVER USE THESE SETTINGS IN PRODUCTION!
    # debug=True and host='0.0.0.0' expose sensitive debugging information to all network interfaces
    # This is intentionally vulnerable for testing purposes only
    app.run(debug=True, host='0.0.0.0', port=5000)
