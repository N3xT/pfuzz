from flask import Flask, request, jsonify, render_template_string
import sqlite3
import subprocess

# This code is vulnerable to various explotis and it's used to test the script
# DO NOT RUN IT ON A PUBLIC SERVICE!!!!

app = Flask(__name__)

@app.route('/')
def home():
    return '''
    <h1>SSTI Vulnerability Demo</h1>
    <form action="/vulnerable" method="post">
        <label for="name">Enter your name:</label>
        <input type="text" id="name" name="name">
        <input type="submit" value="Submit">
    </form>
    '''

# Vulnerable Command Injection
@app.route('/command_injection', methods=['GET'])
def command_injection():
    cmd = request.args.get('cmd', '')
    # Vulnerable to command injection
    output = subprocess.getoutput(cmd)
    return f"<pre>{output}</pre>"

# Vulnerable Local File Inclusion
@app.route('/lfi', methods=['GET'])
def lfi():
    file_name = request.args.get('file', '')

    # Vulnerable to local file inclusion (LFI)
    try:
        # Directly opening the file specified by the user without validation
        with open(file_name, 'r') as file:
            return f"<pre>{file.read()}</pre>"
    except FileNotFoundError:
        return "File not found."

# Vulnerable SQL Injection
@app.route('/sqli', methods=['GET'])
def sqli():
    query = request.args.get('query', '')
    # Vulnerable to SQLi
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return jsonify(results)

# Vulnerable SSTI via POST and GET
@app.route('/ssti', methods=['POST', 'GET'])
def vulnerable():
    if request.method == "GET":
        name = request.args.get('name')
        template = f"Hello, {name}!"
        return render_template_string(template)
    elif request.method == "POST":
        name = request.form.get("name")
        if not name and request.get_json():
            data = request.get_json()
            name = data.get("name")
        template = f"Hello, {name}!"
        return render_template_string(template)

# Static vulnerable robots.txt
@app.route('/robots.txt', methods=['GET'])
def robots():
    return render_template_string("User-agent: *<br>Allow: /")

# Initialize the database for SQLi
def init_db():
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    cursor.execute("INSERT INTO users (username, password) VALUES ('admin', 'admin123')")
    cursor.execute("INSERT INTO users (username, password) VALUES ('guest', 'guest123')")
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
