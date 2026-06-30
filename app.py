from flask import Flask, request, jsonify, send_file
import json
import os

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

DATABASE_URL = os.environ.get('DATABASE_URL')

if DATABASE_URL:
    import pg8000.native
    import urllib.parse

    def get_db():
        r = urllib.parse.urlparse(DATABASE_URL)
        return pg8000.native.Connection(
            host=r.hostname, port=r.port or 5432,
            database=r.path.lstrip('/'), user=r.username,
            password=r.password, ssl_context=True
        )

    def init_db():
        conn = get_db()
        conn.run('CREATE TABLE IF NOT EXISTS store (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
        conn.close()

    def db_load_all():
        conn = get_db()
        rows = conn.run('SELECT key, value FROM store')
        conn.close()
        result = {}
        for key, value in rows:
            try: result[key] = json.loads(value)
            except: result[key] = value
        return result

    def db_save(data):
        conn = get_db()
        for key, value in data.items():
            conn.run('INSERT INTO store (key, value) VALUES (:key, :value) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value',
                     key=key, value=json.dumps(value, ensure_ascii=False))
        conn.close()

else:
    import sqlite3
    DB = 'bicicletas.db'

    def get_db():
        conn = sqlite3.connect(DB)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db():
        conn = get_db()
        conn.execute('CREATE TABLE IF NOT EXISTS store (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
        conn.commit(); conn.close()

    def db_load_all():
        conn = get_db()
        rows = conn.execute('SELECT key, value FROM store').fetchall()
        conn.close()
        result = {}
        for row in rows:
            try: result[row['key']] = json.loads(row['value'])
            except: result[row['key']] = row['value']
        return result

    def db_save(data):
        conn = get_db()
        for key, value in data.items():
            conn.execute('INSERT OR REPLACE INTO store (key, value) VALUES (?, ?)',
                         (key, json.dumps(value, ensure_ascii=False)))
        conn.commit(); conn.close()


def _cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

@app.route('/')
def index():
    return send_file('index.html')

@app.route('/api/efectivo')
def efectivo():
    val = db_load_all().get('efectivo_actual', 0)
    r = jsonify({'efectivo': val})
    return _cors(r)

@app.route('/api/load')
def load():
    return jsonify(db_load_all())

@app.route('/api/save', methods=['POST'])
def save():
    data = request.json
    if not data: return jsonify({'ok': False}), 400
    db_save(data)
    return jsonify({'ok': True})


init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
