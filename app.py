from flask import Flask, request, jsonify, send_file
from datetime import datetime
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
        # Bitacora append-only: NUNCA se borra. Permite recuperar registros perdidos.
        conn.run('''CREATE TABLE IF NOT EXISTS audit_log (
                        id SERIAL PRIMARY KEY,
                        ts TEXT NOT NULL,
                        action TEXT NOT NULL,
                        store_key TEXT,
                        item_id TEXT,
                        snapshot TEXT
                    )''')
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

    def db_get_one(key, default=None):
        # Trae UNA sola clave. /api/efectivo usaba db_load_all(), que descarga
        # toda la base para leer un unico numero, cada 30 segundos y desde cada
        # pestana abierta. Eso agotaba la cuota de transferencia de Supabase.
        conn = get_db()
        try:
            rows = conn.run('SELECT value FROM store WHERE key = :key', key=key)
        finally:
            try: conn.close()
            except Exception: pass
        if rows:
            try: return json.loads(rows[0][0])
            except Exception: return rows[0][0]
        return default

    def db_save(data):
        conn = get_db()
        for key, value in data.items():
            conn.run('INSERT INTO store (key, value) VALUES (:key, :value) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value',
                     key=key, value=json.dumps(value, ensure_ascii=False))
        conn.close()

    def tx_mutate(key, fn, default=None):
        """Lee, modifica y guarda UNA clave dentro de una transaccion con
        candado. Dos pestanas no pueden pisarse: la segunda espera a la primera
        y lee el dato ya actualizado.
        Si el candado no esta disponible, reintenta sin el: la ventana de riesgo
        pasa de horas (vida de una pestana) a milisegundos."""
        try:
            return _tx_mutate(key, fn, default, True)
        except Exception:
            return _tx_mutate(key, fn, default, False)

    def _tx_mutate(key, fn, default, use_lock):
        conn = get_db()
        try:
            conn.run('BEGIN')
            if use_lock:
                conn.run('SELECT pg_advisory_xact_lock(hashtext(:key))', key=key)
            rows = conn.run('SELECT value FROM store WHERE key = :key', key=key)
            cur = [] if default is None else default
            if rows:
                try: cur = json.loads(rows[0][0])
                except Exception: pass
            new, result = fn(cur)
            conn.run('INSERT INTO store (key, value) VALUES (:key, :value) '
                     'ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value',
                     key=key, value=json.dumps(new, ensure_ascii=False))
            conn.run('COMMIT')
            return result
        except Exception:
            try: conn.run('ROLLBACK')
            except Exception: pass
            raise
        finally:
            try: conn.close()
            except Exception: pass

    def audit(action, key, item_id, snapshot):
        try:
            conn = get_db()
            try:
                conn.run('INSERT INTO audit_log (ts, action, store_key, item_id, snapshot) '
                         'VALUES (:ts, :a, :k, :i, :s)',
                         ts=datetime.now().isoformat(timespec='seconds'),
                         a=action, k=key, i=(str(item_id) if item_id is not None else None),
                         s=json.dumps(snapshot, ensure_ascii=False))
            finally:
                try: conn.close()
                except Exception: pass
        except Exception:
            pass  # la bitacora nunca debe romper una operacion del usuario

    def audit_list(limit):
        conn = get_db()
        try:
            rows = conn.run('SELECT ts, action, store_key, item_id, snapshot '
                            'FROM audit_log ORDER BY id DESC LIMIT :l', l=limit)
        finally:
            try: conn.close()
            except Exception: pass
        return rows

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
        conn.execute('''CREATE TABLE IF NOT EXISTS audit_log (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            ts TEXT NOT NULL,
                            action TEXT NOT NULL,
                            store_key TEXT,
                            item_id TEXT,
                            snapshot TEXT
                        )''')
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

    def db_get_one(key, default=None):
        conn = get_db()
        row = conn.execute('SELECT value FROM store WHERE key = ?', (key,)).fetchone()
        conn.close()
        if row:
            try: return json.loads(row['value'])
            except Exception: return row['value']
        return default

    def db_save(data):
        conn = get_db()
        for key, value in data.items():
            conn.execute('INSERT OR REPLACE INTO store (key, value) VALUES (?, ?)',
                         (key, json.dumps(value, ensure_ascii=False)))
        conn.commit(); conn.close()

    def tx_mutate(key, fn, default=None):
        conn = get_db()
        conn.isolation_level = None
        try:
            conn.execute('BEGIN IMMEDIATE')
            row = conn.execute('SELECT value FROM store WHERE key = ?', (key,)).fetchone()
            cur = [] if default is None else default
            if row:
                try: cur = json.loads(row['value'])
                except Exception: pass
            new, result = fn(cur)
            conn.execute('INSERT OR REPLACE INTO store (key, value) VALUES (?, ?)',
                         (key, json.dumps(new, ensure_ascii=False)))
            conn.execute('COMMIT')
            return result
        except Exception:
            try: conn.execute('ROLLBACK')
            except Exception: pass
            raise
        finally:
            try: conn.close()
            except Exception: pass

    def audit(action, key, item_id, snapshot):
        try:
            conn = get_db()
            try:
                conn.execute('INSERT INTO audit_log (ts, action, store_key, item_id, snapshot) '
                             'VALUES (?, ?, ?, ?, ?)',
                             (datetime.now().isoformat(timespec='seconds'), action, key,
                              (str(item_id) if item_id is not None else None),
                              json.dumps(snapshot, ensure_ascii=False)))
                conn.commit()
            finally:
                try: conn.close()
                except Exception: pass
        except Exception:
            pass

    def audit_list(limit):
        conn = get_db()
        try:
            rows = conn.execute('SELECT ts, action, store_key, item_id, snapshot '
                                'FROM audit_log ORDER BY id DESC LIMIT ?', (limit,)).fetchall()
            return [(r['ts'], r['action'], r['store_key'], r['item_id'], r['snapshot']) for r in rows]
        finally:
            try: conn.close()
            except Exception: pass


def _cors(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

@app.route('/')
def index():
    return send_file('index.html')

@app.route('/importar')
def importar():
    return send_file('importar.html')

@app.route('/api/efectivo')
def efectivo():
    # Consulta SOLO esta clave, no la base completa.
    val = db_get_one('efectivo_actual', 0)
    r = jsonify({'efectivo': val})
    return _cors(r)

@app.route('/api/load')
def load():
    return jsonify(db_load_all())

@app.route('/api/save', methods=['POST'])
def save():
    data = request.json
    if not data: return jsonify({'ok': False}), 400
    # RED DE SEGURIDAD: si una lista llega mas corta de lo que ya hay guardado,
    # significa que se estan perdiendo registros (pestana desactualizada, borrado
    # masivo, etc). Guardamos copia completa en la bitacora ANTES de sobreescribir.
    for key, value in data.items():
        if isinstance(value, list):
            old = db_get_one(key, None)
            if isinstance(old, list) and len(old) > len(value):
                audit('shrink', key, None,
                      {'before': old, 'after_count': len(value),
                       'perdidos': len(old) - len(value)})
    db_save(data)
    return jsonify({'ok': True})


# ==================================================================
# OPERACIONES ATOMICAS POR REGISTRO
# Evitan que una pestana desactualizada sobreescriba la lista completa.
# ==================================================================

def _same_id(a, b):
    return str(a) == str(b)


def _num(x):
    """Mantiene los enteros como enteros: evita que el stock quede en '2.0'."""
    try:
        f = float(x)
    except Exception:
        return 0
    return int(f) if f == int(f) else f

@app.route('/api/item/add', methods=['POST'])
def item_add():
    d = request.json or {}
    key, item = d.get('key'), d.get('item')
    if not key or not isinstance(item, dict):
        return _cors(jsonify({'ok': False, 'error': 'peticion invalida'})), 400

    def fn(cur):
        if not isinstance(cur, list): cur = []
        for x in cur:
            if isinstance(x, dict) and _same_id(x.get('id'), item.get('id')):
                return cur, {'ok': True, 'duplicado': True, 'count': len(cur)}
        cur.append(item)
        return cur, {'ok': True, 'duplicado': False, 'count': len(cur)}

    try:
        res = tx_mutate(key, fn)
    except Exception as e:
        return _cors(jsonify({'ok': False, 'error': str(e)})), 500
    if not res.get('duplicado'):
        audit('create', key, item.get('id'), item)
    return _cors(jsonify(res))


@app.route('/api/item/update', methods=['POST'])
def item_update():
    d = request.json or {}
    key, item = d.get('key'), d.get('item')
    if not key or not isinstance(item, dict) or item.get('id') is None:
        return _cors(jsonify({'ok': False, 'error': 'peticion invalida'})), 400

    holder = {}

    def fn(cur):
        if not isinstance(cur, list): cur = []
        for i, x in enumerate(cur):
            if isinstance(x, dict) and _same_id(x.get('id'), item.get('id')):
                holder['before'] = x
                cur[i] = item
                return cur, {'ok': True, 'count': len(cur)}
        # No estaba: lo agregamos en vez de perderlo.
        cur.append(item)
        return cur, {'ok': True, 'count': len(cur), 'agregado': True}

    try:
        res = tx_mutate(key, fn)
    except Exception as e:
        return _cors(jsonify({'ok': False, 'error': str(e)})), 500
    audit('update', key, item.get('id'),
          {'before': holder.get('before'), 'after': item})
    return _cors(jsonify(res))


@app.route('/api/item/delete', methods=['POST'])
def item_delete():
    d = request.json or {}
    key, item_id = d.get('key'), d.get('id')
    if not key or item_id is None:
        return _cors(jsonify({'ok': False, 'error': 'peticion invalida'})), 400

    holder = {}

    def fn(cur):
        if not isinstance(cur, list): cur = []
        keep = []
        for x in cur:
            if isinstance(x, dict) and _same_id(x.get('id'), item_id):
                holder['before'] = x
            else:
                keep.append(x)
        return keep, {'ok': True, 'count': len(keep),
                      'eliminado': 'before' in holder}

    try:
        res = tx_mutate(key, fn)
    except Exception as e:
        return _cors(jsonify({'ok': False, 'error': str(e)})), 500
    if 'before' in holder:
        audit('delete', key, item_id, {'before': holder['before']})
    return _cors(jsonify(res))


@app.route('/api/inv/adjust', methods=['POST'])
def inv_adjust():
    """Suma o resta stock de un SKU de forma atomica.
    delta negativo = venta, delta positivo = devolucion/entrada."""
    d = request.json or {}
    sku = d.get('sku')
    try:
        delta = float(d.get('delta', 0))
    except Exception:
        return _cors(jsonify({'ok': False, 'error': 'delta invalido'})), 400
    if sku is None:
        return _cors(jsonify({'ok': False, 'error': 'sku requerido'})), 400
    sku = str(sku)

    def fn(cur):
        if not isinstance(cur, dict): cur = {}
        if sku not in cur:
            return cur, {'ok': False, 'error': 'SKU no existe en inventario'}
        actual = cur[sku].get('stock') or 0
        cur[sku]['stock'] = _num(actual + delta)
        return cur, {'ok': True, 'stock': cur[sku]['stock']}

    try:
        res = tx_mutate('bec_inv', fn, default={})
    except Exception as e:
        return _cors(jsonify({'ok': False, 'error': str(e)})), 500
    return _cors(jsonify(res))


@app.route('/api/inv/upsert', methods=['POST'])
def inv_upsert():
    """Crea o actualiza un SKU y suma stock, de forma atomica.
    Se usa al ingresar productos: no reescribe el inventario completo."""
    d = request.json or {}
    sku = d.get('sku')
    if sku is None:
        return _cors(jsonify({'ok': False, 'error': 'sku requerido'})), 400
    sku = str(sku)
    campos = d.get('fields') or {}
    try:
        delta = float(d.get('delta', 0))
    except Exception:
        delta = 0

    def fn(cur):
        if not isinstance(cur, dict): cur = {}
        if sku not in cur or not isinstance(cur[sku], dict):
            cur[sku] = {'nombre': '', 'categoria': '', 'stock': 0,
                        'precioCompra': 0, 'precioVenta': 0}
        for k, v in campos.items():
            if v not in (None, ''):
                cur[sku][k] = v
        cur[sku]['stock'] = _num((cur[sku].get('stock') or 0) + delta)
        return cur, {'ok': True, 'stock': cur[sku]['stock']}

    try:
        res = tx_mutate('bec_inv', fn, default={})
    except Exception as e:
        return _cors(jsonify({'ok': False, 'error': str(e)})), 500
    return _cors(jsonify(res))


@app.route('/api/audit')
def audit_view():
    try:
        limit = int(request.args.get('limit', 300))
    except Exception:
        limit = 300
    limit = max(1, min(limit, 2000))
    accion = request.args.get('action')
    out = []
    for ts, action, store_key, item_id, snapshot in audit_list(limit):
        if accion and action != accion:
            continue
        try: snap = json.loads(snapshot) if snapshot else None
        except Exception: snap = snapshot
        out.append({'ts': ts, 'action': action, 'key': store_key,
                    'id': item_id, 'snapshot': snap})
    return _cors(jsonify(out))


init_db()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
