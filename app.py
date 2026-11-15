from flask import Flask, request, jsonify, send_file
from datetime import datetime
import copy
import hashlib
import hmac
import json
import os
import re
import secrets
import time

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

# ==================================================================
# CLAVE DE ADMINISTRADOR
# La app no tiene usuarios. "Administrador" = quien conoce una clave que se
# guarda AQUI, con hash, y se verifica en el servidor en cada operacion
# protegida. Ocultar un boton en la pagina no protege nada por si solo.
#
# La clave vive en la clave reservada ADMIN_KEY, que no sale por /api/load ni
# se puede escribir por /api/save ni /api/item/*. Asi no viaja al navegador ni
# entra en los backups.
#
# Respaldo si se olvida: definir la variable de entorno ADMIN_PIN en Render;
# se acepta ademas de la guardada.
# ==================================================================
ADMIN_KEY = 'bec_admin'
_PIN_MIN, _PIN_MAX = 4, 32
_MAX_FALLOS, _BLOQUEO_SEG = 5, 300
_pin_fallos = {'n': 0, 'hasta': 0.0}


def _hash_pin(pin, salt_hex):
    return hashlib.pbkdf2_hmac(
        'sha256', pin.encode('utf-8'), bytes.fromhex(salt_hex), 200000).hex()


def _pin_configurado():
    return bool(db_get_one(ADMIN_KEY, None)) or bool(os.environ.get('ADMIN_PIN'))


def _pin_coincide(pin):
    if not isinstance(pin, str) or not pin:
        return False
    env = os.environ.get('ADMIN_PIN')
    if env and hmac.compare_digest(pin.encode('utf-8'), env.encode('utf-8')):
        return True
    reg = db_get_one(ADMIN_KEY, None)
    if isinstance(reg, dict) and reg.get('salt') and reg.get('hash'):
        try:
            return hmac.compare_digest(_hash_pin(pin, reg['salt']), reg['hash'])
        except Exception:
            return False
    return False


def _pin_ok(pin):
    """(True, None) si la clave es correcta. Tras varios fallos seguidos se
    bloquea todo intento por unos minutos: frena adivinar la clave a ciegas."""
    ahora = time.time()
    if _pin_fallos['hasta'] > ahora:
        falta = int((_pin_fallos['hasta'] - ahora) // 60) + 1
        return False, 'Demasiados intentos fallidos. Espere %d min.' % falta
    if _pin_coincide(pin):
        _pin_fallos['n'] = 0
        return True, None
    _pin_fallos['n'] += 1
    if _pin_fallos['n'] >= _MAX_FALLOS:
        _pin_fallos['n'] = 0
        _pin_fallos['hasta'] = ahora + _BLOQUEO_SEG
        return False, 'Clave incorrecta. Se bloquearon los intentos por 5 min.'
    return False, 'Clave incorrecta.'


@app.route('/api/admin/estado', methods=['GET', 'POST'])
def admin_estado():
    return _cors(jsonify({'ok': True, 'configurado': _pin_configurado()}))


@app.route('/api/admin/verificar', methods=['POST'])
def admin_verificar():
    ok, err = _pin_ok((request.json or {}).get('pin'))
    if not ok:
        return _cors(jsonify({'ok': False, 'error': err})), 403
    return _cors(jsonify({'ok': True}))


@app.route('/api/admin/configurar', methods=['POST'])
def admin_configurar():
    """Crea la clave la primera vez; despues solo se cambia presentando la actual."""
    d = request.json or {}
    nueva = d.get('pin')
    if not isinstance(nueva, str) or not (_PIN_MIN <= len(nueva) <= _PIN_MAX):
        return _cors(jsonify({'ok': False,
            'error': 'La clave debe tener entre %d y %d caracteres.' % (_PIN_MIN, _PIN_MAX)})), 400
    if _pin_configurado():
        ok, err = _pin_ok(d.get('actual'))
        if not ok:
            return _cors(jsonify({'ok': False, 'error': err})), 403
    salt = secrets.token_hex(16)
    db_save({ADMIN_KEY: {'salt': salt, 'hash': _hash_pin(nueva, salt),
                         'cambiada': datetime.now().isoformat(timespec='seconds')}})
    audit('admin', ADMIN_KEY, None, {'accion': 'clave de administrador definida o cambiada'})
    return _cors(jsonify({'ok': True}))


@app.route('/api/load')
def load():
    datos = db_load_all()
    datos.pop(ADMIN_KEY, None)      # el hash de la clave nunca llega al navegador
    return jsonify(datos)

@app.route('/api/save', methods=['POST'])
def save():
    data = request.json
    if not data: return jsonify({'ok': False}), 400
    if ADMIN_KEY in data:
        return jsonify({'ok': False, 'error': 'clave reservada'}), 403
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
    if not key or not isinstance(item, dict) or key == ADMIN_KEY:
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
    if (not key or not isinstance(item, dict) or item.get('id') is None
            or key == ADMIN_KEY):
        return _cors(jsonify({'ok': False, 'error': 'peticion invalida'})), 400
    if key == 'bec_prod':
        return _err('Editar entradas de productos requiere la clave de administrador.', 403)
    if key == 'bec_gastos':
        return _err('Editar gastos requiere la clave de administrador.', 403)

    holder = {}

    def fn(cur):
        if not isinstance(cur, list): cur = []
        for i, x in enumerate(cur):
            if isinstance(x, dict) and _same_id(x.get('id'), item.get('id')):
                holder['before'] = x
                nuevo = dict(item)
                if key == 'bec_ventas':
                    # El contrato solo cambia por /api/venta/contrato. Aqui se
                    # conserva el guardado: asi editar la venta no puede
                    # borrarlo (la pagina rearma la venta campo por campo) ni
                    # alterar uno firmado.
                    if isinstance(x.get('contrato'), dict):
                        nuevo['contrato'] = x['contrato']
                    else:
                        nuevo.pop('contrato', None)
                holder['after'] = nuevo
                cur[i] = nuevo
                return cur, {'ok': True, 'count': len(cur)}
        # No estaba: lo agregamos en vez de perderlo.
        nuevo = dict(item)
        if key == 'bec_ventas':
            nuevo.pop('contrato', None)
        holder['after'] = nuevo
        cur.append(nuevo)
        return cur, {'ok': True, 'count': len(cur), 'agregado': True}

    try:
        res = tx_mutate(key, fn)
    except Exception as e:
        return _cors(jsonify({'ok': False, 'error': str(e)})), 500
    audit('update', key, item.get('id'),
          {'before': holder.get('before'), 'after': holder.get('after', item)})
    return _cors(jsonify(res))


@app.route('/api/item/delete', methods=['POST'])
def item_delete():
    d = request.json or {}
    key, item_id = d.get('key'), d.get('id')
    if not key or item_id is None or key == ADMIN_KEY:
        return _cors(jsonify({'ok': False, 'error': 'peticion invalida'})), 400
    if key == 'bec_prod':
        return _err('Eliminar entradas de productos requiere la clave de administrador.', 403)
    if key == 'bec_gastos':
        return _err('Eliminar gastos requiere la clave de administrador.', 403)

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


def _err(msg, code=400, **extra):
    r = {'ok': False, 'error': msg}
    r.update(extra)
    return _cors(jsonify(r)), code


def _entero_positivo(x):
    try:
        f = float(x)
    except Exception:
        return None
    if f != int(f) or f <= 0:
        return None
    return int(f)


def _numero(x, defecto=-1):
    try:
        return float(x)
    except Exception:
        return defecto


_FECHA_RE = re.compile(r'^\d{4}-\d{2}-\d{2}$')


def _seguir_ultima_entrada(reg, ult):
    """Deja nombre, categoria, marca, potencia y precios del inventario como los
    de la ULTIMA entrada de ese SKU, igual que al registrar una entrada nueva."""
    if ult is None or not isinstance(reg, dict):
        return
    for campo, v in (('nombre', ult.get('nombre')), ('categoria', ult.get('categoria')),
                     ('marca', ult.get('marca')), ('potencia', ult.get('potencia')),
                     ('precioCompra', ult.get('valor'))):
        if v not in (None, ''):
            reg[campo] = v
    if ult.get('pventa'):
        reg['precioVenta'] = ult['pventa']


@app.route('/api/producto/editar', methods=['POST'])
def producto_editar():
    """Edita una ENTRADA de producto. Solo administrador (clave en cada llamada).

    Corrige el inventario de forma coherente:
      - misma SKU, otra cantidad  -> el stock cambia por la diferencia
      - otra SKU                  -> se saca del SKU viejo y se suma al nuevo
      - nombre, categoria, marca, potencia y precio de compra del inventario se
        toman de la ULTIMA entrada de cada SKU afectado, igual que al registrar.
    Si el stock de algun SKU quedaria negativo (ya se vendieron esas unidades)
    no se cambia nada. Si falla a mitad, el inventario vuelve a como estaba."""
    d = request.json or {}
    ok, err = _pin_ok(d.get('pin'))
    if not ok:
        return _err(err, 403, clave=True)

    item = d.get('item')
    if not isinstance(item, dict) or item.get('id') is None:
        return _err('peticion invalida')

    def txt(k):
        return str(item.get(k) or '').strip()

    sku, nombre, proveedor, fecha = txt('sku').upper(), txt('nombre'), txt('proveedor'), txt('fecha')
    cant = _entero_positivo(item.get('cantidad'))
    valor = _numero(item.get('valor'))
    pventa = _numero(item.get('pventa') or 0)

    if not sku:
        return _err('El SKU es obligatorio.')
    if not nombre:
        return _err('El nombre del producto es obligatorio.')
    if not proveedor:
        return _err('El proveedor es obligatorio.')
    if not _FECHA_RE.match(fecha):
        return _err('La fecha no es valida.')
    if cant is None:
        return _err('La cantidad debe ser un numero entero mayor que 0.')
    if valor <= 0:
        return _err('El valor unitario debe ser mayor que 0.')
    if pventa < 0:
        return _err('El valor FOB no es valido.')

    prods = db_get_one('bec_prod', [])
    if not isinstance(prods, list):
        prods = []
    idx = next((i for i, x in enumerate(prods)
                if isinstance(x, dict) and _same_id(x.get('id'), item['id'])), None)
    if idx is None:
        return _err('No se encontro esa entrada. Recargue la pagina e intente de nuevo.', 404)

    viejo = copy.deepcopy(prods[idx])
    nuevo = dict(viejo)     # conserva campos que el formulario no maneja
    nuevo.update({
        'fecha': fecha, 'proveedor': proveedor, 'factura': txt('factura'),
        'sku': sku, 'nombre': nombre, 'marca': txt('marca'),
        'potencia': txt('potencia'), 'categoria': txt('categoria'),
        'cantidad': cant, 'valor': _num(valor), 'pventa': _num(pventa),
        'total': _num(cant * valor),
    })
    if nuevo == viejo:
        return _cors(jsonify({'ok': True, 'sin_cambios': True, 'item': viejo}))

    lista_nueva = list(prods)
    lista_nueva[idx] = nuevo
    sku_viejo = str(viejo.get('sku') or '')
    cant_vieja = _num(viejo.get('cantidad') or 0)
    afectados = {sku} | ({sku_viejo} if sku_viejo else set())

    def ultima_de(s):
        for x in reversed(lista_nueva):
            if isinstance(x, dict) and str(x.get('sku') or '') == s:
                return x
        return None

    holder = {}

    def fn_inv(cur):
        if not isinstance(cur, dict):
            cur = {}

        def stock_de(s):
            r = cur.get(s)
            return _num(r.get('stock') or 0) if isinstance(r, dict) else 0

        # 1) Calcular el stock resultante SIN tocar nada.
        resultado = {}
        if sku_viejo == sku:
            resultado[sku] = (_num(stock_de(sku) - cant_vieja + cant)
                              if sku in cur else cant)
        else:
            if sku_viejo and sku_viejo in cur:
                resultado[sku_viejo] = _num(stock_de(sku_viejo) - cant_vieja)
            resultado[sku] = _num(stock_de(sku) + cant)
        for s, st in resultado.items():
            if st < 0:
                return cur, {'ok': False, 'error':
                    'El stock de %s quedaria en %s: ya se vendieron unidades de esa entrada. '
                    'No se hizo ningun cambio.' % (s, st)}

        # 2) Aplicar.
        holder['antes'] = {s: copy.deepcopy(cur.get(s)) for s in afectados}
        for s, st in resultado.items():
            reg = cur.get(s)
            if not isinstance(reg, dict):
                reg = cur[s] = {'nombre': '', 'categoria': '', 'stock': 0,
                                'precioCompra': 0, 'precioVenta': 0}
            reg['stock'] = st
        for s in afectados:
            _seguir_ultima_entrada(cur.get(s), ultima_de(s))
        return cur, {'ok': True, 'stock': {s: cur[s]['stock'] for s in resultado}}

    def restaurar_inv():
        antes = holder.get('antes')
        if not antes:
            return

        def fn(cur):
            if not isinstance(cur, dict):
                cur = {}
            for s, reg in antes.items():
                if reg is None:
                    cur.pop(s, None)
                else:
                    cur[s] = reg
            return cur, {'ok': True}
        try:
            tx_mutate('bec_inv', fn, default={})
        except Exception:
            pass

    try:
        res_inv = tx_mutate('bec_inv', fn_inv, default={})
    except Exception as e:
        return _err(str(e), 500)
    if not res_inv.get('ok'):
        return _err(res_inv.get('error') or 'No se pudo actualizar el inventario.', 409)

    def fn_prod(cur):
        if not isinstance(cur, list):
            cur = []
        for i, x in enumerate(cur):
            if isinstance(x, dict) and _same_id(x.get('id'), item['id']):
                cur[i] = nuevo
                return cur, {'ok': True}
        return cur, {'ok': False, 'error': 'La entrada ya no existe.'}

    try:
        res = tx_mutate('bec_prod', fn_prod)
    except Exception as e:
        res = {'ok': False, 'error': str(e)}
    if not res.get('ok'):
        restaurar_inv()
        return _err(res.get('error') or 'No se pudo guardar la entrada.', 500)

    audit('update', 'bec_prod', nuevo.get('id'),
          {'before': viejo, 'after': nuevo, 'por': 'administrador'})

    # Cada venta guarda el costo del momento. Si se corrige el valor de una
    # entrada (un cero de mas), las ventas hechas con el valor equivocado
    # conservan ese costo y su utilidad sale mal. Se devuelven las que usaron
    # exactamente el valor anterior para que la pagina ofrezca corregirlas.
    afectadas = []
    valor_anterior = _num(viejo.get('valor') or 0)
    if valor_anterior and valor_anterior != _num(valor):
        ventas = db_get_one('bec_ventas', [])
        for v in (ventas if isinstance(ventas, list) else []):
            if (isinstance(v, dict) and str(v.get('sku') or '') in afectados
                    and v.get('costoUnit') is not None
                    and _num(v.get('costoUnit')) == valor_anterior):
                afectadas.append({'id': v.get('id'), 'nombre': v.get('nombre'),
                                  'fecha': v.get('fecha'), 'costoUnit': v.get('costoUnit')})
    return _cors(jsonify({'ok': True, 'item': nuevo, 'stock': res_inv.get('stock'),
                          'ventas_afectadas': afectadas}))


@app.route('/api/gasto/editar', methods=['POST'])
def gasto_editar():
    """Edita un GASTO. Solo administrador (clave en cada llamada).

    Un gasto alimenta la caja y el flujo por medio de pago, asi que corregirlo
    cambia esas cuentas; por eso exige la clave y queda en la bitacora con el
    antes y el despues. No mueve inventario."""
    d = request.json or {}
    ok, err = _pin_ok(d.get('pin'))
    if not ok:
        return _err(err, 403, clave=True)
    item = d.get('item')
    if not isinstance(item, dict) or item.get('id') is None:
        return _err('peticion invalida')

    def txt(k, n):
        return str(item.get(k) or '').strip()[:n]

    fecha = _fecha_ok(item.get('fecha'))
    concepto, categoria, formapago = txt('concepto', 200), txt('categoria', 60), txt('formapago', 60)
    valor = _numero(item.get('valor'))
    if not fecha:
        return _err('La fecha no es valida.')
    if not concepto:
        return _err('El concepto es obligatorio.')
    if valor <= 0:
        return _err('El valor debe ser mayor que 0.')
    if not formapago:
        return _err('La forma de pago es obligatoria.')

    holder = {}

    def fn(cur):
        if not isinstance(cur, list):
            cur = []
        for i, x in enumerate(cur):
            if isinstance(x, dict) and _same_id(x.get('id'), item['id']):
                viejo = copy.deepcopy(x)
                # Los gastos viejos no tienen categoria ni comprobante: son
                # opcionales ahi. No se les asigna una categoria por defecto, ni
                # se les agregan campos vacios solo por abrirlos y guardar.
                if not categoria and viejo.get('categoria'):
                    return cur, {'ok': False, 'code': 400,
                                 'error': 'La categoria es obligatoria.'}
                nuevo = dict(x)     # conserva campos que el formulario no maneja
                nuevo.update({'fecha': fecha, 'concepto': concepto,
                              'valor': _num(valor), 'formapago': formapago})
                for campo, v in (('categoria', categoria), ('comprobante', txt('comprobante', 120))):
                    if v or campo in viejo:
                        nuevo[campo] = v
                holder['viejo'], holder['nuevo'] = viejo, nuevo
                if nuevo != viejo:
                    cur[i] = nuevo
                return cur, {'ok': True, 'sin_cambios': nuevo == viejo}
        return cur, {'ok': False, 'code': 404,
                     'error': 'No se encontro ese gasto. Recargue la pagina e intente de nuevo.'}

    try:
        res = tx_mutate('bec_gastos', fn)
    except Exception as e:
        return _err(str(e), 500)
    if not res.get('ok'):
        return _err(res.get('error') or 'No se pudo guardar el gasto.', res.get('code', 500))
    if not res.get('sin_cambios'):
        audit('update', 'bec_gastos', holder['nuevo'].get('id'),
              {'before': holder['viejo'], 'after': holder['nuevo'], 'por': 'administrador'})
    return _cors(jsonify({'ok': True, 'item': holder['nuevo'], 'sin_cambios': bool(res.get('sin_cambios'))}))


@app.route('/api/gasto/eliminar', methods=['POST'])
def gasto_eliminar():
    """Elimina un GASTO. Solo administrador (clave en cada llamada).

    Quita un gasto de la caja y del flujo por medio de pago, asi que exige la
    clave. Queda en la bitacora con el gasto completo para poder recuperarlo."""
    d = request.json or {}
    ok, err = _pin_ok(d.get('pin'))
    if not ok:
        return _err(err, 403, clave=True)
    gid = d.get('id')
    if gid is None:
        return _err('peticion invalida')

    holder = {}

    def fn(cur):
        if not isinstance(cur, list):
            cur = []
        keep = []
        for x in cur:
            if isinstance(x, dict) and _same_id(x.get('id'), gid):
                holder['viejo'] = copy.deepcopy(x)
            else:
                keep.append(x)
        return keep, {'ok': 'viejo' in holder}

    try:
        res = tx_mutate('bec_gastos', fn)
    except Exception as e:
        return _err(str(e), 500)
    if not res.get('ok'):
        return _err('No se encontro ese gasto. Recargue la pagina e intente de nuevo.', 404)
    audit('delete', 'bec_gastos', gid, {'before': holder['viejo'], 'por': 'administrador'})
    return _cors(jsonify({'ok': True}))


@app.route('/api/ventas/costo', methods=['POST'])
def ventas_costo():
    """Corrige el costo unitario congelado de una o varias ventas. Solo
    administrador. Recalcula costoTotal = costoUnit x cantidad y deja cada
    cambio en la bitacora con el antes y el despues."""
    d = request.json or {}
    ok, err = _pin_ok(d.get('pin'))
    if not ok:
        return _err(err, 403, clave=True)
    cambios = d.get('cambios')
    if not isinstance(cambios, list) or not cambios or len(cambios) > 200:
        return _err('peticion invalida')
    mapa = {}
    for c in cambios:
        if not isinstance(c, dict) or c.get('id') is None:
            return _err('peticion invalida')
        cu = _numero(c.get('costoUnit'))
        if cu <= 0:
            return _err('El costo unitario debe ser mayor que 0.')
        mapa[str(c['id'])] = _num(cu)

    hechos = []

    def fn(cur):
        if not isinstance(cur, list):
            cur = []
        for x in cur:
            if isinstance(x, dict) and str(x.get('id')) in mapa:
                cu = mapa[str(x.get('id'))]
                antes = {'nombre': x.get('nombre'), 'fecha': x.get('fecha'), 'total': x.get('total'),
                         'costoUnit': x.get('costoUnit'), 'costoTotal': x.get('costoTotal')}
                x['costoUnit'] = cu
                x['costoTotal'] = _num(cu * _num(x.get('cantidad') or 1))
                despues = dict(antes, costoUnit=x['costoUnit'], costoTotal=x['costoTotal'])
                hechos.append((x.get('id'), antes, despues))
        return cur, {'ok': True}

    try:
        tx_mutate('bec_ventas', fn)
    except Exception as e:
        return _err(str(e), 500)
    if not hechos:
        return _err('No se encontraron esas ventas. Recargue la pagina.', 404)
    for vid, antes, despues in hechos:
        audit('update', 'bec_ventas', vid,
              {'before': antes, 'after': despues, 'por': 'administrador',
               'motivo': 'correccion de costo'})
    return _cors(jsonify({'ok': True, 'actualizadas': len(hechos)}))


@app.route('/api/producto/eliminar', methods=['POST'])
def producto_eliminar():
    """Elimina una ENTRADA de producto. Solo administrador (clave en cada llamada).

    Descuenta del inventario las unidades de esa entrada. Si el stock quedaria
    negativo (ya se vendieron) no cambia nada. Si falla a mitad, el inventario
    vuelve a como estaba. Queda copia en la bitacora para poder recuperarla."""
    d = request.json or {}
    ok, err = _pin_ok(d.get('pin'))
    if not ok:
        return _err(err, 403, clave=True)
    item_id = d.get('id')
    if item_id is None:
        return _err('peticion invalida')

    prods = db_get_one('bec_prod', [])
    if not isinstance(prods, list):
        prods = []
    viejo = next((copy.deepcopy(x) for x in prods
                  if isinstance(x, dict) and _same_id(x.get('id'), item_id)), None)
    if viejo is None:
        return _err('No se encontro esa entrada. Recargue la pagina e intente de nuevo.', 404)

    sku = str(viejo.get('sku') or '')
    cant = _num(viejo.get('cantidad') or 0)
    restantes = [x for x in prods
                 if not (isinstance(x, dict) and _same_id(x.get('id'), item_id))]
    holder = {}

    def fn_inv(cur):
        if not isinstance(cur, dict):
            cur = {}
        reg = cur.get(sku) if sku else None
        if not isinstance(reg, dict):
            return cur, {'ok': True, 'stock': None}      # nada que revertir
        nuevo_stock = _num(_num(reg.get('stock') or 0) - cant)
        if nuevo_stock < 0:
            return cur, {'ok': False, 'error':
                'El stock de %s quedaria en %s: ya se vendieron unidades de esa entrada. '
                'No se elimino nada.' % (sku, nuevo_stock)}
        holder['antes'] = copy.deepcopy(reg)
        reg['stock'] = nuevo_stock
        ult = next((x for x in reversed(restantes)
                    if isinstance(x, dict) and str(x.get('sku') or '') == sku), None)
        _seguir_ultima_entrada(reg, ult)
        return cur, {'ok': True, 'stock': nuevo_stock}

    def restaurar_inv():
        if 'antes' not in holder:
            return

        def fn(cur):
            if not isinstance(cur, dict):
                cur = {}
            cur[sku] = holder['antes']
            return cur, {'ok': True}
        try:
            tx_mutate('bec_inv', fn, default={})
        except Exception:
            pass

    try:
        res_inv = tx_mutate('bec_inv', fn_inv, default={})
    except Exception as e:
        return _err(str(e), 500)
    if not res_inv.get('ok'):
        return _err(res_inv.get('error') or 'No se pudo actualizar el inventario.', 409)

    def fn_prod(cur):
        if not isinstance(cur, list):
            cur = []
        keep = [x for x in cur if not (isinstance(x, dict) and _same_id(x.get('id'), item_id))]
        return keep, {'ok': len(keep) < len(cur)}

    try:
        res = tx_mutate('bec_prod', fn_prod)
    except Exception as e:
        res = {'ok': False, 'error': str(e)}
    if not res.get('ok'):
        restaurar_inv()
        return _err(res.get('error') or 'La entrada ya no existe.', 500)

    audit('delete', 'bec_prod', item_id, {'before': viejo, 'por': 'administrador'})
    return _cors(jsonify({'ok': True, 'stock': res_inv.get('stock')}))


# ==================================================================
# CONTRATO DE VENTA A CREDITO
# Las condiciones del credito (cuotas, fechas, mora) no existian en la venta:
# se guardan en venta['contrato']. Las reglas viven aqui y no solo en la pagina:
# solo hay contrato si queda saldo por financiar, la numeracion no se repite
# aunque haya dos pestanas, y uno firmado no se modifica sin la clave de
# administrador (para cambiarlo hay que quitar primero la firma).
# ==================================================================
_PERIODOS = ('semanal', 'quincenal', 'mensual')
_CRED = ('Crédito', 'Credito')


def _fecha_ok(s):
    s = str(s or '')
    if not _FECHA_RE.match(s):
        return None
    try:
        datetime.strptime(s, '%Y-%m-%d')
    except ValueError:
        return None
    return s


def _pagado_inicial(venta):
    """Lo recibido al vender (cuota inicial): suma de los pagos de la venta."""
    pagos = venta.get('pagos')
    if isinstance(pagos, list) and pagos:
        return _num(sum(_numero(p.get('valor'), 0) for p in pagos if isinstance(p, dict)))
    return _num(venta.get('abono') or 0)


def _saldo_a_financiar(venta):
    return _num(_num(venta.get('total') or 0) - _pagado_inicial(venta))


def _siguiente_numero(ventas):
    mayor = 0
    for v in ventas:
        c = v.get('contrato') if isinstance(v, dict) else None
        m = re.match(r'^CV-(\d+)$', str((c or {}).get('numero') or ''))
        if m:
            mayor = max(mayor, int(m.group(1)))
    return 'CV-%04d' % (mayor + 1)


def _parsear_contrato(c, venta):
    """Valida las condiciones y devuelve (contrato_limpio, None) o (None, error)."""
    if not isinstance(c, dict):
        return None, 'Faltan las condiciones del contrato.'
    saldo = _saldo_a_financiar(venta)
    if saldo <= 0:
        return None, 'Esta venta no tiene saldo por financiar: no necesita contrato de credito.'

    ciudad = str(c.get('ciudad') or '').strip()[:80]
    if not ciudad:
        return None, 'La ciudad del contrato es obligatoria.'
    fecha = _fecha_ok(c.get('fecha'))
    if not fecha:
        return None, 'La fecha del contrato no es valida.'
    primera = _fecha_ok(c.get('primeraCuota'))
    if not primera:
        return None, 'La fecha de la primera cuota no es valida.'
    if primera < fecha:
        return None, 'La primera cuota no puede ser anterior a la fecha del contrato.'
    cuotas = _entero_positivo(c.get('cuotas'))
    if cuotas is None or cuotas > 120:
        return None, 'El numero de cuotas debe ser un entero entre 1 y 120.'
    periodo = str(c.get('periodicidad') or '').lower()
    if periodo not in _PERIODOS:
        return None, 'La periodicidad debe ser semanal, quincenal o mensual.'

    valor_cuota = _numero(c.get('valorCuota'))
    if cuotas == 1:
        valor_cuota = saldo
    if valor_cuota <= 0:
        return None, 'El valor de la cuota debe ser mayor que 0.'
    if cuotas > 1 and valor_cuota * (cuotas - 1) >= saldo:
        return None, ('Con %d cuotas de %s no queda saldo para la ultima: el valor de la cuota '
                      'es demasiado alto.' % (cuotas, int(valor_cuota)))
    if valor_cuota * cuotas < saldo:
        return None, ('Con %d cuotas de %s no se alcanza a pagar el saldo: el valor de la cuota '
                      'es demasiado bajo.' % (cuotas, int(valor_cuota)))

    mora = c.get('moraPct')
    if mora in (None, ''):
        mora = None
    else:
        mora = _numero(mora)
        if mora < 0 or mora > 10:
            return None, 'El interes de mora mensual debe estar entre 0 y 10 %.'
        mora = _num(mora)
    mora_cuotas = _entero_positivo(c.get('moraCuotas') or 2)
    if mora_cuotas is None or mora_cuotas > 12:
        return None, 'Las cuotas en mora para vencimiento anticipado deben ser entre 1 y 12.'

    codeudor = None
    cd = c.get('codeudor')
    if isinstance(cd, dict) and any(str(cd.get(k) or '').strip() for k in cd):
        codeudor = {k: str(cd.get(k) or '').strip()[:120]
                    for k in ('nombre', 'cedula', 'telefono', 'direccion')}
        if not codeudor['nombre'] or not codeudor['cedula']:
            return None, 'Del codeudor se necesitan al menos el nombre y la cedula.'

    return {
        'ciudad': ciudad, 'fecha': fecha, 'primeraCuota': primera,
        'cuotas': cuotas, 'periodicidad': periodo, 'valorCuota': _num(valor_cuota),
        'moraPct': mora, 'moraCuotas': mora_cuotas,
        # Se fijan al guardar, calculados aqui con la venta: no se confia en la pagina.
        'valorFinanciado': saldo, 'cuotaInicial': _pagado_inicial(venta),
        'precioTotal': _num(venta.get('total') or 0), 'codeudor': codeudor,
    }, None


@app.route('/api/venta/contrato', methods=['POST'])
def venta_contrato():
    """accion: 'guardar' (crea o actualiza las condiciones; asigna el numero la
    primera vez), 'firmar' (marca la fecha de firma) o 'desfirmar' (solo con la
    clave de administrador)."""
    d = request.json or {}
    vid, accion = d.get('id'), (d.get('accion') or 'guardar')
    if vid is None or accion not in ('guardar', 'firmar', 'desfirmar'):
        return _err('peticion invalida')
    if accion == 'desfirmar':
        ok, err = _pin_ok(d.get('pin'))
        if not ok:
            return _err(err, 403, clave=True)

    def fn(cur):
        if not isinstance(cur, list):
            cur = []
        venta = next((x for x in cur if isinstance(x, dict) and _same_id(x.get('id'), vid)), None)
        if venta is None:
            return cur, {'ok': False, 'code': 404,
                         'error': 'No se encontro esa venta. Recargue la pagina.'}
        antes = copy.deepcopy(venta.get('contrato')) if isinstance(venta.get('contrato'), dict) else None

        if accion == 'guardar':
            if venta.get('tipo') not in _CRED:
                return cur, {'ok': False, 'code': 400, 'error': 'Solo las ventas a credito tienen contrato.'}
            if antes and antes.get('firmado'):
                return cur, {'ok': False, 'code': 409, 'error':
                    'El contrato ya esta firmado. Para modificarlo, un administrador debe quitar primero la firma.'}
            limpio, err = _parsear_contrato(d.get('contrato'), venta)
            if err:
                return cur, {'ok': False, 'code': 400, 'error': err}
            nuevo = dict(limpio)
            nuevo['numero'] = (antes or {}).get('numero') or _siguiente_numero(cur)
            nuevo['creado'] = (antes or {}).get('creado') or datetime.now().isoformat(timespec='seconds')
            nuevo['firmado'] = None
        elif accion == 'firmar':
            if not antes:
                return cur, {'ok': False, 'code': 400, 'error': 'Primero guarde el contrato.'}
            if antes.get('firmado'):
                return cur, {'ok': True, 'contrato': antes, 'sin_cambios': True}
            fecha = _fecha_ok(d.get('fecha')) or datetime.now().strftime('%Y-%m-%d')
            nuevo = dict(antes, firmado=fecha)
        else:  # desfirmar
            if not antes or not antes.get('firmado'):
                return cur, {'ok': False, 'code': 400, 'error': 'Ese contrato no esta firmado.'}
            nuevo = dict(antes, firmado=None)

        venta['contrato'] = nuevo
        resumen = {'nombre': venta.get('nombre'), 'fecha': venta.get('fecha'), 'total': venta.get('total')}
        return cur, {'ok': True, 'contrato': nuevo,
                     'auditoria': (dict(resumen, contrato=antes), dict(resumen, contrato=nuevo))}

    try:
        res = tx_mutate('bec_ventas', fn)
    except Exception as e:
        return _err(str(e), 500)
    if not res.get('ok'):
        return _err(res.get('error') or 'No se pudo guardar el contrato.', res.get('code', 400))
    if res.get('auditoria'):
        antes, despues = res['auditoria']
        audit('update', 'bec_ventas', vid,
              {'before': antes, 'after': despues, 'motivo': 'contrato: ' + accion})
    return _cors(jsonify({'ok': True, 'contrato': res['contrato'],
                          'sin_cambios': bool(res.get('sin_cambios'))}))


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
