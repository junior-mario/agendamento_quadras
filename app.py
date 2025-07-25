# app.py
from flask import Flask, render_template, request, redirect, url_for, flash, g, session, abort, jsonify, make_response
import sqlite3
import json
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import os # Importar para criar diretório de logs
import csv # Importar para lidar com CSV
import io # Importar para lidar com strings como arquivos

app = Flask(__name__)
app.secret_key = 'super_secret_key_change_me_to_a_long_random_string' # ALTO RECOMENDADO: Altere para uma chave secreta real e complexa em produção!

# --- Configuração do Banco de Dados SQLite ---
DB_FILE = 'court_bookings.db' # Nome do arquivo do banco de dados SQLite
LOGS_DIR = 'logs' # Diretório para armazenar os arquivos de log JSON

def get_db():
    """
    Retorna uma conexão com o banco de dados SQLite.
    A conexão é armazenada no objeto `g` para ser reutilizada na mesma requisição.
    Adicionado check_same_thread=False para compatibilidade com o servidor de desenvolvimento do Flask.
    """
    if 'db' not in g:
        g.db = sqlite3.connect(DB_FILE, check_same_thread=False)
        g.db.row_factory = sqlite3.Row # Configura o cursor para retornar linhas como objetos Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    """
    Fecha a conexão com o banco de dados ao final da requisição.
    """
    db = g.pop('db', None)
    if db is not None:
        db.close()

def initialize_db_schema():
    """
    Cria as tabelas do banco de dados se elas não existirem e insere usuários padrão.
    Esta função é chamada uma única vez na primeira execução do aplicativo.
    """
    conn = get_db()
    cursor = conn.cursor()

    # Criação da tabela de configurações
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    conn.commit()

    # Inicializa a duração padrão do agendamento se não existir
    cursor.execute("SELECT value FROM settings WHERE key = 'bookingDurationMinutes'")
    if cursor.fetchone() is None:
        cursor.execute("INSERT INTO settings (key, value) VALUES (?, ?)", ('bookingDurationMinutes', '50'))
        conn.commit()
    
    # Criação da tabela de agendamentos
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS bookings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            courtId TEXT NOT NULL,
            startTime TEXT NOT NULL,
            endTime TEXT NOT NULL,
            players TEXT NOT NULL, -- Armazenado como JSON string
            status TEXT NOT NULL,
            bookedBy TEXT,
            isBlockBooking INTEGER NOT NULL, -- 0 para False, 1 para True
            blockBookingReason TEXT,
            createdAt TEXT NOT NULL
        )
    """)
    conn.commit()

    # Criação da tabela da lista de espera
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS waiting_list (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            players TEXT NOT NULL, -- Armazenado como JSON string
            preferredCourt TEXT,
            preferredTime TEXT, -- Apenas a hora (HH:MM)
            requestedAt TEXT NOT NULL,
            status TEXT NOT NULL,
            requestedBy TEXT
        )
    """)
    conn.commit()

    # **********************************************
    # NOVO: Criação da tabela de usuários
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer' -- 'admin', 'operator', 'viewer'
        )
    """)
    conn.commit()

    # NOVO: Inserir usuários padrão se não existirem
    users_to_create = [
        ("admin", "admin", "admin"),
        ("operador", "operador", "operator"),
        ("monitor", "monitor", "viewer")
    ]

    for username, password, role in users_to_create:
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone() is None:
            hashed_password = generate_password_hash(password)
            cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                           (username, hashed_password, role))
            conn.commit()
            print(f"Usuário padrão '{username}' ({role}) criado.")
        else:
            print(f"Usuário padrão '{username}' já existe.")

    print("Esquema do banco de dados SQLite e usuários inicializados/verificados.")

# Inicializa o esquema do banco de dados na primeira vez que a aplicação é executada
with app.app_context():
    initialize_db_schema()

# --- Funções de Ajuda do Banco de Dados (usando get_db()) ---
def get_user_by_username(username):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password_hash, role FROM users WHERE username = ?", (username,))
    return cursor.fetchone()

def get_user_by_id(user_id):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, password_hash, role FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()

def get_all_users():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, role FROM users ORDER BY username ASC")
    return cursor.fetchall()

def create_user_db(username, password, role):
    conn = get_db()
    cursor = conn.cursor()
    try:
        hashed_password = generate_password_hash(password)
        cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                       (username, hashed_password, role))
        conn.commit()
        return True, "Usuário criado com sucesso!"
    except sqlite3.IntegrityError:
        return False, "Nome de usuário já existe."
    except sqlite3.Error as e:
        return False, f"Erro ao criar usuário: {e}"

def update_user_db(user_id, username, role, new_password=None):
    conn = get_db()
    cursor = conn.cursor()
    try:
        # Verifica se o novo username já existe para outro ID
        cursor.execute("SELECT id FROM users WHERE username = ? AND id != ?", (username, user_id))
        if cursor.fetchone():
            return False, "Nome de usuário já existe para outro usuário."

        if new_password:
            hashed_password = generate_password_hash(new_password)
            cursor.execute("UPDATE users SET username = ?, password_hash = ?, role = ? WHERE id = ?",
                           (username, hashed_password, role, user_id))
        else:
            cursor.execute("UPDATE users SET username = ?, role = ? WHERE id = ?",
                           (username, role, user_id))
        conn.commit()
        return True, "Usuário atualizado com sucesso!"
    except sqlite3.Error as e:
        return False, f"Erro ao atualizar usuário: {e}"

def delete_user_db(user_id):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        return True, "Usuário apagado com sucesso!"
    except sqlite3.Error as e:
        return False, f"Erro ao apagar usuário: {e}"


def get_settings_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = 'bookingDurationMinutes'")
    result = cursor.fetchone()
    return {"bookingDurationMinutes": int(result[0])} if result else {"bookingDurationMinutes": 50}

def update_settings_db(new_duration):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("REPLACE INTO settings (key, value) VALUES (?, ?)", ('bookingDurationMinutes', str(new_duration)))
    conn.commit()

def get_bookings_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, courtId, startTime, endTime, players, status, bookedBy, isBlockBooking, blockBookingReason, createdAt FROM bookings")
    bookings_data = cursor.fetchall() # Retorna Rows, que se comportam como dicionários
    bookings = []
    for row in bookings_data:
        booking = {
            "id": row["id"],
            "courtId": row["courtId"],
            "startTime": datetime.fromisoformat(row["startTime"]),
            "endTime": datetime.fromisoformat(row["endTime"]),
            "players": json.loads(row["players"]),
            "status": row["status"],
            "bookedBy": row["bookedBy"],
            "isBlockBooking": bool(row["isBlockBooking"]),
            "blockBookingReason": row["blockBookingReason"],
            "createdAt": datetime.fromisoformat(row["createdAt"])
        }
        bookings.append(booking)
    return bookings

def add_booking_db(court_id, start_time, end_time, players, is_block_booking=False, block_reason=""):
    conn = get_db()
    cursor = conn.cursor()
    
    # Verifica sobreposição de horários
    start_ts = start_time.isoformat()
    end_ts = end_time.isoformat()

    cursor.execute(
        """SELECT id FROM bookings 
           WHERE courtId = ? 
           AND (
               (startTime < ? AND endTime > ?) OR 
               (startTime < ? AND endTime > ?) OR
               (startTime >= ? AND endTime <= ?)
           )""", 
        (court_id, end_ts, start_ts, start_ts, end_ts, start_ts, end_ts)
    )
    if cursor.fetchone():
        return False, "Este horário está em conflito com um agendamento existente."

    players_json = json.dumps(players)
    is_block_booking_int = 1 if is_block_booking else 0

    try:
        cursor.execute(
            """INSERT INTO bookings (courtId, startTime, endTime, players, status, bookedBy, isBlockBooking, blockBookingReason, createdAt)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (court_id, start_time.isoformat(), end_time.isoformat(), players_json, "confirmed", 
             g.user['username'] if g.user else "desconhecido", is_block_booking_int, block_reason, datetime.now().isoformat())
        )
        conn.commit()
        # Logar o evento de agendamento
        log_booking_event(
            "booked" if not is_block_booking else "blocked",
            {
                "courtId": court_id,
                "startTime": start_time.isoformat(),
                "endTime": end_time.isoformat(),
                "players": players,
                "isBlockBooking": is_block_booking,
                "blockBookingReason": block_reason
            },
            g.user['username'] if g.user else "desconhecido"
        )
        return True, "Agendamento realizado com sucesso!" if not is_block_booking else "Quadra bloqueada com sucesso!"
    except sqlite3.Error as e:
        return False, f"Erro ao adicionar agendamento: {e}"

def cancel_booking_db(booking_id):
    conn = get_db()
    cursor = conn.cursor()
    try:
        # Recuperar dados do agendamento antes de deletar para log
        cursor.execute("SELECT id, courtId, startTime, endTime, players, isBlockBooking, blockBookingReason FROM bookings WHERE id = ?", (booking_id,))
        booking_to_log = cursor.fetchone()

        cursor.execute("DELETE FROM bookings WHERE id = ?", (booking_id,))
        conn.commit()

        if booking_to_log:
            # Logar o evento de cancelamento
            log_booking_event(
                "cancelled",
                {
                    "id": booking_to_log["id"],
                    "courtId": booking_to_log["courtId"],
                    "startTime": booking_to_log["startTime"],
                    "endTime": booking_to_log["endTime"],
                    "players": json.loads(booking_to_log["players"]),
                    "isBlockBooking": bool(booking_to_log["isBlockBooking"]),
                    "blockBookingReason": booking_to_log["blockBookingReason"]
                },
                g.user['username'] if g.user else "desconhecido"
            )
        return True, "Agendamento cancelado com sucesso!"
    except sqlite3.Error as e:
        return False, f"Erro ao cancelar agendamento: {e}"

def update_booking_status_db(booking_id, new_status):
    conn = get_db()
    cursor = conn.cursor()
    try:
        # Recuperar dados do agendamento antes de atualizar para log
        cursor.execute("SELECT id, courtId, startTime, endTime, players, isBlockBooking, blockBookingReason FROM bookings WHERE id = ?", (booking_id,))
        booking_to_log = cursor.fetchone()

        cursor.execute("UPDATE bookings SET status = ? WHERE id = ?", (new_status, booking_id))
        conn.commit()

        if booking_to_log and new_status == 'confirmed':
            # Logar o evento de confirmação
            log_booking_event(
                "confirmed",
                {
                    "id": booking_to_log["id"],
                    "courtId": booking_to_log["courtId"],
                    "startTime": booking_to_log["startTime"],
                    "endTime": booking_to_log["endTime"],
                    "players": json.loads(booking_to_log["players"]),
                    "isBlockBooking": bool(booking_to_log["isBlockBooking"]),
                    "blockBookingReason": booking_to_log["blockBookingReason"]
                },
                g.user['username'] if g.user else "desconhecido"
            )
        return True, "Status do agendamento atualizado!"
    except sqlite3.Error as e:
        return False, f"Erro ao atualizar status do agendamento: {e}"

def get_waiting_list_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, players, preferredCourt, preferredTime, requestedAt, status, requestedBy FROM waiting_list ORDER BY requestedAt ASC") # Ordem ascendente para fila
    waiting_data = cursor.fetchall()
    waiting_entries = []
    for row in waiting_data:
        entry = {
            "id": row["id"],
            "players": json.loads(row["players"]),
            "preferredCourt": row["preferredCourt"],
            "preferredTime": row["preferredTime"],
            "requestedAt": datetime.fromisoformat(row["requestedAt"]),
            "status": row["status"],
            "requestedBy": row["requestedBy"]
        }
        waiting_entries.append(entry)
    return waiting_entries

def add_to_waiting_list_db(players, preferred_court=None, preferred_time=None):
    conn = get_db()
    cursor = conn.cursor()
    players_json = json.dumps(players)

    # Validação de sobreposição para a lista de espera se tempo e quadra preferidos forem fornecidos
    if preferred_court and preferred_time:
        try:
            # Assumimos que a preferência de tempo na lista de espera é o início de um agendamento
            # e a duração é a padrão do sistema.
            booking_duration_minutes = get_settings_db()['bookingDurationMinutes']
            
            # Precisamos da data de hoje para construir o datetime para a validação
            today = datetime.now().date()
            preferred_start_time_dt = datetime.combine(today, datetime.strptime(preferred_time, '%H:%M').time())
            preferred_end_time_dt = preferred_start_time_dt + timedelta(minutes=booking_duration_minutes)

            # Verificar sobreposição com agendamentos existentes (confirmados ou bloqueados)
            cursor.execute(
                """SELECT id FROM bookings 
                   WHERE courtId = ? 
                   AND (
                       (startTime < ? AND endTime > ?) OR 
                       (startTime < ? AND endTime > ?) OR
                       (startTime >= ? AND endTime <= ?)
                   )""", 
                (preferred_court, preferred_end_time_dt.isoformat(), preferred_start_time_dt.isoformat(), 
                 preferred_start_time_dt.isoformat(), preferred_end_time_dt.isoformat(), 
                 preferred_start_time_dt.isoformat(), preferred_end_time_dt.isoformat())
            )
            if cursor.fetchone():
                return False, f"O horário preferido {preferred_time} na {preferred_court} já está ocupado ou em conflito com um agendamento existente."
        except ValueError:
            return False, "Formato de hora preferida inválido."
        except Exception as e:
            return False, f"Erro na validação de horário da lista de espera: {e}"


    try:
        cursor.execute(
            """INSERT INTO waiting_list (players, preferredCourt, preferredTime, requestedAt, status, requestedBy)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (players_json, preferred_court, preferred_time, datetime.now().isoformat(), "pending", g.user['username'] if g.user else "desconhecido")
        )
        conn.commit()
        return True, "Adicionado à lista de espera com sucesso!"
    except sqlite3.Error as e:
        return False, f"Erro ao adicionar à lista de espera: {e}"

def remove_from_waiting_list_db(entry_id):
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM waiting_list WHERE id = ?", (entry_id,))
        conn.commit()
        return True, "Entrada removida da lista de espera."
    except sqlite3.Error as e:
        return False, f"Erro ao remover da lista de espera: {e}"

# --- Funções de Lógica de Negócios (similar ao Streamlit, adaptadas para Flask) ---
def get_booking_status(booking, booking_duration_minutes):
    now = datetime.now()
    end_time = booking['endTime']
    start_time = booking['startTime']

    if booking['isBlockBooking']:
        return 'block-booking'
    
    # Check if the booking is currently active (playing)
    if now >= start_time and now < end_time:
        time_remaining = (end_time - now).total_seconds()
        fifteen_minutes_in_seconds = 15 * 60

        if time_remaining <= fifteen_minutes_in_seconds and time_remaining > 0:
            return 'alert-yellow' # Este status é para index.html e tv_view
        return 'playing' # Este status é para index.html e tv_view
    
    # Check if the booking has ended
    elif now >= end_time:
        # If it ended more than 20 minutes ago, apply 'faded-past'
        if (now - end_time).total_seconds() > (20 * 60): # 20 minutes
            return 'faded-past'
        # Otherwise, if it just ended or is within the 20-min window, it's 'alert-red'
        return 'alert-red' # Este status é para index.html e tv_view
    
    # If the booking is in the future
    return 'confirmed' # Este status é para index.html e tv_view

# --- Filtro personalizado para Jinja2 ---
@app.template_filter('strftime')
def format_datetime(value, format="%Y-%m-%d %H:%M:%S"):
    """Formata um objeto datetime."""
    if isinstance(value, datetime):
        return value.strftime(format)
    # Se o valor for uma string (como 'now'), tente converter para datetime ou lidar de outra forma
    # Apenas para o caso específico de 'now', que é o que estava causando o problema.
    elif isinstance(value, str) and value.lower() == 'now':
        return datetime.now().strftime(format)
    return str(value) # Retorna o valor como string para evitar erros se o tipo for inesperado


# --- Context Processor para dados do usuário globalmente ---
@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        g.user = get_user_by_id(user_id)

# --- Decoradores de Autenticação e Autorização ---
def login_required(view):
    """Decorator for routes that require a user to be logged in."""
    @wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            flash("Você precisa estar logado para acessar esta página.", "error")
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

def role_required(roles):
    """Decorator for routes that require specific user roles."""
    def decorator(view):
        @wraps(view)
        def wrapped_view(**kwargs):
            if not g.user: # Not logged in
                flash("Você precisa estar logado para acessar esta página.", "error")
                return redirect(url_for('login'))
            if g.user['role'] not in roles:
                flash(f"Seu perfil '{g.user['role']}' não tem permissão para acessar esta página.", "error")
                # Redireciona para uma página baseada no perfil, ou para a raiz
                if g.user['role'] == 'operator':
                    return redirect(url_for('index'))
                elif g.user['role'] == 'viewer':
                    return redirect(url_for('tv_view'))
                else: # Default para admin ou outros roles sem uma página específica
                    return redirect(url_for('index'))
            return view(**kwargs)
        return wrapped_view
    return decorator


# --- Rotas de Autenticação ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if g.user: # Se já estiver logado, redireciona para a página principal
        if g.user['role'] == 'admin':
            return redirect(url_for('admin_panel'))
        elif g.user['role'] == 'operator':
            return redirect(url_for('index'))
        else: # viewer
            return redirect(url_for('tv_view'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user_by_username(username)

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            flash("Login bem-sucedido!", "success")
            if user['role'] == 'admin':
                return redirect(url_for('admin_panel'))
            elif user['role'] == 'operator':
                return redirect(url_for('index'))
            else: # viewer
                return redirect(url_for('tv_view'))
        else:
            flash("Nome de usuário ou senha inválidos.", "error")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    flash("Você foi desconectado.", "success")
    return redirect(url_for('login'))


# --- Rotas Principais (com controle de acesso) ---
@app.route('/')
@login_required
@role_required(['admin', 'operator'])
def index():
    settings = get_settings_db()
    current_bookings = get_bookings_db()
    waiting_list = get_waiting_list_db() 

    courts = [f"QUADRA {i + 1}" for i in range(7)]
    
    calendar_data = {court: [] for court in courts}
    for booking in current_bookings:
        if booking['courtId'] in calendar_data:
            booking['status_class'] = get_booking_status(booking, settings['bookingDurationMinutes'])
            
            # Ajusta o display_text para bloqueios
            if booking['isBlockBooking']:
                display_text = f"BLOQUEADO:<br>{booking['blockBookingReason']}<br>{booking['startTime'].strftime('%H:%M')} - {booking['endTime'].strftime('%H:%M')}"
            else:
                display_text = f"{', '.join(booking['players'])}"
                display_text += f"<br>{booking['startTime'].strftime('%H:%M')} - {booking['endTime'].strftime('%H:%M')}"
                if booking['status_class'] == 'alert-yellow':
                    display_text += "<br>Atenção!"
                elif booking['status_class'] == 'alert-red':
                    display_text += "<br>Tempo Esgotado!"
            
            booking['display_text'] = display_text
            
            booking_copy = booking.copy()
            booking_copy['startTime'] = booking_copy['startTime'].isoformat()
            booking_copy['endTime'] = booking_copy['endTime'].isoformat()

            calendar_data[booking['courtId']].append(booking_copy)
    
    for court in courts:
        calendar_data[court].sort(key=lambda x: x['startTime'])

    hours_for_modal = [f"{h:02d}:00" for h in range(8, 24)]

    return render_template('index.html', courts=courts, calendar_data=calendar_data, 
                           hours_for_modal=hours_for_modal, settings=settings, 
                           waiting_list=waiting_list)

@app.route('/book', methods=['POST'])
@login_required
@role_required(['admin', 'operator'])
def book_court():
    court_id = request.form['courtId']
    start_time_str = request.form['startTime']
    players_raw = request.form.getlist('players')
    players = [p.strip() for p in players_raw if p.strip()]

    if not players or len(players) < 2 or len(players) > 4:
        flash("É obrigatório ter 2 ou 4 integrantes para o jogo.", "error")
        return redirect(url_for('index'))

    try:
        start_time_dt = datetime.fromisoformat(start_time_str)
    except ValueError:
        flash("Formato de hora inválido.", "error")
        return redirect(url_for('index'))

    settings = get_settings_db()
    end_time_dt = start_time_dt + timedelta(minutes=settings['bookingDurationMinutes'])

    success, message = add_booking_db(court_id, start_time_dt, end_time_dt, players)
    
    if success:
        flash(message, "success")
    else:
        flash(message, "error")

    return redirect(url_for('index'))

@app.route('/admin', methods=['GET', 'POST'])
@login_required
@role_required(['admin'])
def admin_panel():
    settings = get_settings_db()
    all_bookings = get_bookings_db()
    all_bookings.sort(key=lambda x: x['startTime'], reverse=True) # Mais recente primeiro

    all_users = get_all_users() 

    if request.method == 'POST':
        # Gerenciamento de Usuários
        if 'create_user' in request.form:
            username = request.form['new_username']
            password = request.form['new_password']
            role = request.form['new_role']
            success, message = create_user_db(username, password, role)
            flash(message, "success" if success else "error")
            return redirect(url_for('admin_panel'))
        
        elif 'edit_user' in request.form:
            user_id = int(request.form['edit_user_id'])
            username = request.form['edit_username']
            role = request.form['edit_role']
            new_password = request.form.get('edit_password') # Pode ser vazio
            success, message = update_user_db(user_id, username, role, new_password if new_password else None)
            flash(message, "success" if success else "error")
            return redirect(url_for('admin_panel'))

        elif 'delete_user' in request.form:
            user_id = int(request.form['delete_user_id'])
            if user_id == g.user['id']: # Impedir que o admin apague a si mesmo
                flash("Você não pode apagar sua própria conta.", "error")
            else:
                success, message = delete_user_db(user_id)
                flash(message, "success" if success else "error")
            return redirect(url_for('admin_panel'))

        # Restante das operações do admin_panel (já existentes)
        elif 'update_duration' in request.form:
            new_duration = int(request.form['new_duration'])
            update_settings_db(new_duration)
            flash("Duração do agendamento atualizada com sucesso!", "success")
            return redirect(url_for('admin_panel'))
        
        elif 'block_court' in request.form:
            court_id = request.form['block_court_id']
            reason = request.form['block_reason']
            start_date_str = request.form['block_start_date']
            start_time_str = request.form['block_start_time']
            end_date_str = request.form['block_end_date']
            end_time_str = request.form['block_end_time']

            # CORREÇÃO AQUI: Usar strptime para a hora
            start_datetime = datetime.combine(datetime.fromisoformat(start_date_str).date(), datetime.strptime(start_time_str, '%H:%M').time())
            end_datetime = datetime.combine(datetime.fromisoformat(end_date_str).date(), datetime.strptime(end_time_str, '%H:%M').time())

            if start_datetime >= end_datetime:
                flash("A data/hora de início deve ser anterior à data/hora de término.", "error")
            elif not reason:
                flash("Por favor, insira o motivo do bloqueio.", "error")
            else:
                success, message = add_booking_db(court_id, start_datetime, end_datetime, [], is_block_booking=True, block_reason=reason)
                if success:
                    flash(message, "success")
                else:
                    flash(message, "error")
            return redirect(url_for('admin_panel'))

        elif 'cancel_booking' in request.form:
            booking_id = int(request.form['booking_id'])
            success, message = cancel_booking_db(booking_id)
            if success:
                flash(message, "success")
            else:
                flash(message, "error")
            return redirect(url_for('admin_panel'))
        
        elif 'confirm_provisional' in request.form:
            booking_id = int(request.form['booking_id'])
            success, message = update_booking_status_db(booking_id, 'confirmed')
            if success:
                flash(message, "success")
            else:
                flash(message, "error")
            return redirect(url_for('admin_panel'))


    courts = [f"QUADRA {i + 1}" for i in range(7)]
    current_date = datetime.now().strftime('%Y-%m-%d')
    current_time = datetime.now().strftime('%H:%M')
    one_hour_later = (datetime.now() + timedelta(hours=1)).strftime('%H:%M')

    return render_template('admin.html', settings=settings, bookings=all_bookings, courts=courts, 
                           current_date=current_date, current_time=current_time, one_hour_later=one_hour_later, all_users=all_users)

@app.route('/tv_view')
@login_required
@role_required(['admin', 'viewer'])
def tv_view():
    # Esta rota agora apenas renderiza o template que buscará os dados da API
    return render_template('tv_view.html')

@app.route('/api/dashboard_data')
@login_required
@role_required(['admin', 'viewer'])
def api_dashboard_data():
    settings = get_settings_db()
    all_bookings = get_bookings_db()

    courts = [f"QUADRA {i + 1}" for i in range(7)]
    dashboard_output_data = []

    start_display_hour = 8 
    end_display_hour = 23 # Display until 23:59:59

    now = datetime.now()
    today = now.replace(hour=0, minute=0, second=0, microsecond=0) # Apenas a data de hoje

    for court_name in courts:
        court_bookings = sorted([b for b in all_bookings if b['courtId'] == court_name], key=lambda x: x['startTime'])
        
        court_display_slots = []
        
        # Gera todos os slots de 30 minutos para o dia de exibição
        current_slot_time = today.replace(hour=start_display_hour, minute=0, second=0, microsecond=0)
        slot_granularity_minutes = 30 # A granularidade dos slots de exibição

        while current_slot_time <= today.replace(hour=end_display_hour, minute=59, second=59, microsecond=999999):
            slot_end_time = current_slot_time + timedelta(minutes=slot_granularity_minutes)
            
            # Encontra um agendamento que se sobreponha a este slot de tempo
            overlapping_booking = None
            for booking in court_bookings:
                # Condição de sobreposição: [start1, end1) e [start2, end2) se sobrepõem se start1 < end2 e end1 > start2
                if booking['startTime'] < slot_end_time and booking['endTime'] > current_slot_time:
                    overlapping_booking = booking
                    break
            
            slot_status_class = ''
            content_html = ''
            slot_type = 'free'

            if overlapping_booking:
                # Se há um agendamento sobreposto, use seus dados
                booking_status_from_logic = get_booking_status(overlapping_booking, settings['bookingDurationMinutes'])
                
                # Mapeia os status do backend para as classes CSS do frontend
                if overlapping_booking['isBlockBooking']:
                    slot_status_class = 'block-booking-tv' # Classe específica para bloqueio
                elif booking_status_from_logic == 'playing':
                    slot_status_class = 'slot-playing-active' # Classe para "em jogo"
                elif booking_status_from_logic == 'alert-yellow' or booking_status_from_logic == 'alert-red':
                    slot_status_class = 'slot-ending-soon' # Para alert-yellow e alert-red
                elif booking_status_from_logic == 'confirmed':
                    slot_status_class = 'slot-ocupado'
                elif booking_status_from_logic == 'faded-past':
                    slot_status_class = 'slot-passado'

                players_or_reason = (', '.join(overlapping_booking['players']) if not overlapping_booking['isBlockBooking'] 
                                     else overlapping_booking['blockBookingReason'])

                content_html = (
                    f"<span class='cliente-nome'>{players_or_reason}</span>"
                    f"<span class='horario-time'>{overlapping_booking['startTime'].strftime('%H:%M')} - {overlapping_booking['endTime'].strftime('%H:%M')}</span>"
                )
                slot_type = 'booked' if not overlapping_booking['isBlockBooking'] else 'blocked'

            else:
                # Se não há agendamento sobreposto, o slot está livre
                if current_slot_time < now and slot_end_time > now: # Slot atual (parcialmente no passado e futuro)
                    slot_status_class = 'slot-atual'
                    content_html = f"<span class='horario-time'>{current_slot_time.strftime('%H:%M')} - {slot_end_time.strftime('%H:%M')}</span>"
                elif slot_end_time <= now: # Slot no passado
                    slot_status_class = 'slot-passado'
                    content_html = f"<span class='horario-time'>{current_slot_time.strftime('%H:%M')} - {slot_end_time.strftime('%H:%M')}</span>"
                else: # Slot no futuro
                    slot_status_class = 'slot-livre'
                    content_html = f"<span class='horario-time'>{current_slot_time.strftime('%H:%M')} - {slot_end_time.strftime('%H:%M')}</span>"
                slot_type = 'free'

            court_display_slots.append({
                'startTime': current_slot_time.isoformat(),
                'endTime': slot_end_time.isoformat(),
                'content': content_html,
                'status_class': slot_status_class,
                'type': slot_type
            })
            
            current_slot_time += timedelta(minutes=slot_granularity_minutes)

        # Determina o status geral da quadra (livre/ocupada) para o cabeçalho
        quadra_overall_status = 'livre'
        for booking in court_bookings:
            # Se há um agendamento ou bloqueio ativo AGORA
            if now >= booking['startTime'] and now < booking['endTime']:
                quadra_overall_status = 'ocupada'
                break

        dashboard_output_data.append({
            'id': court_name, 
            'nome': court_name,
            'tipo': 'Tênis/Esportes',
            'status': quadra_overall_status,
            'agendamentos': court_display_slots
        })
    
    return jsonify(dashboard_output_data)


@app.route('/statistics')
@login_required
@role_required(['admin']) # Somente admin pode ver estatísticas
def statistics_panel():
    all_bookings = get_bookings_db()

    # Calcula as horas mais populares
    hour_counts = {}
    for booking in all_bookings:
        # Se for um agendamento dinâmico, considere a hora de início
        start_hour = booking['startTime'].hour
        hour_counts[start_hour] = hour_counts.get(start_hour, 0) + 1
    
    sorted_hours = sorted(hour_counts.items(), key=lambda item: item[1], reverse=True)
    most_popular_hours = [(f"{hour:02d}h", count) for hour, count in sorted_hours[:5]]

    # Calcula as quadras mais populares
    court_counts = {}
    for booking in all_bookings:
        court_counts[booking['courtId']] = court_counts.get(booking['courtId'], 0) + 1
    
    sorted_courts = sorted(court_counts.items(), key=lambda item: item[1], reverse=True)
    most_popular_courts = [(court, count) for court, count in sorted_courts[:5]]

    # Calcula a média de tempo de jogo
    total_duration = 0
    count_confirmed = 0
    for booking in all_bookings:
        if not booking.get('isBlockBooking') and booking.get('status') == 'confirmed':
            duration = (booking['endTime'] - booking['startTime']).total_seconds() / 60
            total_duration += duration
            count_confirmed += 1
    
    average_play_time = (total_duration / count_confirmed) if count_confirmed > 0 else 0

    return render_template('statistics.html', 
                           most_popular_hours=most_popular_hours, 
                           most_popular_courts=most_popular_courts, 
                           average_play_time=average_play_time)

# --- Funções de Log de Agendamentos ---
def log_booking_event(event_type, booking_info, performed_by_user):
    """
    Registra um evento de agendamento (booked, cancelled, confirmed, blocked) em um arquivo JSON diário.
    """
    if not os.path.exists(LOGS_DIR):
        os.makedirs(LOGS_DIR)

    today_str = datetime.now().strftime('%Y-%m-%d')
    log_file_path = os.path.join(LOGS_DIR, f'bookings_log_{today_str}.json')

    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "event_type": event_type,
        "booking_info": booking_info,
        "performed_by": performed_by_user
    }

    # Tenta ler logs existentes, adiciona o novo e reescreve
    logs = []
    if os.path.exists(log_file_path):
        try:
            with open(log_file_path, 'r', encoding='utf-8') as f:
                logs = json.load(f)
        except json.JSONDecodeError:
            # Arquivo corrompido ou vazio, inicia um novo
            logs = []
    
    logs.append(log_entry)

    with open(log_file_path, 'w', encoding='utf-8') as f:
        json.dump(logs, f, ensure_ascii=False, indent=4)
    
    print(f"Evento logado: {event_type} por {performed_by_user} em {booking_info.get('courtId')}")

# --- Rota para visualização de Logs ---
@app.route('/admin/get_daily_logs', methods=['POST'])
@login_required
@role_required(['admin']) # Apenas administradores podem ver os logs
def get_daily_logs():
    data = request.get_json()
    selected_date_str = data.get('date')

    if not selected_date_str:
        return jsonify({"error": "Data não fornecida."}), 400

    log_file_path = os.path.join(LOGS_DIR, f'bookings_log_{selected_date_str}.json')

    if os.path.exists(log_file_path):
        try:
            with open(log_file_path, 'r', encoding='utf-8') as f:
                logs = json.load(f)
            return jsonify(logs), 200
        except json.JSONDecodeError:
            return jsonify({"error": "Arquivo de log corrompido ou vazio para esta data."}), 500
        except Exception as e:
            return jsonify({"error": f"Erro ao ler arquivo de log: {e}"}), 500
    else:
        return jsonify({"message": "Nenhum log encontrado para esta data."}), 404

# --- Rota para exportação de Logs CSV ---
@app.route('/admin/export_daily_logs_csv', methods=['POST'])
@login_required
@role_required(['admin'])
def export_daily_logs_csv():
    data = request.get_json()
    selected_date_str = data.get('date')

    if not selected_date_str:
        return jsonify({"error": "Data não fornecida para exportação CSV."}), 400

    log_file_path = os.path.join(LOGS_DIR, f'bookings_log_{selected_date_str}.json')

    if not os.path.exists(log_file_path):
        return jsonify({"message": "Nenhum log encontrado para esta data para exportação CSV."}), 404

    try:
        with open(log_file_path, 'r', encoding='utf-8') as f:
            logs = json.load(f)

        # Preparar os dados para CSV
        output = io.StringIO()
        writer = csv.writer(output)

        # Cabeçalho do CSV
        writer.writerow(["Timestamp", "Tipo de Evento", "Quadra", "Hora Inicio", "Hora Fim", "Integrantes/Motivo", "Realizado Por"])

        for log in logs:
            booking_info = log.get('booking_info', {})
            event_type = log.get('event_type', 'N/A')
            performed_by = log.get('performed_by', 'Desconhecido')
            timestamp = datetime.fromisoformat(log.get('timestamp')).strftime('%Y-%m-%d %H:%M:%S')

            court_id = booking_info.get('courtId', 'N/A')
            start_time_iso = booking_info.get('startTime', datetime.now().isoformat())
            end_time_iso = booking_info.get('endTime', datetime.now().isoformat())
            
            # Garante que os valores são strings para evitar erros se forem None/vazios
            start_time = datetime.fromisoformat(start_time_iso).strftime('%H:%M') if start_time_iso else 'N/A'
            end_time = datetime.fromisoformat(end_time_iso).strftime('%H:%M') if end_time_iso else 'N/A'

            players_or_reason = ""
            if booking_info.get('isBlockBooking'):
                players_or_reason = f"BLOQUEIO: {booking_info.get('blockBookingReason', 'N/A')}"
            else:
                players_list = booking_info.get('players', [])
                players_or_reason = ", ".join(players_list)

            writer.writerow([
                timestamp,
                event_type.upper(),
                court_id,
                start_time,
                end_time,
                players_or_reason,
                performed_by
            ])
        
        csv_data = output.getvalue()
        
        response = make_response(csv_data)
        response.headers["Content-Disposition"] = f"attachment; filename=logs_agendamento_{selected_date_str}.csv"
        response.headers["Content-type"] = "text/csv"
        return response

    except json.JSONDecodeError:
        return jsonify({"error": "Arquivo de log corrompido ou vazio para esta data."}), 500
    except Exception as e:
        return jsonify({"error": f"Erro ao gerar CSV: {e}"}), 500

# Rotas API para a Lista de Espera (para serem chamadas por JS)
@app.route('/api/add_to_waiting_list', methods=['POST'])
@login_required
@role_required(['admin', 'operator'])
def api_add_to_waiting_list():
    data = request.get_json()
    players = [p.strip() for p in data.get('players', []) if p.strip()]
    preferred_court = data.get('preferred_court') or None
    preferred_time = data.get('preferred_time') or None

    if not players or (len(players) != 2 and len(players) != 4):
        return jsonify({"success": False, "message": "É obrigatório ter 2 ou 4 integrantes para a lista de espera."}), 400

    success, message = add_to_waiting_list_db(players, preferred_court, preferred_time)
    return jsonify({"success": success, "message": message})

@app.route('/api/remove_from_waiting_list', methods=['POST'])
@login_required
@role_required(['admin', 'operator'])
def api_remove_from_waiting_list():
    data = request.get_json()
    entry_id = data.get('entry_id')

    if not entry_id:
        return jsonify({"success": False, "message": "ID da entrada não fornecido."}), 400
    
    success, message = remove_from_waiting_list_db(entry_id)
    return jsonify({"success": success, "message": message})

# Rota API para obter a lista de espera (necessária para updateWaitingListDisplay)
@app.route('/api/get_waiting_list', methods=['GET'])
@login_required
@role_required(['admin', 'operator'])
def api_get_waiting_list():
    waiting_list_data = get_waiting_list_db()
    # Converte objetos datetime para string ISO para JSON serialização
    serializable_waiting_list = []
    for entry in waiting_list_data:
        serializable_entry = entry.copy()
        serializable_entry['requestedAt'] = serializable_entry['requestedAt'].isoformat()
        serializable_waiting_list.append(serializable_entry)
    return jsonify({"waiting_list": serializable_waiting_list}), 200


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
