import os
import logging
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, make_response, redirect, url_for
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_caching import Cache
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin.menu import MenuLink

# Configuração de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Inicialização do Flask
app = Flask(__name__)

# Carregar variáveis de ambiente
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')
if not app.config['SECRET_KEY']:
    message = "ERRO CRÍTICO DE CONFIGURAÇÃO: A variável de ambiente FLASK_SECRET_KEY não está definida. A aplicação não pode iniciar de forma segura."
    logger.critical(message)
    raise ValueError(message)
else:
    logger.info("FLASK_SECRET_KEY carregada com sucesso do ambiente.")

# Configuração do CORS
CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'http://localhost:3000').split(',')
CORS(app, resources={r"/*": {"origins": CORS_ORIGINS}})
logger.info(f"CORS Configurado para origens: {CORS_ORIGINS}")

# Configuração do Limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://", # Pode ser Redis para produção
    strategy="fixed-window"
)

# Configuração do Cache
cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache'}) # Pode ser Redis para produção
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Configuração do Banco de Dados (Adaptado para MySQL da Railway) ---
# Usamos os nomes de variáveis que a Railway fornece para o MySQL
dbconfig = {
    'host': os.getenv('MYSQLHOST'),
    'user': os.getenv('MYSQLUSER'),
    'password': os.getenv('MYSQLPASSWORD'),
    'database': os.getenv('MYSQLDATABASE'),
    'port': int(os.getenv('MYSQLPORT', 3306)), # Padrão 3306 se não definido
    'pool_name': 'radar_pncp_pool',
    'pool_size': 5
}

try:
    import mysql.connector.pooling
    connection_pool = mysql.connector.pooling.MySQLConnectionPool(**dbconfig)
    logger.info("Configurado para usar MySQL da Railway.")
    # Testar conexão inicial
    with connection_pool.get_connection() as cnx:
        if cnx.is_connected():
            logger.info("Conexão inicial com MySQL bem-sucedida.")
        else:
            raise Exception("Conexão inicial com MySQL falhou.")
except ImportError:
    logger.error("ERRO CRÍTICO: mysql-connector-python não está instalado. A aplicação não pode iniciar sem o driver MySQL.")
    raise ImportError("mysql-connector-python não encontrado. Verifique requirements.txt.")
except Exception as e:
    logger.error(f"ERRO CRÍTICO: Não foi possível inicializar o pool de conexão MySQL: {e}")
    raise ValueError(f"Erro ao conectar ao MySQL. Verifique as variáveis de ambiente MYSQLHOST, MYSQLUSER, MYSQLPASSWORD, MYSQLDATABASE, MYSQLPORT: {e}")

def get_db_connection():
    return connection_pool.get_connection()

# --- Configuração do Firebase (Desativado por padrão) ---
firebase_enabled = os.getenv('FIREBASE_ENABLED', 'false').lower() == 'true'
if firebase_enabled:
    try:
        import firebase_admin
        from firebase_admin import credentials
        cred_path = os.getenv('FIREBASE_CREDENTIALS_PATH', 'firebase_credentials.json')
        cred = credentials.Certificate(cred_path)
        firebase_admin.initialize_app(cred)
        logger.info("Firebase inicializado com sucesso.")
    except ImportError:
        logger.error("ERRO: firebase_admin não está instalado. Firebase não será inicializado.")
    except Exception as e:
        logger.error(f"ERRO AO INICIAR FIREBASE: {e}")
        # Não vamos crashar a aplicação por causa do Firebase se ele não for crítico
else:
    logger.info("Firebase desativado via variável de ambiente FIREBASE_ENABLED.")

# --- Modelos de Usuário para Flask-Login ---
class User(UserMixin):
    def __init__(self, id, username, email, is_admin=False):
        self.id = id
        self.username = username
        self.email = email
        self.is_admin = is_admin

    @staticmethod
    def get(user_id):
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True) # Retorna dicionário para facilitar acesso
            cursor.execute("SELECT id, username, email, is_admin FROM users WHERE id = %s", (user_id,))
            user_data = cursor.fetchone()
            if user_data:
                return User(user_data['id'], user_data['username'], user_data['email'], user_data['is_admin'])
            return None
        except Exception as e:
            logger.error(f"Erro ao buscar usuário por ID: {e}")
            return None
        finally:
            if cursor: cursor.close()
            if conn: conn.close()

    @staticmethod
    def get_by_username(username):
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT id, username, email, password_hash, is_admin FROM users WHERE username = %s", (username,))
            user_data = cursor.fetchone()
            return user_data # Retorna todos os dados para verificação de senha
        except Exception as e:
            logger.error(f"Erro ao buscar usuário por username: {e}")
            return None
        finally:
            if cursor: cursor.close()
            if conn: conn.close()

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# --- Flask-Admin ---
admin = Admin(app, name='Radar PNCP Admin', template_mode='bootstrap4')

class AuthenticatedModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login', next=request.url))

# Exemplo de como adicionar uma tabela para o Admin (você precisará adaptar)
# admin.add_view(AuthenticatedModelView(User, session)) # Se User fosse um modelo SQLAlchemy

# Link para o logout no Admin
admin.add_link(MenuLink(name='Logout', url='/logout'))

# --- Rotas de Autenticação ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin.index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user_data = User.get_by_username(username)

        if user_data and bcrypt.check_password_hash(user_data['password_hash'], password):
            user = User(user_data['id'], user_data['username'], user_data['email'], user_data['is_admin'])
            login_user(user)
            return redirect(url_for('admin.index'))
        else:
            return "Login inválido", 401
    return '''
        <form method="post">
            <p><input type=text name=username></p>
            <p><input type=password name=password></p>
            <p><input type=submit value=Login></p>
        </form>
    '''

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- Rotas da API ---
@app.route('/')
@limiter.limit("10 per minute")
def home():
    return jsonify({"message": "API Radar PNCP está online!"})

@app.route('/editais', methods=['GET'])
@limiter.limit("5 per minute")
def get_editais():
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True) # Retorna dicionário para facilitar acesso

        # Exemplo de query (adapte para sua tabela 'editais')
        # Certifique-se de que sua tabela 'editais' existe no MySQL
        query = "SELECT id, numero_controle_pncp, titulo, objeto, orgao_nome, valor_estimado, data_abertura, link_edital FROM editais LIMIT 100"
        cursor.execute(query)
        editais = cursor.fetchall()

        editais_list = []
        for edital in editais:
            editais_list.append({
                "id": edital.get('id'),
                "numero_controle_pncp": edital.get('numero_controle_pncp'),
                "titulo": edital.get('titulo'),
                "objeto": edital.get('objeto'),
                "orgao_nome": edital.get('orgao_nome'),
                "valor_estimado": str(edital.get('valor_estimado')) if edital.get('valor_estimado') else None,
                "data_abertura": edital.get('data_abertura').isoformat() if edital.get('data_abertura') else None,
                "link_edital": edital.get('link_edital')
            })
        return jsonify(editais_list)
    except Exception as e:
        logger.error(f"Erro ao buscar editais: {e}")
        return jsonify({"error": "Erro interno do servidor"}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# --- Rota para criar usuário admin (apenas para desenvolvimento/primeira configuração) ---
@app.route('/create_admin_user', methods=['POST'])
def create_admin_user():
    # Esta rota deve ser protegida ou removida em produção!
    if os.getenv('FLASK_ENV') != 'development':
        return jsonify({"message": "Esta rota está desativada em produção."}), 403

    username = request.json.get('username')
    password = request.json.get('password')
    email = request.json.get('email')

    if not username or not password or not email:
        return jsonify({"message": "Dados incompletos"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, email, password_hash, is_admin) VALUES (%s, %s, %s, %s)",
            (username, email, hashed_password, True)
        )
        conn.commit()
        return jsonify({"message": f"Admin user {username} created"}), 201
    except Exception as e:
        logger.error(f"Erro ao criar usuário admin: {e}")
        conn.rollback()
        return jsonify({"error": "Erro ao criar usuário admin"}), 500
    finally:
        if cursor: cursor.close()
        if conn: conn.close()

# --- Inicialização da aplicação ---
if __name__ == '__main__':
    logger.info("Aplicação FINND iniciada")
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', 8080)))

