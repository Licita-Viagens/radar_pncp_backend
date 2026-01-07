import os
import logging
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, make_response
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

# --- Configuração do Banco de Dados (Adaptado para PostgreSQL) ---
db_type = os.getenv('DB_TYPE', 'postgresql').lower() # Padrão para postgresql na Railway

if db_type == 'postgresql':
    import psycopg2
    dbconfig = {
        'host': os.getenv('DB_HOST'),
        'user': os.getenv('DB_USER'),
        'password': os.getenv('DB_PASSWORD'),
        'database': os.getenv('DB_NAME'),
        'port': int(os.getenv('DB_PORT', 5432)),
    }
    logger.info("Configurado para usar PostgreSQL.")
    # Testar conexão inicial (opcional, mas bom para depuração)
    try:
        conn = psycopg2.connect(**dbconfig)
        conn.close()
        logger.info("Conexão inicial com PostgreSQL bem-sucedida.")
    except Exception as e:
        logger.error(f"ERRO CRÍTICO: Não foi possível conectar ao PostgreSQL no startup: {e}")
        raise ValueError(f"Erro ao conectar ao PostgreSQL: {e}")

else:
    # Fallback para MySQL (se DB_TYPE não for 'postgresql')
    try:
        import mysql.connector.pooling
        dbconfig = {
            'host': os.getenv('DB_HOST', 'localhost'),
            'user': os.getenv('DB_USER', 'root'),
            'password': os.getenv('DB_PASSWORD', 'root'),
            'database': os.getenv('DB_NAME', 'radar_pncp'),
            'port': int(os.getenv('DB_PORT', 3306)),
            'pool_name': 'radar_pncp_pool',
            'pool_size': 5
        }
        connection_pool = mysql.connector.pooling.MySQLConnectionPool(**dbconfig)
        logger.info("Configurado para usar MySQL.")
    except ImportError:
        logger.error("ERRO: mysql-connector-python não está instalado ou DB_TYPE está incorreto.")
        raise ImportError("mysql-connector-python não encontrado. Instale ou defina DB_TYPE=postgresql.")
    except Exception as e:
        logger.error(f"ERRO CRÍTICO: Não foi possível inicializar o pool de conexão MySQL: {e}")
        raise ValueError(f"Erro ao conectar ao MySQL: {e}")

def get_db_connection():
    if db_type == 'postgresql':
        import psycopg2
        try:
            conn = psycopg2.connect(**dbconfig)
            return conn
        except Exception as e:
            logger.error(f"Erro ao obter conexão PostgreSQL: {e}")
            raise
    else:
        # Para MySQL, usa o pool existente
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
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, email, is_admin FROM users WHERE id = %s", (user_id,))
            user_data = cursor.fetchone()
            if user_data:
                return User(user_data[0], user_data[1], user_data[2], user_data[3])
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
            cursor = conn.cursor()
            cursor.execute("SELECT id, username, email, password_hash, is_admin FROM users WHERE username = %s", (username,))
            user_data = cursor.fetchone()
            if user_data:
                return user_data # Retorna todos os dados para verificação de senha
            return None
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

# Adicione suas tabelas aqui para o Admin
# Exemplo:
# from sqlalchemy import create_engine, Column, Integer, String, Boolean
# from sqlalchemy.orm import sessionmaker, declarative_base
# Base = declarative_base()
# class UserAdmin(Base):
#     __tablename__ = 'users'
#     id = Column(Integer, primary_key=True)
#     username = Column(String(80), unique=True, nullable=False)
#     email = Column(String(120), unique=True, nullable=False)
#     is_admin = Column(Boolean, default=False)
#     # Adicione outras colunas conforme seu esquema de banco de dados
#
# # Configurar SQLAlchemy para Flask-Admin (se você estiver usando ORM)
# # Para PostgreSQL com psycopg2, você precisaria de um ORM como SQLAlchemy
# # ou adaptar o ModelView para usar diretamente o psycopg2
# # Exemplo de configuração SQLAlchemy para PostgreSQL:
# # SQLALCHEMY_DATABASE_URI = f"postgresql://{dbconfig['user']}:{dbconfig['password']}@{dbconfig['host']}:{dbconfig['port']}/{dbconfig['database']}"
# # engine = create_engine(SQLALCHEMY_DATABASE_URI)
# # Session = sessionmaker(bind=engine)
# # session = Session()
# # admin.add_view(AuthenticatedModelView(UserAdmin, session))

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

        if user_data and bcrypt.check_password_hash(user_data[3], password): # user_data[3] é o password_hash
            user = User(user_data[0], user_data[1], user_data[2], user_data[4]) # user_data[4] é is_admin
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
        cursor = conn.cursor()

        # Exemplo de query (adapte para sua tabela 'public.editais')
        query = "SELECT id, numero_controle_pncp, titulo, objeto, orgao_nome, valor_estimado, data_abertura, link_edital FROM public.editais LIMIT 100"
        cursor.execute(query)
        editais = cursor.fetchall()

        editais_list = []
        for edital in editais:
            editais_list.append({
                "id": edital[0],
                "numero_controle_pncp": edital[1],
                "titulo": edital[2],
                "objeto": edital[3],
                "orgao_nome": edital[4],
                "valor_estimado": str(edital[5]) if edital[5] else None, # Converter Decimal para string
                "data_abertura": edital[6].isoformat() if edital[6] else None,
                "link_edital": edital[7]
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
            "INSERT INTO users (username, email, password_hash, is_admin) VALUES (%s, %s, %s, %s) RETURNING id",
            (username, email, hashed_password, True)
        )
        user_id = cursor.fetchone()[0]
        conn.commit()
        return jsonify({"message": f"Admin user {username} created with ID: {user_id}"}), 201
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

