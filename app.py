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
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView
from flask_admin.menu import MenuLink

### NOVO/CORRIGIDO: Importações para MySQL e SQLAlchemy ###
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.ext.declarative import declarative_base

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
### NOVO/CORRIGIDO: Completando a configuração do MySQL ###
# Usamos os nomes de variáveis que a Railway fornece para o MySQL
DB_HOST = os.getenv('MYSQLHOST')
DB_PORT = os.getenv('MYSQLPORT')
DB_USER = os.getenv('MYSQLUSER')
DB_PASSWORD = os.getenv('MYSQLPASSWORD')
DB_NAME = os.getenv('MYSQLDATABASE')

if all([DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME]):
    DATABASE_URL = f"mysql+mysqlconnector://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Boa prática para evitar warnings
    logger.info("Configurado para usar MySQL da Railway.")
else:
    message = "ERRO CRÍTICO DE CONFIGURAÇÃO: Variáveis de ambiente do MySQL não estão totalmente definidas. Verifique MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DATABASE."
    logger.critical(message)
    raise ValueError(message)

db = SQLAlchemy(app)

# Teste de conexão inicial com o MySQL
try:
    with app.app_context():
        db.engine.connect()
    logger.info("Conexão inicial com MySQL bem-sucedida.")
except Exception as e:
    logger.critical(f"ERRO: Falha na conexão inicial com MySQL: {e}")
    raise e

### NOVO/CORRIGIDO: Definição do modelo para a tabela 'licitacoes' ###
# O Flask-Admin precisa de modelos para gerenciar as tabelas
class Licitacao(db.Model):
    __tablename__ = 'licitacoes' # Nome da tabela no banco de dados
    id = db.Column(db.Integer, primary_key=True)
    numero_controle_pncp = db.Column(db.String(255), unique=True)
    titulo = db.Column(db.Text)
    objeto = db.Column(db.Text)
    orgao_cnpj = db.Column(db.String(20))
    orgao_nome = db.Column(db.String(255))
    valor_estimado = db.Column(db.Numeric(15, 2))
    data_abertura = db.Column(db.DateTime)
    data_encerramento = db.Column(db.DateTime)
    modalidade = db.Column(db.String(100))
    uf = db.Column(db.String(2))
    municipio = db.Column(db.String(255))
    link_edital = db.Column(db.String(500))
    status = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<Licitacao {self.titulo}>'

### NOVO/CORRIGIDO: Firebase desativado (já estava no seu log, mantido) ###
FIREBASE_ENABLED = os.getenv('FIREBASE_ENABLED', 'false').lower() == 'true'
if not FIREBASE_ENABLED:
    logger.info("Firebase desativado via variável de ambiente FIREBASE_ENABLED.")
# else:
#     # Configuração do Firebase (se FIREBASE_ENABLED for 'true')
#     try:
#         import firebase_admin
#         from firebase_admin import credentials, auth
#         # Certifique-se de que o arquivo firebase_credentials.json está no caminho correto
#         cred = credentials.Certificate("firebase_credentials.json")
#         firebase_admin.initialize_app(cred)
#         logger.info("Firebase inicializado com sucesso.")
#     except Exception as e:
#         logger.error(f"Erro ao inicializar Firebase: {e}")
#         FIREBASE_ENABLED = False # Desativa se houver erro na inicialização

# --- Configuração do Flask-Login (Exemplo de Usuário) ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Rotas de Autenticação (Exemplo) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('admin.index')) # Redireciona para o admin após login
        return 'Login falhou'
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

# --- Painel Admin (Flask-Admin) ---
### NOVO/CORRIGIDO: Sua MyAdminIndexView para resolver o erro 'stats' ###
class MyAdminIndexView(AdminIndexView):
    @login_required # Garante que só usuários logados acessem o admin
    def index(self):
        # Aqui é onde buscamos os dados para 'stats' do MySQL
        try:
            total_licitacoes = db.session.query(Licitacao).count()
        except Exception as e:
            logger.error(f"Erro ao buscar total de licitações para o admin: {e}")
            total_licitacoes = 0 # Em caso de erro, mostra 0 para não quebrar a página

        stats = {
            "total_posts": total_licitacoes, # Usamos 'total_posts' para compatibilidade com seu template
            # Você pode adicionar mais estatísticas aqui, por exemplo:
            # "licitacoes_abertas": db.session.query(Licitacao).filter_by(status='aberta').count()
        }

        # Passamos a variável 'stats' para o template
        return self.render('admin/index.html', stats=stats)

# Inicialização do Flask-Admin com sua view personalizada
admin = Admin(
    app,
    name='RADAR PNCP Admin',
    template_mode='bootstrap4',
        index_view=MyAdminIndexView(name='Dashboard', template='admin/index.html') # Adicionado o template aqui
)

# Adicionar modelos ao Flask-Admin para gerenciar no painel
admin.add_view(ModelView(User, db.session, name='Usuários'))
admin.add_view(ModelView(Licitacao, db.session, name='Licitações')) # Adiciona o modelo Licitacao

# --- Rotas da API (Exemplo) ---
@app.route('/')
def home():
    return "Bem-vindo ao RADAR PNCP Backend!"

@app.route('/api/licitacoes', methods=['GET'])
@limiter.limit("10 per minute")
def get_licitacoes():
    # Exemplo de como buscar licitações do banco de dados
    licitacoes = Licitacao.query.limit(10).all()
    results = []
    for licitacao in licitacoes:
        results.append({
            'id': licitacao.id,
            'titulo': licitacao.titulo,
            'objeto': licitacao.objeto,
            'status': licitacao.status,
            'data_abertura': licitacao.data_abertura.isoformat() if licitacao.data_abertura else None
        })
    return jsonify(results)

# --- Inicialização da Aplicação ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Cria as tabelas no MySQL se elas não existirem
        # Exemplo: Criar um usuário admin se não existir
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin')
            admin_user.set_password('admin123') # Mude para uma senha forte em produção!
            db.session.add(admin_user)
            db.session.commit()
            logger.info("Usuário 'admin' criado com senha 'admin123'.")
    app.run(debug=True, host='0.0.0.0', port=8080)



