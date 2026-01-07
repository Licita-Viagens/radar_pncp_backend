import mysql.connector 
from mysql.connector import errors # Para tratamento de erros
# Importações para usuarios e admin
from flask_admin import Admin, BaseView, expose, AdminIndexView
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user
from flask_bcrypt import Bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session, Response
import requests  # Para chamar a API do IBGE
from typing import Optional
from markupsafe import Markup, escape
from functools import wraps
import shlex  # biblioteca padrão que entende aspas em strings
from pydantic import BaseModel, EmailStr, ValidationError
import os  # Para ler variáveis de ambiente
from dotenv import load_dotenv  # Para carregar o arquivo .env
import csv #Esse e os tres de baixo são para o upload de arquivos CSV
import io
import re
from flask import Response
import time
from datetime import datetime, date, timezone
import bleach
from flask_cors import CORS
from flask_caching import Cache
import logging
from logging.handlers import RotatingFileHandler # Para log rotate
from decimal import Decimal # Para manipular números decimais do banco
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
load_dotenv()  # Carrega as variáveis do arquivo .env para o ambiente
import firebase_admin
from firebase_admin import credentials, messaging
from firebase_admin import auth as firebase_auth
import hmac # Para comparação segura de senha
import json
import traceback
import hashlib
from mysql.connector import pooling
from typing import Optional, Union

# =========================================================================
# ========================= FIREBASE ======================================
# Decorator para proteger rotas da API com Token do Firebase
# - Valida o Firebase ID Token
# - Extrai uid e email diretamente do token
# - Injeta uid/email nas rotas protegidas
# - O backend é a única fonte de verdade da identidade do usuário
def login_firebase_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. Pega e valida o cabeçalho
        header = request.headers.get('Authorization')
        if not header or not header.startswith('Bearer '):
            return jsonify({'erro': 'Token de autenticação inválido ou ausente'}), 401
        
        token = header.split(' ')[1]
        
        # --- LÓGICA DE CACHE ---
        try:
            # Cria chave hash curta
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            cache_key = f"firebase_token_{token_hash}"
            
            # Tenta pegar do Redis
            cached_user_info = cache.get(cache_key)
            
            if cached_user_info:
                uid = cached_user_info['uid']
                email = cached_user_info['email']
                return f(uid, email, *args, **kwargs)

            # --- Cache MISS: Valida com o Google ---
            decoded_token = firebase_auth.verify_id_token(token)
            
            # === TRAVA DE SEGURANÇA ===
            # Cuidado: Isso bloqueia usuários que não confirmaram e-mail!
            if not decoded_token.get('email_verified', False):
                return jsonify({
                    'erro': 'E-mail não verificado. Verifique sua caixa de entrada.',
                    'code': 'auth/email-not-verified' 
                }), 403
            # ==========================
            
            uid = decoded_token['uid']
            email = decoded_token.get('email', '')
            
            # Salva no Cache por 50 min
            user_info_to_cache = {'uid': uid, 'email': email}
            cache.set(cache_key, user_info_to_cache, timeout=3000)
            
            return f(uid, email, *args, **kwargs)

        except ValueError as e:
            app.logger.warning(f"Token Firebase rejeitado: {e}")
            return jsonify({'erro': 'Token inválido ou expirado'}), 401
        except Exception as e:
            app.logger.error(f"Erro interno Auth: {e}")
            return jsonify({'erro': 'Erro interno de autenticação'}), 500
            
    return decorated_function

# Inicializa o Firebase (Só faz isso se ainda não tiver inicializado)
try:
    if not firebase_admin._apps:
        # Caminho absoluto é mais seguro em VPS
        cred_path = os.path.join(os.path.dirname(__file__), 'firebase_credentials.json')
        cred = credentials.Certificate(cred_path)
        firebase_admin.initialize_app(cred)
        logging.info("Firebase Admin inicializado com sucesso.")
except Exception as e:
    logging.error(f"ERRO AO INICIAR FIREBASE: {e}")
    # Decisão de projeto: Se o firebase falhar, a API sobe? 
    # Sugiro deixar subir, senão derruba o site todo por erro de config de push.

# ========================= FIM FIREBASE ================================
# ========================================================================

# --- Configurações ---
app = Flask(__name__, template_folder='templates') # O template_folder agora aponta para 'backend/templates/'

# Configura o app para confiar nos cabeçalhos de proxy do Nginx
# x_for=1 significa que ele vai confiar no primeiro IP da lista X-Forwarded-For
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
# --- FIM DO BLOCO ---

# --- Definição do Schema de Validação (Pydantic) ---
class ContatoSchema(BaseModel):
    nome_contato: str
    email_usuario: EmailStr # Valida automaticamente se é um e-mail
    assunto_contato: str
    mensagem_contato: str
    origem: Optional[str] = "mobile"  # Valor padrão se não fornecido

# --- CONFIGURAÇÃO DO CACHE ---
# Configura o cache para usar Redis, com um timeout padrão de 1 hora (3600 segundos)
cache = Cache(app, config={
    'CACHE_TYPE': 'RedisCache',
    'CACHE_REDIS_URL': 'redis://localhost:6379/0',
    'CACHE_DEFAULT_TIMEOUT': 10800 # 3600 # (Segundos) Equivale a 1 hora - Mas vou deixar 3 horas nessa porra
})

# --- CONFIGURAÇÃO DE LOGGING PARA A APLICAÇÃO FLASK ---
# Garante que o diretório de logs exista
if not os.path.exists('logs'):
    os.mkdir('logs')

# Cria um handler que rotaciona os arquivos de log
# Manterá 5 arquivos de 10MB cada. Quando o log atual atinge 10MB,
# ele é renomeado para app.log.1 e um novo app.log é criado.
file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240000, backupCount=5)

# Define o formato do log
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))

# Define o nível do log
file_handler.setLevel(logging.INFO) # Em produção, INFO é um bom nível. Para depurar, use logging.DEBUG

# Adiciona o handler ao logger da aplicação Flask
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)

app.logger.info('Aplicação FINND iniciada')
# --- FIM DA CONFIGURAÇÃO DE LOGGING ---

# --- LOG PARA SABER QUAL URL RECEBEMOS ---
@app.before_request
def log_request_info():
    """Loga a URL completa, método e IP de cada requisição recebida."""
    # Evita logar requisições para arquivos estáticos (CSS, JS, imagens), 
    # que geram muito "ruído" no log.
    if request.path.startswith('/static'):
        return

    app.logger.info("--------------------- Nova Requisição -----------------------")
    # Loga a informação desejada usando o logger que você já configurou
    app.logger.info(
        f"Requisição Recebida: {request.method} {request.url} - IP: {request.remote_addr}"
    )

    # Loga também os parâmetros já decodificados
    app.logger.info(f"Parâmetros decodificados: {dict(request.args)}")
# --- FIM DO LOG DE REQUISIÇÕES ---

# --- INÍCIO DA CONFIGURAÇÃO DO RATE LIMITER ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["450 per 5 minutes", "100 per minute"], # Limite padrão para todas as rotas
    storage_uri="redis://localhost:6379" # Use 'memory://' ou configure um Redis
)
# --- FIM DA CONFIGURAÇÃO DO RATE LIMITER ---

# Chave secreta para sessões e flash messages
app.secret_key = os.getenv('FLASK_SECRET_KEY')
if not app.secret_key:    
    message = "ERRO CRÍTICO DE CONFIGURAÇÃO: A variável de ambiente FLASK_SECRET_KEY não está definida. A aplicação não pode iniciar de forma segura."
    app.logger.critical(message) # O logger do Flask pode não estar totalmente pronto aqui, mas tentamos.
    # Para garantir que a mensagem apareça e a aplicação pare:
    import sys
    sys.stderr.write(message + "\n")
    raise ValueError(message) # Impede que a aplicação continue sem a chave.
# Se chegou até aqui, a app.secret_key foi carregada com sucesso.
app.logger.info("FLASK_SECRET_KEY carregada com sucesso do ambiente.")

### Configuração de CORS baseada no ambiente ###
AMBIENTE = os.getenv('AMBIENTE', 'desenvolvimento')

allowed_origins = []

if AMBIENTE == 'producao':
    allowed_origins_str = os.getenv('FRONTEND_URL_PROD', '')
    # Garante que removemos espaços em branco acidentais entre as virgulas
    allowed_origins = [url.strip() for url in allowed_origins_str.split(',') if url.strip()]
else:
    # Em desenvolvimento, aceitamos uma lista padrão ou vinda do env
    dev_urls = os.getenv('FRONTEND_URL_DEV', 'http://localhost:3000')
    allowed_origins = [url.strip() for url in dev_urls.split(',') if url.strip()]

# Logs para debug (vai aparecer no pm2 logs se der erro)
app.logger.info(f"CORS Configurado para origens: {allowed_origins}")

# Habilita o CORS apenas para as rotas da API pública, permitindo que o frontend faça requisições
# A área /admin não precisa de CORS pois será acessada diretamente no mesmo domínio do backend.
CORS(app, resources={r"/api/.*": {"origins": allowed_origins}})

# Configurações de segurança e login
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Redireciona para a rota 'login' se não estiver logado
login_manager.login_message = "Por favor, faça login para acessar esta página."
login_manager.login_message_category = "info"


# --- Função Auxiliares e de Conecção para o Banco de Dados ---
dbconfig = {
    "host": os.getenv('MARIADB_HOST'),
    "user": os.getenv('MARIADB_USER'),
    "password": os.getenv('MARIADB_PASSWORD'),
    "database": os.getenv('MARIADB_DATABASE'),
    "pool_name": "finnd_pool",
    "pool_size": 10, # Mantém 10 conexões vivas e reaproveita ---- QUANDO SUBIR O NUMERO DE USUARIOS PRECISA AUMENTAR ISSO AQUI ----
    "autocommit": False
}
connection_pool = pooling.MySQLConnectionPool(**dbconfig)

def get_db_connection():
    """
    Retorna uma conexão válida do pool MariaDB.

    - Reutiliza conexões (connection pooling)
    - Revalida conexão morta
    - Evita churn de TCP
    - Seguro para Gunicorn + produção
    """
    try:
        conn = connection_pool.get_connection()

        # Garante que a conexão ainda está viva
        if not conn.is_connected():
            conn.reconnect(attempts=2, delay=1)

        return conn

    except mysql.connector.Error as err:
        app.logger.error(f"Erro ao obter conexão do pool MariaDB: {err}")
        return None

    except Exception as err:
        app.logger.exception("Erro inesperado ao obter conexão do pool")
        return None

def with_db_cursor(func):
    """
    Decorator para gerenciar automaticamente conexões e cursores de banco de dados
    para rotas de API (leitura) que retornam JSON.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        conn = None
        cursor = None
        try:
            conn = get_db_connection()
            if not conn:
                app.logger.error(f"Falha de conexão em {func.__name__}")
                return jsonify(erro="Falha de conexão com o banco de dados."), 503
            
            cursor = conn.cursor(dictionary=True)
            
            return func(*args, cursor=cursor, **kwargs)
            
        except mysql.connector.Error as err:
            app.logger.error(f"Erro de DB em {func.__name__}: {err}")
            # Não precisa de rollback() pois é para rotas GET (leitura)
            return jsonify(erro="Erro interno no banco de dados."), 500
        except Exception as e:
            app.logger.error(f"Erro inesperado em {func.__name__}: {e}")
            return jsonify(erro="Erro interno inesperado no servidor."), 500
        finally:
            if cursor:
                cursor.close()
            if conn and conn.is_connected():
                conn.close()
    return wrapper

# --- Função para formatar um dicionário para JSON (datas e números) ---
def formatar_para_json(dicionario):
    """Converte objetos date/datetime para strings e Decimal para float/int."""
    if dicionario is None:
        return None
    
    for key, value in dicionario.items():
        # Tratamento de datas (como você já fazia)
        if isinstance(value, (datetime, date)):
            dicionario[key] = value.isoformat()
        # NOVO: Tratamento de números decimais
        elif isinstance(value, Decimal):
            # Converte Decimal para float
            float_value = float(value)
            # Se o número for inteiro (ex: 1.0000), converte para int (1)
            if float_value.is_integer():
                dicionario[key] = int(float_value)
            # Senão, mantém como float (ex: 123.45)
            else:
                dicionario[key] = float_value
                
    return dicionario


# --- Função para gerar slugs únicos ---
def generate_unique_slug(conn, base_slug, table='posts'):
    cursor = conn.cursor()
    slug = base_slug
    counter = 1
    while True:
        cursor.execute(f"SELECT COUNT(*) FROM {table} WHERE slug = %s", (slug,))
        if cursor.fetchone()[0] == 0:
            break
        slug = f"{base_slug}-{counter}"
        counter += 1
    cursor.close()
    return slug


@limiter.request_filter
def is_exempt():
    # Lista de IPs que não devem ter limite aplicado
    exempt_ips = ["adicionaroutros ips aqui se quiser", "127.0.0.1", "45.167.53.69"] 
    return get_remote_address() in exempt_ips

# --- Filtro personalizado nl2br para quebra de linha ---
def nl2br_filter(value):
    if value is None:
        return ''
    # Escapa o HTML para segurança, substitui \n por <br>\n, e marca como Markup seguro
    return Markup(str(escape(value)).replace('\n', '<br>\n'))

app.jinja_env.filters['nl2br'] = nl2br_filter  # Registra o filtro


#   CONFIGURAÇÃO DO USUÁRIO PARA FLASK-LOGIN
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

@login_manager.user_loader
def load_user(user_id):
    """Carrega um usuário do banco de dados com base no ID da sessão."""
    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            return None
        
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM usuarios WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()
        
        if user_data:
            return User(id=user_data['id'], username=user_data['username'], password_hash=user_data['password_hash'])
        return None
    except mysql.connector.Error as err:
        app.logger.error(f"Erro ao carregar usuário: {err}")
        return None
    finally:
        if conn and conn.is_connected():
            if 'cursor' in locals():
                cursor.close()
            conn.close()


# =========================================================================
# ROTAS DE AUTENTICAÇÃO E ADMINISTRAÇÃO de USUÁRIOS
# =========================================================================
@app.route('/login', methods=['GET', 'POST'])   # Mudar para Login admin essa rota
@limiter.limit("10 per minute") # Limite específico para esta rota (previne força bruta)
def login():
    if current_user.is_authenticated:
        return redirect(url_for('admin.index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = get_db_connection()
        if not conn:
            flash("Erro de conexão com o banco de dados.", "danger")
            return render_template('login.html', page_title="Login")

        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM usuarios WHERE username = %s", (username,))
        user_data = cursor.fetchone()
        cursor.close()
        conn.close()

        if user_data and bcrypt.check_password_hash(user_data['password_hash'], password):
            user = User(id=user_data['id'], username=user_data['username'], password_hash=user_data['password_hash'])
            login_user(user)
            return redirect(url_for('admin.index'))
        else:
            flash('Login inválido.', 'danger')
    
    # Lembre-se de mover seu login.html para templates/admin/
    return render_template('login.html', page_title="Login")

@app.route('/logout')
def logout():
    logout_user()
    flash('Você foi desconectado.', 'info')
    return redirect(url_for('login'))

# =========================================================================
# Tratamento de erros agora retorna JSON para a API
@app.errorhandler(404)
def pagina_nao_encontrada(e):
    # 1. Rotas da API → sempre retornam JSON
    if request.path.startswith('/api/'):
        return jsonify({"erro": "Recurso não encontrado","status_code": 404}), 404

    # 2. Rotas do Admin → renderizam o template de admin com a variável necessária
    if request.path.startswith('/admin'):
        return render_template('admin/404.html', admin_view=admin.index_view, admin_base_template=admin.base_template), 404

    # 3. Outras rotas (/, /.env, etc.) → retornam JSON para evitar spam de bots
    return jsonify({"erro": "Página não encontrada", "status_code": 404}), 404

@app.errorhandler(500)
def erro_interno_servidor(e):
    logging.error(f"Erro 500: {e} na URL: {request.url}")
    # Para a API, sempre retorne JSON
    if request.path.startswith('/api/'):
        return jsonify(erro="Erro interno no servidor"), 500
    # Para o /admin
    return render_template('admin/500.html'), 500

# --- Rota para Processar o Formulário de Contato ---
@app.route('/api/contato', methods=['POST'])
@limiter.limit("5 per hour") 
def api_processar_contato():
    # --- BLOCO DE DEPURAÇÃO ---
    app.logger.info(f"--- DEPURAÇÃO ROTA /api/contato (MAILGUN) ---")
    data = request.json
    logging.info(f"API Contato: Dados recebidos: {data}")

    # --- VALIDAÇÃO (PYDANTIC) ---
    try:
        contato_data = ContatoSchema(**data)
        nome = contato_data.nome_contato
        email_usuario = contato_data.email_usuario 
        assunto = contato_data.assunto_contato
        mensagem = contato_data.mensagem_contato
        origem = contato_data.origem # <--- Captura a origem (web ou mobile)
    except ValidationError as e:
        app.logger.warning(f"API Contato: Falha de validação. Erro: {e.errors()}")
        return jsonify({'status': 'erro', 'mensagem': 'Dados inválidos.', 'detalhes': e.errors()}), 400

    # --- CONFIGURAÇÃO MAILGUN ---
    mailgun_domain = os.getenv('MAILGUN_DOMAIN')
    mailgun_api_key = os.getenv('MAILGUN_API_KEY')
    email_remetente = os.getenv('EMAIL_REMETENTE')
    email_destinatario = os.getenv('EMAIL_DESTINATARIO_FEEDBACK')

    # Verifica se as variáveis existem
    if not all([mailgun_domain, mailgun_api_key, email_remetente, email_destinatario]):
        logging.error("API Contato: Variáveis de ambiente do Mailgun não configuradas corretamente.")
        return jsonify({'status': 'erro', 'mensagem': 'Erro técnico no servidor (configuração de e-mail).'}), 500

    # Monta a URL da API do Mailgun
    request_url = f"https://api.mailgun.net/v3/{mailgun_domain}/messages"

    # Corpo do e-mail
    texto_email = f"Origem: {origem.upper()}\nNome: {nome}\nE-mail do Usuário: {email_usuario}\nAssunto Original: {assunto}\n\nMensagem:\n{mensagem}"
    
    try:
        # --- ENVIO VIA REQUESTS (API) ---
        response = requests.post(
            request_url,
            auth=("api", mailgun_api_key),
            data={
                "from": f"Finnd Licitações <{email_remetente}>",
                "to": [email_destinatario],
                "subject": f"Novo email - Finnd: {assunto}",
                "text": texto_email,
                "h:Reply-To": email_usuario  # Permite que você clique em "Responder" e vá para o usuário
            }
        )

        # Verifica se o Mailgun aceitou (Status 200 OK)
        if response.status_code == 200:
            app.logger.info(f"E-mail enviado com sucesso. ID: {response.json().get('id')}")
            return jsonify({'status': 'sucesso', 'mensagem': 'Mensagem enviada com sucesso!'}), 200
        else:
            # Se o Mailgun recusar, loga o motivo
            app.logger.error(f"Erro Mailgun: Status {response.status_code} - {response.text}")
            return jsonify({'status': 'erro', 'mensagem': 'Não foi possível enviar a mensagem. Tente novamente mais tarde.'}), 500

    except Exception as e:
        logging.error(f"API Contato: Exceção ao conectar com Mailgun: {e}")
        return jsonify({'status': 'erro', 'mensagem': 'Erro interno ao processar envio.'}), 500

 
# ===========================================---- ROTAS BACKEND (API Principal) ----============================================ #
def _build_licitacoes_query(filtros):
    """
    Constrói a cláusula WHERE para MariaDB, com busca case-insensitive.
    """
    condicoes_db = []
    parametros_db = []
    status_radar = filtros.get('statusRadar')
    match_string = "" 

    # --- 🔧 NORMALIZAÇÃO GERAL ---
    def normalize_field(value):
        """
        Garante que qualquer campo venha como lista de strings limpas.
        Aceita strings únicas, listas ou None.
        """
        if isinstance(value, list):
            return [str(v).strip() for v in value if str(v).strip()]
        elif isinstance(value, str) and value.strip():
            return [value.strip()]
        return []

    # Normaliza todos os campos que podem ser múltiplos
    filtros['ufs'] = normalize_field(filtros.get('ufs'))
    filtros['modalidadesId'] = normalize_field(filtros.get('modalidadesId'))
    filtros['municipiosNome'] = normalize_field(filtros.get('municipiosNome'))
    filtros['palavrasChave'] = normalize_field(filtros.get('palavrasChave'))
    filtros['excluirPalavra'] = normalize_field(filtros.get('excluirPalavra'))
    # FIM DA NORMALIZAÇÃO

    # --- Filtros normais (status, datas, etc.) ---
    if status_radar and status_radar.upper() != 'TODOS':
        condicoes_db.append("situacaoReal = %s")
        parametros_db.append(status_radar)
    elif filtros.get('statusId') is not None:
        condicoes_db.append("situacaoCompraId = %s")
        parametros_db.append(filtros['statusId'])

    # --- UF ---
    if filtros['ufs']:
        placeholders = ', '.join(['%s'] * len(filtros['ufs']))
        condicoes_db.append(f"unidadeOrgaoUfSigla IN ({placeholders})")
        parametros_db.extend([uf.upper() for uf in filtros['ufs']])

    # --- Modalidades ---
    if filtros['modalidadesId']:
        placeholders = ', '.join(['%s'] * len(filtros['modalidadesId']))
        condicoes_db.append(f"modalidadeId IN ({placeholders})")
        parametros_db.extend(filtros['modalidadesId'])

    if filtros.get('dataPubInicio'):
        condicoes_db.append("dataPublicacaoPncp >= %s")
        parametros_db.append(filtros['dataPubInicio'])
    if filtros.get('dataPubFim'):
        condicoes_db.append("dataPublicacaoPncp <= %s")
        parametros_db.append(filtros['dataPubFim'])

    if filtros.get('valorMin') is not None:
        condicoes_db.append("valorTotalEstimado >= %s")
        parametros_db.append(filtros['valorMin'])
    if filtros.get('valorMax') is not None:
        condicoes_db.append("valorTotalEstimado <= %s")
        parametros_db.append(filtros['valorMax'])

    if filtros.get('dataAtualizacaoInicio'):
        condicoes_db.append("dataAtualizacao >= %s")
        parametros_db.append(filtros['dataAtualizacaoInicio'])
    if filtros.get('dataAtualizacaoFim'):
        condicoes_db.append("dataAtualizacao <= %s")
        parametros_db.append(filtros['dataAtualizacaoFim'])

    # --- Municípios ---
    if filtros['municipiosNome']:
        placeholders = ', '.join(['%s'] * len(filtros['municipiosNome']))
        condicoes_db.append(f"unidadeOrgaoMunicipioNome IN ({placeholders})")
        parametros_db.extend(filtros['municipiosNome'])

    if filtros.get('anoCompra') is not None:
        condicoes_db.append("anoCompra = %s")
        parametros_db.append(filtros['anoCompra'])
    if filtros.get('cnpjOrgao'):
        condicoes_db.append("orgaoEntidadeCnpj = %s")
        parametros_db.append(filtros['cnpjOrgao'])

    
    # --- Filtros de Texto com FULLTEXT SEARCH (Lógica OU e Exclusão) ---
    search_terms = []

     # 🔍 Inclusão
    palavras_chave = filtros.get('palavrasChave', [])
    if palavras_chave:
        for valor in palavras_chave:
            termos = shlex.split(valor)
            search_terms.extend([
                f'"{t}"' if ' ' in t else t for t in termos
            ])

    # 🔍 Exclusão
    excluir_palavras = filtros.get('excluirPalavra', [])
    if excluir_palavras:
        for valor in excluir_palavras:
            termos = shlex.split(valor)
            for t in termos:
                # 1. Limpa qualquer '-' que o cliente tenha enviado
                clean_t = t.lstrip('-') 
                
                # 2. Adiciona o '-' de volta, com aspas se for frase
                if ' ' in clean_t:
                    search_terms.append(f'-"{clean_t}"')
                else:
                    search_terms.append(f'-{clean_t}')


    app.logger.info(f"Termos de busca processados: {search_terms}")
    app.logger.info(f"Filtros aplicados: {filtros}")    

    # Se houver qualquer termo de busca (inclusão ou exclusão), montamos a query
    if search_terms:
        # --- SANITIZAÇÃO DE CARACTERES ---
        # Regex de caracteres NÃO permitidos.
        # Remove tudo que NÃO for:
        #   0-9a-zA-Zá-úÁ-ÚçÇ (letras, números, acentos)
        #   \-+ (operadores FTS)
        #   espaço ( )
        #   @\./_ (separadores comuns)
        #   " (para frases exatas)        
        invalid_chars_regex = r'[^0-9a-zA-Zá-úÁ-ÚçÇ\-\+"*@\./_ ]' # Permitido '*' para buscas de prefixo
        sanitized_terms = [re.sub(invalid_chars_regex, '', term) for term in search_terms]
        match_string = ' '.join(filter(None, sanitized_terms))
        
        if match_string:
            # LOG MOVIDO PARA CÁ: Só loga se houver algo para logar
            app.logger.info(f"FTS Query: MATCH() AGAINST ('{match_string}' IN BOOLEAN MODE)")
            
            campos_fts = "objetoCompra, orgaoEntidadeRazaoSocial, unidadeOrgaoNome, orgaoEntidadeCnpj"
            condicoes_db.append(f"MATCH({campos_fts}) AGAINST (%s IN BOOLEAN MODE)")
            parametros_db.append(match_string)

    query_where = ""
    if condicoes_db:
        query_where = " WHERE " + " AND ".join(condicoes_db)

    """
    # lOG DE DEBUG DA QUERY CONSTRUÍDA (Saber qual foi a URL e os parâmetros)
    app.logger.info(f"Query Construída: WHERE = '{query_where}'")
    app.logger.info(f"Parâmetros da Query: {parametros_db}")
    app.logger.info(f"Filtros finais aplicados: {filtros}")
    app.logger.info(f"Palavras de busca finais: {search_terms}")
    app.logger.info(f"String de busca final: '{match_string}'")
    app.logger.info(f"Modalidades ID finais: {filtros['modalidadesId']}")
    app.logger.info(f"UFs finais: {filtros['ufs']}")
    app.logger.info(f"Municípios finais: {filtros['municipiosNome']}")
    """
    
    return query_where, parametros_db

@app.route('/api/licitacoes', methods=['GET'])
@cache.cached(timeout=10800, query_string=True)   # Cacheia a resposta por 3 horas, considerando os parâmetros da query string. Mudar depois para "timeout=900" quando tiver muitos usuários
def get_licitacoes():
    # 1. Coleta e valida os parâmetros de paginação/ordenação
    pagina = request.args.get('pagina', default=1, type=int)
    por_pagina = request.args.get('porPagina', default=20, type=int)
    orderBy_param = request.args.get('orderBy', default='dataAtualizacao', type=str)
    orderDir_param = request.args.get('orderDir', default='DESC', type=str).upper()

    if pagina < 1:
        pagina = 1
    if por_pagina not in [10, 20, 50, 100]:
        por_pagina = 20

    campos_validos_ordenacao = [
        'dataPublicacaoPncp', 'dataAtualizacao', 'valorTotalEstimado',
        'dataAberturaProposta', 'dataEncerramentoProposta', 'modalidadeNome',
        'orgaoEntidadeRazaoSocial', 'unidadeOrgaoMunicipioNome', 'situacaoReal'
    ]
    if orderBy_param not in campos_validos_ordenacao:
        return jsonify({"erro": "Parâmetro de ordenação inválido."}), 400
    if orderDir_param not in ['ASC', 'DESC']:
        return jsonify({"erro": "Parâmetro de direção de ordenação inválido."}), 400

    # 2. Coleta todos os filtros em um único dicionário
    # Função auxiliar para limpar e dividir a string
    def parse_lista_param(param_name):
        value = request.args.get(param_name, '')
        # Primeiro, divide pela vírgula. Depois, remove espaços de cada item.
        # E por fim, filtra quaisquer itens que ficaram vazios.
        return [item.strip() for item in value.split(',') if item.strip()]

    filtros = {
        'ufs': parse_lista_param('uf'),
        'modalidadesId': [int(item) for item in parse_lista_param('modalidadeId') if item.isdigit()],
        'municipiosNome': parse_lista_param('municipioNome'),
        'palavrasChave': parse_lista_param('palavraChave'),
        'excluirPalavra': parse_lista_param('excluirPalavra'),
        'statusRadar': request.args.get('statusRadar'),
        'dataPubInicio': request.args.get('dataPubInicio'),
        'dataPubFim': request.args.get('dataPubFim'),
        'valorMin': request.args.get('valorMin', type=float),
        'valorMax': request.args.get('valorMax', type=float),
        'dataAtualizacaoInicio': request.args.get('dataAtualizacaoInicio'),
        'dataAtualizacaoFim': request.args.get('dataAtualizacaoFim'),
        'anoCompra': request.args.get('anoCompra', type=int),
        'cnpjOrgao': request.args.get('cnpjOrgao'),
        'statusId': request.args.get('statusId', type=int),
    }
    # Limpa filtros vazios ou nulos
    filtros = {k: v for k, v in filtros.items() if v is not None and v != '' and v != []}

    # 3. Monta a cláusula WHERE e os parâmetros usando a função centralizada
    query_where, parametros_db = _build_licitacoes_query(filtros)

    # 4. Monta as queries de contagem e de dados
    query_contagem = f"SELECT COUNT(*) as total FROM licitacoes {query_where}"
    
    query_select_dados = f"""
        SELECT * FROM licitacoes
        {query_where}
        ORDER BY {orderBy_param} {orderDir_param}
        LIMIT %s OFFSET %s
    """
    
    conn = get_db_connection()
    if not conn:
        return jsonify({"erro": "Falha na conexão com o banco de dados."}), 503

    licitacoes_lista = []
    total_registros = 0
    try:
        # Cria cursores que retornam dicionários
        cursor_dados = conn.cursor(dictionary=True)
        cursor_contagem = conn.cursor(dictionary=True)

        # Definimos o nível de isolamento como READ COMMITTED para esta sessão.
        # Isso reduz a chance de a leitura bloquear o script de escrita (sync_api.py).
        cursor_contagem.execute("SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED")
        
        # Executa a query de contagem total
        cursor_contagem.execute(query_contagem, parametros_db)
        resultado_contagem = cursor_contagem.fetchone()
        if resultado_contagem:
            total_registros = resultado_contagem['total']

        # Executa a query de dados com paginação
        parametros_dados_sql = parametros_db + [por_pagina, (pagina - 1) * por_pagina]
        cursor_dados.execute(query_select_dados, parametros_dados_sql)
        licitacoes_lista_bruta = cursor_dados.fetchall()
        
        licitacoes_lista = [formatar_para_json(row) for row in licitacoes_lista_bruta]



    except mysql.connector.Error as err:
        app.logger.error(f"Erro de SQL em get_licitacoes: {err}")
        return jsonify({"erro": "Erro interno ao processar sua busca.", "detalhes": str(err)}), 500
    finally:
        if conn and conn.is_connected():    # Verifica se a conexão e o cursor estão abertos, se tiverem então fecha
            if 'cursor_dados' in locals():
                cursor_dados.close()
            if 'cursor_contagem' in locals():
                cursor_contagem.close()
            conn.close()

    total_paginas = (total_registros + por_pagina - 1) // por_pagina if por_pagina > 0 else 0

    return jsonify({
        "pagina_atual": pagina,
        "por_pagina": por_pagina,
        "total_registros": total_registros,
        "total_paginas": total_paginas,
        "origem_dados": "banco_local_com_filtro_sql",
        "licitacoes": licitacoes_lista
    })    

@app.route('/api/licitacao/<path:numero_controle_pncp>', methods=['GET'])
@with_db_cursor
def get_detalhe_licitacao(numero_controle_pncp, cursor):
    query_licitacao_principal = "SELECT * FROM licitacoes WHERE numeroControlePNCP = %s"
    cursor.execute(query_licitacao_principal, (numero_controle_pncp,))
    licitacao_principal_row = cursor.fetchone()

    if not licitacao_principal_row:
        return jsonify({"erro": "Licitação não encontrada", "numeroControlePNCP": numero_controle_pncp}), 404

    licitacao_principal_dict = formatar_para_json(licitacao_principal_row)
    licitacao_id_local = licitacao_principal_dict['id']

    query_itens = "SELECT * FROM itens_licitacao WHERE licitacao_id = %s"
    cursor.execute(query_itens, (licitacao_id_local,))
    itens_rows = cursor.fetchall()
    itens_lista = [formatar_para_json(row) for row in itens_rows]

    query_arquivos = "SELECT * FROM arquivos_licitacao WHERE licitacao_id = %s"
    cursor.execute(query_arquivos, (licitacao_id_local,))
    arquivos_rows = cursor.fetchall()
    arquivos_lista = [formatar_para_json(row) for row in arquivos_rows]

    resposta_final = {
        "licitacao": licitacao_principal_dict,
        "itens": itens_lista,
        "arquivos": arquivos_lista
    }
    return jsonify(resposta_final)

@app.route('/api/referencias/modalidades', methods=['GET'])
@with_db_cursor
def get_modalidades_referencia(cursor):
    cursor.execute("SELECT DISTINCT modalidadeId, modalidadeNome FROM licitacoes ORDER BY modalidadeNome")
    modalidades = [dict(row) for row in cursor.fetchall()]
    return jsonify(modalidades)

@app.route('/api/referencias/statuscompra', methods=['GET'])
@with_db_cursor
def get_statuscompra_referencia(cursor):
    cursor.execute("SELECT DISTINCT situacaoCompraId, situacaoCompraNome FROM licitacoes ORDER BY situacaoCompraNome")
    status_compra = [dict(row) for row in cursor.fetchall()]
    return jsonify(status_compra)

@app.route('/api/referencias/statusradar', methods=['GET'])
@with_db_cursor
def get_statusradar_referencia(cursor):
    cursor.execute("SELECT DISTINCT situacaoReal FROM licitacoes WHERE situacaoReal IS NOT NULL ORDER BY situacaoReal")
    status_radar_rows = cursor.fetchall()
    status_radar = [{"id": row['situacaoReal'], "nome": row['situacaoReal']} for row in status_radar_rows]
    return jsonify(status_radar)

# --- Rota API IBGE (mantida do frontend) ---
@app.route('/api/ibge/municipios/<uf_sigla>', methods=['GET'])
def api_get_municipios_ibge(uf_sigla):
    if not uf_sigla or len(uf_sigla) != 2 or not uf_sigla.isalpha():
        return jsonify({"erro": "Sigla da UF inválida."}), 400
    
    ibge_api_url = f"https://servicodados.ibge.gov.br/api/v1/localidades/estados/{uf_sigla.upper()}/municipios"
    try:
        response = requests.get(ibge_api_url)
        response.raise_for_status()
        municipios = [{"id": m["id"], "nome": m["nome"]} for m in response.json()]
        return jsonify(municipios)
    except requests.exceptions.HTTPError as http_err:
        return jsonify({"erro": f"Erro ao buscar municípios no IBGE: {http_err}", "status_code": http_err.response.status_code}), http_err.response.status_code
    except requests.exceptions.RequestException as e:
        return jsonify({"erro": f"Erro de conexão com API do IBGE: {e}", "status_code": 503}), 503
    except ValueError:
        return jsonify({"erro": "Resposta inválida (JSON) da API do IBGE.", "status_code": 500}), 500


# EXPORTAR CSV - Mantendo separado de def get_licitacoes() sem refatorar posso enviar mais coisas ou menos. 
@app.route('/api/exportar-csv')
def exportar_csv():
    # 1. Coleta todos os filtros da URL em um único dicionário
    filtros = {
        'ufs': request.args.getlist('uf'),
        'modalidadesId': request.args.getlist('modalidadeId', type=int),
        'statusRadar': request.args.get('statusRadar'),
        'dataPubInicio': request.args.get('dataPubInicio'),
        'dataPubFim': request.args.get('dataPubFim'),
        'valorMin': request.args.get('valorMin', type=float),
        'valorMax': request.args.get('valorMax', type=float),
        'municipiosNome': request.args.getlist('municipioNome'),
        'dataAtualizacaoInicio': request.args.get('dataAtualizacaoInicio'),
        'dataAtualizacaoFim': request.args.get('dataAtualizacaoFim'),
        'anoCompra': request.args.get('anoCompra', type=int),
        'cnpjOrgao': request.args.get('cnpjOrgao'),
        'statusId': request.args.get('statusId', type=int),
        'palavrasChave': request.args.getlist('palavraChave'),
        'excluirPalavras': request.args.getlist('excluirPalavra')
    }
    # Limpa filtros que não foram preenchidos
    filtros = {k: v for k, v in filtros.items() if v is not None and v != '' and v != []}
    
    # Coleta parâmetros de ordenação
    orderBy_param = request.args.get('orderBy', default='dataPublicacaoPncp')
    orderDir_param = request.args.get('orderDir', default='DESC').upper()

    # --- INÍCIO DA CORREÇÃO DE SEGURANÇA ---
    # Reutilize a MESMA whitelist da sua rota get_licitacoes
    campos_validos_ordenacao = [
        'dataPublicacaoPncp', 'dataAtualizacao', 'valorTotalEstimado',
        'dataAberturaProposta', 'dataEncerramentoProposta', 'modalidadeNome',
        'orgaoEntidadeRazaoSocial', 'unidadeOrgaoMunicipioNome', 'situacaoReal'
    ]
    if orderBy_param not in campos_validos_ordenacao:
        app.logger.warning(f"Export CSV: Tentativa de ordenação inválida por '{orderBy_param}'")
        # Retorna um erro em vez de continuar
        return jsonify({"erro": "Parâmetro de ordenação inválido."}), 400
        
    if orderDir_param not in ['ASC', 'DESC']:
        app.logger.warning(f"Export CSV: Tentativa de direção de ordenação inválida '{orderDir_param}'")
        return jsonify({"erro": "Parâmetro de direção de ordenação inválido."}), 400

    # 2. Usa a função central para construir a cláusula WHERE e os parâmetros
    query_where_sql, parametros_db_sql = _build_licitacoes_query(filtros)
    
    # 3. Monta a query final de seleção (sem paginação para exportar tudo)
    query_select_dados = f"SELECT * FROM licitacoes {query_where_sql} ORDER BY {orderBy_param} {orderDir_param}"
    
    conn = get_db_connection()
    licitacoes_filtradas = []
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query_select_dados, parametros_db_sql)
        # O resultado do banco já está completamente filtrado
        licitacoes_filtradas = cursor.fetchall()
    except mysql.connector.Error as e:
        app.logger.error(f"Erro ao buscar dados para exportar CSV: {e}")
        return jsonify({"erro": "Erro ao buscar dados para exportação"}), 500
    finally:
        if conn and conn.is_connected():
            if 'cursor' in locals():
                cursor.close()
            conn.close()

    # 4. Geração do CSV em memória
    output = io.StringIO()
    writer = csv.writer(output, delimiter=';', lineterminator='\n', quoting=csv.QUOTE_ALL)
    
    # Cabeçalho do CSV
    writer.writerow(['Data Atualizacao', 'Municipio/UF', 'Orgao', 'Modalidade', 'Status', 'Valor Estimado (R$)', 'Objeto da Compra', 'Link PNCP'])

    # Escreve as linhas de dados
    for lic in licitacoes_filtradas:
        municipio_uf = f"{lic.get('unidadeOrgaoMunicipioNome', '')}/{lic.get('unidadeOrgaoUfSigla', '')}"
        
        valor_str = 'N/I'
        if lic.get('valorTotalEstimado') is not None:
            # Formata o valor como moeda brasileira
            valor_str = f"{lic['valorTotalEstimado']:.2f}".replace('.', ',')
            
        writer.writerow([
            lic.get('dataAtualizacao', ''),
            municipio_uf,
            lic.get('orgaoEntidadeRazaoSocial', ''),
            lic.get('modalidadeNome', ''),
            lic.get('situacaoReal', ''),
            valor_str,
            lic.get('objetoCompra', ''),
            lic.get('link_portal_pncp', '')
        ])

    # 5. Prepara a resposta HTTP para o download do arquivo
    output.seek(0)
    return Response(
        output.getvalue().encode('utf-8-sig'), # utf-8-sig para compatibilidade com Excel
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=radar_pncp_licitacoes.csv"}
    )

# ===============================================================
# =================== Rotas para posts do blog ==================
# ===============================================================
@app.route('/api/posts', methods=['GET'])
@with_db_cursor
def get_all_posts(cursor):
    # --- 1. Captura de todos os parâmetros --- (mantida igual)
    categoria_slug = request.args.get('categoria')
    tag_nome = request.args.get('tag')
    query_busca = request.args.get('q')
    page = request.args.get('page', 1, type=int)
    per_page = 9
    offset = (page - 1) * per_page

    # --- 2. Monta as partes da query (JOINs e WHEREs) primeiro --- (mantida igual)
    joins = " LEFT JOIN categorias c ON p.categoria_id = c.id"
    where_clauses = []
    params = []

    if tag_nome:
        joins += " JOIN posts_tags pt ON p.id = pt.post_id JOIN tags t ON pt.tag_id = t.id"
        where_clauses.append("t.nome = %s")
        params.append(tag_nome)

    if categoria_slug:
        where_clauses.append("c.slug = %s")
        params.append(categoria_slug)

    if query_busca:
        where_clauses.append("(p.titulo LIKE %s OR p.resumo LIKE %s OR p.conteudo_completo LIKE %s)")
        search_term = f"%{query_busca}%"
        params.extend([search_term, search_term, search_term])
    
    where_sql = ""
    if where_clauses:
        where_sql = " WHERE " + " AND ".join(where_clauses)

    # --- 3. Executa a Query de Contagem (agora correta) --- (mantida igual)
    count_query = f"SELECT COUNT(DISTINCT p.id) as total FROM posts p{joins}{where_sql}"
    cursor.execute(count_query, params)
    total_posts = cursor.fetchone()['total']
    total_pages = (total_posts + per_page - 1) // per_page if total_posts > 0 else 0

    # --- 4. Executa a Query para buscar os dados da página --- (mantida igual)
    query_data = f"""
        SELECT p.id, p.titulo, p.slug, p.resumo, p.data_publicacao, p.imagem_destaque,
               c.nome AS categoria_nome, c.slug AS categoria_slug
        FROM posts p
        {joins}
        {where_sql}
        ORDER BY p.data_publicacao DESC
        LIMIT %s OFFSET %s
    """
    params_paginados = params + [per_page, offset]
    cursor.execute(query_data, params_paginados)
    posts = cursor.fetchall()
    
    posts_formatados = [formatar_para_json(p) for p in posts]
    
    # --- 5. Retorna o JSON com os dados da paginação --- (mantida igual)
    return jsonify(
        posts=posts_formatados,
        pagina_atual=page,
        total_paginas=total_pages
    )

@app.route('/api/post/<string:post_slug>', methods=['GET'])
@with_db_cursor
def get_single_post(post_slug, cursor):
    # Adicionamos o LEFT JOIN com a tabela 'categorias' para já pegar os dados da categoria.
    query_post = """
        SELECT 
            p.id, p.titulo, p.conteudo_completo, p.data_publicacao,
            c.nome AS categoria_nome, 
            c.slug AS categoria_slug
        FROM posts p
        LEFT JOIN categorias c ON p.categoria_id = c.id
        WHERE p.slug = %s
    """
    cursor.execute(query_post, (post_slug,))
    post = cursor.fetchone()
  
    if not post:
        return jsonify(erro="Post não encontrado"), 404

    # Usamos o ID do post que acabamos de encontrar para buscar suas tags.
    post_id = post['id']
    query_tags = """
        SELECT t.nome
        FROM tags t
        JOIN posts_tags pt ON t.id = pt.tag_id
        WHERE pt.post_id = %s
    """
    cursor.execute(query_tags, (post_id,))
    tags_result = cursor.fetchall()
    
    # Extrai apenas os nomes das tags para uma lista simples
    tags = [tag['nome'] for tag in tags_result]

    # Formata as datas e adiciona as tags ao resultado final
    post_formatado = formatar_para_json(post)
    post_formatado['tags'] = tags # Adiciona a lista de tags ao dicionário do post

    return jsonify(post=post_formatado)

@app.route('/api/posts/destaques', methods=['GET'])
@with_db_cursor
def get_featured_posts(cursor):
    # ### ALTERAÇÃO NA QUERY: Adicionado "WHERE is_featured = TRUE" e "LIMIT 3" ### (mantida igual)
    cursor.execute("""
        SELECT titulo, slug, resumo, data_publicacao, imagem_destaque 
        FROM posts 
        WHERE is_featured = TRUE 
        ORDER BY data_publicacao DESC 
        LIMIT 3
    """)
    posts = cursor.fetchall()

    posts_formatados = [formatar_para_json(p) for p in posts]
    return jsonify(posts=posts_formatados)


# =========================================================================
# ========= CONFIGURAÇÃO DO FLASK-ADMIN -- BACKEND ADMINISTRATIVO =========
# =========================================================================
# View principal do admin que verifica se o usuário está logado - HOME DO ADMIN
class MyAdminIndexView(AdminIndexView):
    @expose('/')
    def index(self):
        if not current_user.is_authenticated:
            return redirect(url_for('login'))
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        # Estatísticas
        cursor.execute("SELECT COUNT(*) as total FROM posts")
        total_posts = cursor.fetchone()['total']        
        cursor.execute("SELECT COUNT(*) as total FROM categorias")
        total_categorias = cursor.fetchone()['total']        
        cursor.execute("SELECT COUNT(*) as total FROM tags")
        total_tags = cursor.fetchone()['total']        
        cursor.execute("SELECT * FROM posts ORDER BY data_publicacao DESC LIMIT 5")
        posts_recentes = cursor.fetchall()
        
        cursor.close()
        conn.close()        
        stats = {
            'total_posts': total_posts,
            'total_categorias': total_categorias,
            'total_tags': total_tags,
        }
        
        return self.render('admin/index.html', stats=stats, posts_recentes=posts_recentes)
    
    def is_accessible(self):
        # Acessível apenas se o usuário estiver logado e autenticado
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        # Se não estiver logado, redireciona para a página de login
        flash("Você precisa estar logado para acessar a área administrativa.", "warning")
        return redirect(url_for('login', next=request.url))

class PostsView(BaseView):
    def is_accessible(self):
        # Acessível apenas se o usuário estiver logado
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        # Redireciona para o login se não estiver autenticado
        return redirect(url_for('login'))

    # Rota para a lista de posts
    @expose('/')
    def list_posts(self):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # --- LÓGICA DE PAGINAÇÃO ---
        page = request.args.get('page', 1, type=int) # Pega o nº da página da URL, padrão é 1
        per_page = 15 # Define quantos posts por página
        offset = (page - 1) * per_page # Calcula o deslocamento

        # Query para contar o total de posts (para saber quantas páginas teremos)
        cursor.execute("SELECT COUNT(*) as total FROM posts")
        total_posts = cursor.fetchone()['total']
        total_pages = (total_posts + per_page - 1) // per_page

        # Query principal MODIFICADA com LIMIT e OFFSET
        cursor.execute("""
            SELECT p.id, p.titulo, p.slug, p.data_publicacao, u.username as autor_nome 
            FROM posts p 
            LEFT JOIN usuarios u ON p.autor_id = u.id 
            ORDER BY p.data_publicacao DESC
            LIMIT %s OFFSET %s
        """, (per_page, offset))
        
        posts = cursor.fetchall()
        cursor.close()
        conn.close()
        
        # Passa as variáveis de paginação para o template
        return self.render('admin/posts_list.html', 
                        posts=posts, 
                        page=page, 
                        total_pages=total_pages)

    # Rota para o formulário de adicionar/editar post
    @expose('/edit/', methods=('GET', 'POST'))
    @expose('/edit/<int:post_id>', methods=('GET', 'POST'))
    def edit_post(self, post_id=None):
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        # --- BUSCAR DADOS PARA O FORMULÁRIO (CATEGORIAS E TAGS) ---
        cursor.execute("SELECT id, nome FROM categorias ORDER BY nome")
        todas_categorias = cursor.fetchall()
        
        cursor.execute("SELECT id, nome FROM tags ORDER BY nome")
        todas_tags = cursor.fetchall()

        post_para_formulario = {}
        tags_atuais_do_post = [] # Lista de IDs das tags já selecionadas

        # Se estiver editando, busca os dados do post e suas tags
        if post_id:
            cursor.execute("SELECT * FROM posts WHERE id = %s", (post_id,))
            post_para_formulario = cursor.fetchone()
            if not post_para_formulario:
                flash('Post não encontrado!', 'danger')
                cursor.close()
                conn.close()
                return redirect(url_for('.list_posts'))
            
            cursor.execute("SELECT tag_id FROM posts_tags WHERE post_id = %s", (post_id,))
            tags_atuais_do_post = [row['tag_id'] for row in cursor.fetchall()]
        
        # --- LÓGICA PARA REQUISIÇÃO POST (Quando o formulário é ENVIADO) ---
        if request.method == 'POST':
            # 1. Pega os dados brutos do formulário
            titulo = request.form.get('titulo')
            slug = request.form.get('slug')
            resumo = request.form.get('resumo')
            conteudo_bruto = request.form.get('conteudo_completo')
            imagem_destaque = request.form.get('imagem_destaque')
            is_featured = 'is_featured' in request.form
            categoria_id = request.form.get('categoria_id')
            # O Python None será traduzido para o SQL NULL pelo conector do banco.
            if categoria_id == '':
                categoria_id = None
            
            tags_selecionadas_ids = request.form.getlist('tags')
            
            import re
            slug_limpo = re.sub(r'[^a-z0-9\-]+', '', slug.lower()).strip('-')
            
            # 2. Sanitiza o conteúdo HTML
            conteudo_sanitizado = bleach.clean(conteudo_bruto,tags = [
                "p", "br", "hr", "div", "span",
                "h1", "h2", "h3", "h4", "h5", "h6",
                "strong", "b", "em", "i", "u", "mark", "small", "sup", "sub",
                "ul", "ol", "li", "dl", "dt", "dd",
                "blockquote", "pre", "code",
                "a", "img", "figure", "figcaption",
                "table", "thead", "tbody", "tfoot", "tr", "td", "th",
                "section", "article", "main", "aside", "header", "footer", "nav"
            ], attributes = {   # Atributos permitidos
                'a': ['href', 'title', "target", "rel"],
                'img': ['src', 'alt', 'title',"width", "height", 'style'],
                'div': ['class', 'id', 'style'],
                'span': ['class', 'id', 'style'],
                'section': ['class', 'id'],
                'article': ['class', 'id'],
                'main': ['class', 'id'],
                "table": ["class", "style", "border", "cellpadding", "cellspacing"],
                "td": ["class", "style", "colspan", "rowspan"],
                "th": ["class", "style", "colspan", "rowspan"],
                "*": ["class", "id", "style"]
            })

            try:
                # --- LÓGICA DE UNICIDADE PROATIVA ---
                cursor = conn.cursor(dictionary=True)
                
                # Query para verificar se o slug já existe em OUTRO post
                check_slug_query = "SELECT id FROM posts WHERE slug = %s AND id != %s"
                cursor.execute(check_slug_query, (slug_limpo, post_id if post_id else 0))
                
                slug_final = slug_limpo
                if cursor.fetchone():
                    # Se encontrou, o slug já está em uso. Chame sua função!
                    slug_final = generate_unique_slug(conn, slug_limpo)
                    flash(f"O slug '{slug_limpo}' já estava em uso e foi ajustado para '{slug_final}'.", 'warning')
                
                # --- INSERÇÃO OU ATUALIZAÇÃO DO POST ---
                if post_id:
                    # UPDATE
                    query = """UPDATE posts SET titulo=%s, slug=%s, resumo=%s, conteudo_completo=%s, imagem_destaque=%s, categoria_id=%s, is_featured=%s WHERE id=%s"""
                    cursor.execute(query, (titulo, slug_final, resumo, conteudo_sanitizado, imagem_destaque, categoria_id, is_featured, post_id))
                else:
                    # INSERT (Corrigido o recuo aqui para alinhar com o bloco de cima)
                    query = """INSERT INTO posts (titulo, slug, resumo, conteudo_completo, autor_id, imagem_destaque, categoria_id, is_featured) 
                               VALUES (%s, %s, %s, %s, %s, %s, %s, %s)"""
                    cursor.execute(query, (titulo, slug_final, resumo, conteudo_sanitizado, current_user.id, imagem_destaque, categoria_id, is_featured))
                    post_id = cursor.lastrowid
                
                # Atualiza as tags na tabela de junção
                cursor.execute("DELETE FROM posts_tags WHERE post_id = %s", (post_id,))
                if tags_selecionadas_ids:
                    tags_para_inserir = [(post_id, tag_id) for tag_id in tags_selecionadas_ids]
                    cursor.executemany("INSERT INTO posts_tags (post_id, tag_id) VALUES (%s, %s)", tags_para_inserir)

                conn.commit()
                flash('Post salvo com sucesso!', 'success')
                
                # Fecha tudo e redireciona
                cursor.close()
                conn.close()
                return redirect(url_for('.list_posts'))
            
            except mysql.connector.Error as err:
                conn.rollback()
                if err.errno == 1062:
                    flash(f"Erro: O slug '{slug_limpo}' já existe. Por favor, escolha outro.", 'danger')
                    post_para_formulario = request.form
                else:
                    flash(f"Ocorreu um erro no banco de dados: {err}", "danger")
                    post_para_formulario = request.form
        
        # --- RENDERIZA O FORMULÁRIO (PARA REQUISIÇÃO GET OU APÓS ERRO NO POST) ---
        cursor.close()
        conn.close()
        
        tinymce_key = os.getenv('TINYMCE_API_KEY')
        return self.render('admin/post_form.html', 
                           post=post_para_formulario, 
                           post_id=post_id, 
                           tinymce_key=tinymce_key,
                           todas_categorias=todas_categorias,
                           todas_tags=todas_tags,
                           tags_atuais=tags_atuais_do_post)

    # Rota para deletar um post
    @expose('/delete/<int:post_id>', methods=('POST',))
    def delete_post(self, post_id):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM posts WHERE id = %s", (post_id,))
        conn.commit()
        cursor.close()
        conn.close()
        flash('Post excluído com sucesso!', 'success')
        return redirect(url_for('.list_posts'))

# Inicializa o Flask-Admin
admin = Admin(
    app, 
    name='Painel RADAR PNCP', 
    template_mode='bootstrap4',
    index_view=MyAdminIndexView()
)

# BLOCO DE CÓDIGO 5: VIEW DE ADMINISTRAÇÃO PARA CATEGORIAS E TAGS
class CategoriaView(BaseView):
    def is_accessible(self):
        return current_user.is_authenticated

    @expose('/', methods=('GET', 'POST'))
    def index(self):
        if request.method == 'POST':
            nome = request.form.get('nome')
            slug = request.form.get('slug')
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                cursor.execute("INSERT INTO categorias (nome, slug) VALUES (%s, %s)", (nome, slug))
                conn.commit()
                flash('Categoria criada com sucesso!', 'success')
            except mysql.connector.Error as err:
                flash(f'Erro ao criar categoria: {err}', 'danger')
            finally:
                cursor.close()
                conn.close()
            return redirect(url_for('.index'))

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM categorias ORDER BY nome")
        categorias = cursor.fetchall()
        cursor.close()
        conn.close()
        return self.render('admin/categorias_tags.html', items=categorias, title="Categorias", endpoint_name="categorias")

    @expose('/delete/<int:item_id>', methods=('POST',))
    def delete(self, item_id):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM categorias WHERE id = %s", (item_id,))
        conn.commit()
        cursor.close()
        conn.close()
        flash('Categoria excluída com sucesso.', 'success')
        return redirect(url_for('.index'))

class TagView(BaseView):
    def is_accessible(self):
        return current_user.is_authenticated
    
    # Esta view é quase idêntica à de categorias, mas usa a tabela 'tags'
    @expose('/', methods=('GET', 'POST'))
    def index(self):
        if request.method == 'POST':
            nome = request.form.get('nome')
            # Tags não precisam de slug, apenas nome.
            conn = get_db_connection()
            cursor = conn.cursor()
            try:
                cursor.execute("INSERT INTO tags (nome) VALUES (%s)", (nome,))
                conn.commit()
                flash('Tag criada com sucesso!', 'success')
            except mysql.connector.IntegrityError as err:
                # Erro 1062 = chave duplicada
                if err.errno == 1062:
                    flash(f"A tag '{nome}' já existe. Escolha outro nome.", 'warning')
                else:
                    flash('Erro de integridade no banco de dados.', 'danger')
            except mysql.connector.Error as err:
                # Para qualquer outro erro do MySQL
                flash('Erro inesperado ao criar tag. Tente novamente.', 'danger')
                app.logger.error(f"Erro MySQL ao criar tag: {err}")
            finally:
                cursor.close()
                conn.close()
            return redirect(url_for('.index'))

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM tags ORDER BY nome")
        tags = cursor.fetchall()
        cursor.close()
        conn.close()
        return self.render('admin/categorias_tags.html', items=tags, title="Tags", endpoint_name="tags")

    @expose('/delete/<int:item_id>', methods=('POST',))
    def delete(self, item_id):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM tags WHERE id = %s", (item_id,))
        conn.commit()
        cursor.close()
        conn.close()
        flash('Tag excluída com sucesso.', 'success')
        return redirect(url_for('.index'))
    
# =================== Rotas API para categorias e tags ==================
@app.route('/api/categorias', methods=['GET'])
@with_db_cursor
def get_all_categorias(cursor):
    cursor.execute("SELECT nome, slug FROM categorias ORDER BY nome")
    categorias = cursor.fetchall()
    return jsonify(categorias=categorias)

@app.route('/api/tags', methods=['GET'])
@with_db_cursor
def get_all_tags(cursor):
    cursor.execute("SELECT nome FROM tags ORDER BY nome")
    tags = cursor.fetchall()
    return jsonify(tags=tags)

admin.add_view(PostsView(name='Posts', endpoint='posts'))
admin.add_view(CategoriaView(name='Categorias', endpoint='categorias'))
admin.add_view(TagView(name='Tags', endpoint='tags'))
# =============================================== acaba aqui o Flask-Admin e rotas do admin ======================================================
# ================================================================================================================================================



# =========================================================================
# ======================== ROTAS DE PAGAMENTO (REVENUECAT) ================
# =========================================================================
@app.route('/api/webhooks/revenuecat', methods=['POST'])
@limiter.limit("100 per minute") # Isso na pratica faz com que ataques de força bruta sejam mitigados, pois so permite 300 reqs/min
def revenuecat_webhook():
    """
    Webhook RevenueCat com segurança, idempotência e consistência de estado.
    """
    # 1. AUTENTICAÇÃO
    auth_header = request.headers.get('Authorization', '')
    expected_token = os.getenv('REVENUECAT_WEBHOOK_AUTH', '')

    incoming_token = auth_header.split(' ')[1] if auth_header.startswith('Bearer ') else auth_header
    if not incoming_token or not hmac.compare_digest(incoming_token, expected_token):
        app.logger.warning("SECURITY: Webhook RevenueCat com token inválido")
        return jsonify({"erro": "Não autorizado"}), 401

    data = request.get_json(silent=True) or {}
    event = data.get('event')
    if not event:
        return jsonify({"status": "Ignorado (payload inválido)"}), 200
    # 2. EXTRAÇÃO DE DADOS
    rc_event_id = event.get('id')
    rc_event_type = event.get('type')
    app_user_id = event.get('app_user_id')
    product_id = event.get('product_id')
    entitlement_id = event.get('entitlement_id')

    purchased_at_ms = event.get('purchased_at_ms')
    expiration_at_ms = event.get('expiration_at_ms')

    if not rc_event_id or not app_user_id or not rc_event_type:
        app.logger.warning("Webhook RC incompleto recebido")
        return jsonify({"erro": "Dados obrigatórios ausentes"}), 400

    def ms_to_utc(ms):
        return datetime.fromtimestamp(ms / 1000, tz=timezone.utc) if ms else None

    dt_compra = ms_to_utc(purchased_at_ms)
    dt_expiracao = ms_to_utc(expiration_at_ms)
    # 3. BANCO + IDEMPOTÊNCIA
    conn = get_db_connection()
    if not conn:
        return jsonify({"erro": "Danco de Dados indisponível"}), 500

    try:
        cursor = conn.cursor(dictionary=True)
        # Idempotência forte
        cursor.execute(
            "SELECT id FROM assinaturas_historico WHERE event_id = %s",
            (rc_event_id,)
        )
        if cursor.fetchone():
            app.logger.info(f"RC: Evento {rc_event_id} já processado")
            return jsonify({"status": "Já processado"}), 200
        # 4. GARANTE USUÁRIO
        cursor.execute("""
            INSERT IGNORE INTO usuarios_status (uid_externo, created_at)
            VALUES (%s, NOW())
        """, (app_user_id,))
        cursor.execute("""
            SELECT id FROM usuarios_status WHERE uid_externo = %s
        """, (app_user_id,))
        user = cursor.fetchone()
        user_id = user['id']
        # 5. LÓGICA DE ESTADO
        eventos_ativam = {'INITIAL_PURCHASE', 'RENEWAL', 'UNCANCELLATION', 'NON_RENEWING_PURCHASE', 'PRODUCT_CHANGE'}
        eventos_alerta = {'CANCELLATION', 'BILLING_ISSUE'}
        eventos_expiram = {'EXPIRATION'}

        novo_is_pro = None
        novo_status = None
        if rc_event_type in eventos_ativam:
            novo_is_pro = 1
            novo_status = 'active'
        elif rc_event_type == 'CANCELLATION':
            novo_is_pro = 1
            novo_status = 'canceled'
        elif rc_event_type == 'BILLING_ISSUE':
            novo_is_pro = 1
            novo_status = 'billing_issue'
        elif rc_event_type in eventos_expiram:
            novo_is_pro = 0
            novo_status = 'expired'
        # 6. UPDATE CONSOLIDADO DO USUÁRIO
        if novo_status:
            cursor.execute("""
                UPDATE usuarios_status
                SET
                    is_pro = %s, status_assinatura = %s, data_expiracao_atual = %s, updated_at = NOW()
                WHERE id = %s
            """, (
                novo_is_pro, novo_status, dt_expiracao, user_id
            ))
        # 7. HISTÓRICO (FONTE DA VERDADE)
        cursor.execute("""
            INSERT INTO assinaturas_historico
            (
                usuario_id, uid_externo, evento, produto_id, event_id, entitlement_id, data_compra, data_expiracao, json_original
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            user_id, app_user_id, rc_event_type, product_id, rc_event_id, entitlement_id, dt_compra, dt_expiracao,
            json.dumps(data)
        ))
        conn.commit()

        app.logger.info(
            f"RC OK | event={rc_event_type} | user={app_user_id} | event_id={rc_event_id}"
        )
        return jsonify({"status": "processado"}), 200

    except Exception as e:
        conn.rollback()
        error_msg = str(e)
        stack_trace = traceback.format_exc()
        app.logger.error(f"CRITICAL RC ERROR | event_id={rc_event_id} | {error_msg}")

        # --- ALERTA DE EMERGÊNCIA (MAILGUN) ---
        # Se falhar o processamento, te avisa na hora para você não perder dinheiro/cliente.
        try:
            requests.post(
                f"https://api.mailgun.net/v3/{os.getenv('MAILGUN_DOMAIN')}/messages",
                auth=("api", os.getenv('MAILGUN_API_KEY')),
                data={
                    "from": f"Sistema Finnd <erro@{os.getenv('MAILGUN_DOMAIN')}>",
                    "to": ["laysoftone@gmail.com"], # <--- COLOCAR NO ENV DEPOIS.
                    "subject": f"⚠️ ERRO CRÍTICO: Webhook RevenueCat Falhou!",
                    "text": f"O usuário {app_user_id} fez uma ação {rc_event_type} e o banco falhou.\n\nErro: {error_msg}\n\nTraceback:\n{stack_trace}"
                },
                timeout=5 # Não deixa travar se o mailgun demorar
            )
        except:
            print("Falha ao enviar alerta de email.")
        # ----------------------------------------
        return jsonify({"erro": "Erro interno"}), 500

    finally:
        cursor.close()
        conn.close()

# Função para verificação ativa do status PRO via API RevenueCat
# --- HELPER: TIRA TEIMA REVENUECAT (VERSÃO LEVE - SEM BANCO) ---
def verificar_status_revenuecat_agora(uid):
    """
    Consulta direta à API da RevenueCat.
    Retorna APENAS True/False. Não mexe no banco para evitar Deadlock.
    """
    rc_key = os.getenv('REVENUECAT_API_KEY')
    if not rc_key:
        app.logger.error("REVENUECAT_API_KEY não configurada.")
        return False 

    app.logger.info(f"RC CHECK: Verificando {uid}...")
    
    try:
        url = f"https://api.revenuecat.com/v1/subscribers/{uid}"
        headers = {
            "Authorization": f"Bearer {rc_key}",
            "Content-Type": "application/json"
        }
        
        response = requests.get(url, headers=headers, timeout=4)
        
        if response.status_code == 200:
            data = response.json()
            entitlements = data.get('subscriber', {}).get('entitlements', {})
            
            for ent_name, ent_data in entitlements.items():
                expires = ent_data.get('expires_date')
                if expires:
                    dt_expires = datetime.fromisoformat(expires.replace("Z", "+00:00"))
                    if dt_expires > datetime.now(timezone.utc):
                        return True # Assinatura ativa
                else:
                    return True # Assinatura vitalícia ou sem expiração
            
            return False # Não achou assinatura ativa
            
    except Exception as e:
        app.logger.error(f"Erro geral mo RevenueCat: {e}")
        return False
    
    return False
# ============================================================================

# ================  Rotas para Usuarios comuns e Notificações ================
# Função auxiliar para converter listas em CSV (blinda contra formats diferentes)
def list_to_csv(value):
    """Converte lista em string CSV para salvar no banco."""
    if value is None: return None
    if isinstance(value, list):
        return ",".join([str(v).strip() for v in value if v])
    if isinstance(value, str):
        return value.strip() if value.strip() else None
    return str(value)

def _inserir_criterios_filhos(cursor, alerta_id, data):
    """Insere os detalhes normalizados do alerta (UFs, Termos, etc)."""
    
    def inserir_lote(tabela, coluna, lista_valores, extra_col=None, extra_val=None):
        if not lista_valores: return
        
        lista_final = []
        if isinstance(lista_valores, list): lista_final = lista_valores
        elif isinstance(lista_valores, str): 
            lista_final = [x.strip() for x in lista_valores.split(',') if x.strip()]
            
        vals = []
        # Monta a query dinamicamente
        query = f"INSERT INTO {tabela} (alerta_id, {coluna}" + (f", {extra_col}" if extra_col else "") + ") VALUES (%s, %s" + (", %s" if extra_col else "") + ")"

        for item in lista_final:
            item_limpo = str(item).strip().replace('"', '').replace("'", "")
            if not item_limpo: continue
            
            if extra_val: vals.append((alerta_id, item_limpo, extra_val))
            else: vals.append((alerta_id, item_limpo))
        
        if vals: cursor.executemany(query, vals)

    inserir_lote('alertas_ufs', 'uf', data.get('uf'))
    inserir_lote('alertas_municipios', 'municipio_nome', data.get('municipio'))
    inserir_lote('alertas_modalidades', 'modalidade_id', data.get('modalidades'))
    inserir_lote('alertas_termos', 'termo', data.get('termos_inclusao'), 'tipo', 'INCLUSAO')
    inserir_lote('alertas_termos', 'termo', data.get('termos_exclusao'), 'tipo', 'EXCLUSAO')

# IMPORTANTE:
# - O UID do usuário NUNCA deve ser enviado pelo cliente.
# - A identidade do usuário é derivada EXCLUSIVAMENTE do Firebase ID Token
#   presente no header Authorization: Bearer <token>.
# - Qualquer UID enviado no body será ignorado.
# - Isso previne spoofing e garante que o backend seja a fonte da verdade.
class RegistroDispositivoSchema(BaseModel):
    email: Optional[str] = None
    nome: Optional[str] = None
    token_push: str
    tipo_dispositivo: str  # 'mobile_android', 'mobile_ios', 'web_browser'
    # Aceita dict ou str ou None. O App geralmente manda um Objeto (dict)
    device_info: Optional[Union[dict, str]] = None

@app.route('/api/usuarios/sincronizar', methods=['POST'])
@limiter.limit("20 per minute") # ISSO EVITA ABUSOS. Basicamente isso significa que um usuário pode chamar essa API no máximo 20 vezes por minuto.
@login_firebase_required  # <--- Segurança ativada. # Usuário deve estar logado no Firebase.
@with_db_cursor # Isso injeta o cursor do DB na função.
def api_sincronizar_usuario(uid, email, cursor):
    data = request.json
    
    # Segurança
    if 'uid' in data:
        app.logger.warning(f"SECURITY: Tentativa de envio de UID no body por {email}")
        return jsonify({'erro': 'Campo uid não é permitido'}), 400

    app.logger.info(f"SYNC USUARIO: Recebido payload de {email}")

    try:
        # Validação Pydantic (Assumindo que RegistroDispositivoSchema está importado)
        dados = RegistroDispositivoSchema(**data)
        
        # 1. Garante Usuário na Tabela status
        cursor.execute("""
            INSERT INTO usuarios_status (uid_externo, email, nome, created_at) 
            VALUES (%s, %s, %s, NOW())
            ON DUPLICATE KEY UPDATE email=VALUES(email), nome=VALUES(nome), updated_at=NOW()
        """, (uid, email, dados.nome))
        
        # 2. Pega ID Local
        cursor.execute("SELECT id, is_pro FROM usuarios_status WHERE uid_externo = %s", (uid,))
        user_row = cursor.fetchone()
        
        if not user_row:
             # Caso raríssimo onde o insert falhou silenciosamente
             raise Exception("Falha ao recuperar ID do usuário após insert")

        user_id = user_row['id']
        is_pro = bool(user_row['is_pro'])
        
        # 3. Tratamento JSON Device
        device_info_str = None
        if dados.device_info:
            if isinstance(dados.device_info, dict):
                device_info_str = json.dumps(dados.device_info)
            else:
                device_info_str = str(dados.device_info)

        # 4. Upsert do Dispositivo Atual
        cursor.execute("""
            INSERT INTO usuarios_dispositivos (usuario_id, tipo, token_push, device_info, updated_at)
            VALUES (%s, %s, %s, %s, NOW())
            ON DUPLICATE KEY UPDATE updated_at=NOW(), device_info=VALUES(device_info), token_push=VALUES(token_push)
        """, (user_id, dados.tipo_dispositivo, dados.token_push, device_info_str))
        
        # --- 5. LIMPEZA DE DISPOSITIVOS ANTIGOS (LOGICA SEGURA) ---
        cursor.execute("SELECT id FROM usuarios_dispositivos WHERE usuario_id = %s ORDER BY updated_at ASC", (user_id,))
        devices = cursor.fetchall()
        
        # Se tiver mais que 5, remove os excedentes (os mais antigos)
        if len(devices) > 5:
            qtd_para_remover = len(devices) - 5
            ids_para_remover = [d['id'] for d in devices[:qtd_para_remover]]
            
            if ids_para_remover:
                # Cria string segura para SQL IN (ex: %s, %s)
                format_strings = ','.join(['%s'] * len(ids_para_remover))
                sql_delete = f"DELETE FROM usuarios_dispositivos WHERE id IN ({format_strings})"
                cursor.execute(sql_delete, tuple(ids_para_remover))
                app.logger.info(f"SYNC CLEANUP: Removidos {len(ids_para_remover)} dispositivos antigos do user {user_id}")

        cursor._connection.commit()
        
        return jsonify({
            "status": "sucesso", 
            "mensagem": "Sincronizado com sucesso.",
            "is_pro": is_pro
        })

    except ValidationError as e:
        app.logger.error(f"SYNC ERRO VALIDACAO: {e.errors()}")
        return jsonify({'erro': "Dados inválidos", 'detalhes': e.errors()}), 400
    except Exception as e:
        app.logger.error(f"SYNC ERRO INTERNO: {e}")
        return jsonify({'erro': "Erro interno no servidor"}), 500


# ============================================================================
class AlertaSchema(BaseModel):
    nome_alerta: str
    uf: Optional[list[str] | str] = None 
    municipio: Optional[list[str] | str] = None
    modalidades: Optional[list[str] | str] = None
    termos_inclusao: list[str] | str 
    termos_exclusao: Optional[list[str] | str] = None
    enviar_push: bool = True
    enviar_email: bool = False
    # enviar_whatsapp: bool = False # Implantar isso seria fantastico no futuro


# --- ROTA LISTAR (GET) - CORRIGIDA PARA O NOVO BANCO ---
@app.route('/api/alertas', methods=['GET'])
@login_firebase_required
@with_db_cursor
def listar_alertas(uid, email, cursor):
    """
    Lista alertas convertendo as strings CSV do banco de volta para Listas JSON
    """
    try:
        cursor.execute("SELECT id FROM usuarios_status WHERE uid_externo = %s", (uid,))
        user_row = cursor.fetchone()
        
        if not user_row: return jsonify([]), 200

        # --- A MÁGICA DO GROUP_CONCAT ---
        # Como os dados estão em tabelas separadas, usamos subqueries para 
        # juntá-los com vírgula e entregar pronto para o App Mobile.
        query = """
            SELECT 
                pa.id, pa.nome_alerta, pa.enviar_push, pa.enviar_email, pa.created_at, pa.ativo,
                (SELECT GROUP_CONCAT(uf SEPARATOR ',') FROM alertas_ufs WHERE alerta_id = pa.id) as uf,
                (SELECT GROUP_CONCAT(municipio_nome SEPARATOR ',') FROM alertas_municipios WHERE alerta_id = pa.id) as municipio,
                (SELECT GROUP_CONCAT(modalidade_id SEPARATOR ',') FROM alertas_modalidades WHERE alerta_id = pa.id) as modalidades,
                (SELECT GROUP_CONCAT(termo SEPARATOR ',') FROM alertas_termos WHERE alerta_id = pa.id AND tipo = 'INCLUSAO') as termos_inclusao,
                (SELECT GROUP_CONCAT(termo SEPARATOR ',') FROM alertas_termos WHERE alerta_id = pa.id AND tipo = 'EXCLUSAO') as termos_exclusao
            FROM preferencias_alertas pa 
            WHERE pa.usuario_id = %s AND pa.ativo = TRUE
            ORDER BY pa.created_at DESC
        """
        cursor.execute(query, (user_row['id'],))
        alertas = cursor.fetchall()
        
        resultado_formatado = []
        for a in alertas:
            # Formata datas/decimais primeiro
            a = formatar_para_json(a)

            # Garante que enviar_email seja booleano (0/1 -> False/True)
            a['enviar_email'] = bool(a['enviar_email']) if 'enviar_email' in a else False
            
            # --- CONVERSÃO MANUAL DE STRING CSV PARA LISTA ---
            # Se for None, vira []. Se for string, dá split.
            a['uf'] = a['uf'].split(',') if a['uf'] else []
            a['municipio'] = a['municipio'].split(',') if a['municipio'] else []
            
            # Modalidades são números, precisamos converter '1,5' -> [1, 5]
            if a['modalidades']:
                a['modalidades'] = [int(m) for m in a['modalidades'].split(',') if m.isdigit()]
            else:
                a['modalidades'] = []
                
            a['termos_inclusao'] = a['termos_inclusao'].split(',') if a['termos_inclusao'] else []
            a['termos_exclusao'] = a['termos_exclusao'].split(',') if a['termos_exclusao'] else []
            
            resultado_formatado.append(a)
        
        return jsonify(resultado_formatado)
        
    except Exception as e:
        app.logger.error(f"Erro ao listar alertas: {e}")
        return jsonify({'erro': 'Erro ao buscar alertas'}), 500

# --- ROTA SALVAR (POST) ---
@app.route('/api/alertas', methods=['POST'])
@login_firebase_required
@with_db_cursor
def salvar_alerta(uid, email, cursor):
    data = request.json
    if not data: 
        app.logger.warning("Salvar alerta: JSON inválido recebido.")
        return jsonify({'erro': "JSON inválido"}), 400
    
    try:
        nome_alerta = data.get('nome_alerta', 'Alerta Personalizado')
        enviar_push = data.get('enviar_push', True)
        enviar_email = data.get('enviar_email', False) 

        # 1. Busca ou Cria Usuário (UPSERT)
        # INSERT IGNORE inicia a transação e bloqueia a linha se inserir
        cursor.execute("INSERT IGNORE INTO usuarios_status (uid_externo, email, created_at, is_pro) VALUES (%s, %s, NOW(), 0)", (uid, email))
        
        cursor.execute("SELECT id, is_pro FROM usuarios_status WHERE uid_externo = %s", (uid,))
        user_row = cursor.fetchone()
        user_id = user_row['id']
        is_pro = bool(user_row['is_pro'])

        # Segunda chance (Se consta como Free)
        if not is_pro:
            # Chama o helper LEVE (sem afetar o banco)
            is_pro_real = verificar_status_revenuecat_agora(uid)
            
            if is_pro_real:
                app.logger.info(f"RevenueCAT 2º teste: Usuário {uid} é PRO! Atualizando banco local...")
                
                # ATUALIZAÇÃO SEGURA: Usamos o MESMO cursor. 
                # Como estamos na mesma transação, não há deadlock.
                cursor.execute("""
                    UPDATE usuarios_status 
                    SET is_pro = 1, status_assinatura = 'active', updated_at = NOW() 
                    WHERE id = %s
                """, (user_id,))
                
                is_pro = True # Libera o fluxo
            else:
                return jsonify({"erro": "Funcionalidade exclusiva para assinantes PRO.", "upgrade_required": True}), 403

        # 3. Validação Limite
        LIMIT_PRO = 5
        cursor.execute("SELECT COUNT(*) as total FROM preferencias_alertas WHERE usuario_id = %s", (user_id,))
        if cursor.fetchone()['total'] >= LIMIT_PRO:
            return jsonify({"erro": f"Limite de {LIMIT_PRO} alertas atingido."}), 403

        # 4. Insere Alerta
        cursor.execute("""
            INSERT INTO preferencias_alertas (usuario_id, nome_alerta, enviar_push, enviar_email, ativo) 
            VALUES (%s, %s, %s, %s, 1)
        """, (user_id, nome_alerta, enviar_push, enviar_email))
        alerta_id = cursor.lastrowid 

        _inserir_criterios_filhos(cursor, alerta_id, data)
        
        # Commit Único no final
        cursor._connection.commit()
        return jsonify({"status": "sucesso", "id": alerta_id}), 201
        
    except Exception as e:
        app.logger.error(f"Erro criar alerta: {e}")
        app.logger.error(traceback.format_exc())
        return jsonify({'erro': "Erro interno."}), 500
    
@app.route('/api/alertas/<int:alerta_id>', methods=['PUT'])
@login_firebase_required
@with_db_cursor
def editar_alerta(uid, email, cursor, alerta_id):
    app.logger.info(f"Editar alerta {alerta_id} para usuário {uid}")
    data = request.json
    
    try:
        # 1. VERIFICAÇÃO DE SEGURANÇA (O alerta pertence a esse usuário?)
        cursor.execute("""
            SELECT pa.id 
            FROM preferencias_alertas pa
            JOIN usuarios_status u ON pa.usuario_id = u.id
            WHERE pa.id = %s AND u.uid_externo = %s
        """, (alerta_id, uid))
        
        if not cursor.fetchone():
            app.logger.warning(f"ALERTA: Tentativa de editar alerta {alerta_id} que não pertence ao usuário {uid}. OU alerta não existe.")
            return jsonify({"erro": "Alerta não encontrado ou acesso negado."}), 404

        # 2. ATUALIZA A TABELA PAI (Nome, Status, Push)
        nome_alerta = data.get('nome_alerta')
        enviar_push = data.get('enviar_push')
        enviar_email = data.get('enviar_email') 
        
        cursor.execute("""
            UPDATE preferencias_alertas 
            SET nome_alerta = %s, enviar_push = %s, enviar_email = %s, ativo = 1
            WHERE id = %s
        """, (nome_alerta, enviar_push, enviar_email, alerta_id))

        # 3. ESTRATÉGIA "LIMPA" (Deleta todos os filhos antigos)
        # Como configuramos ON DELETE CASCADE no banco, deletar o pai apagaria tudo.
        # Mas aqui NÃO queremos deletar o pai (para manter o ID).
        # Então deletamos manualmente os filhos.
        
        tabelas_filhas = [
            'alertas_ufs', 
            'alertas_municipios', 
            'alertas_modalidades', 
            'alertas_termos'
        ]
        
        for tabela in tabelas_filhas:
            cursor.execute(f"DELETE FROM {tabela} WHERE alerta_id = %s", (alerta_id,))

        # 4. ESTRATÉGIA "REFAZ" (Insere os novos dados usando a função auxiliar)
        _inserir_criterios_filhos(cursor, alerta_id, data)
        app.logger.info(f"ALERTA: Alerta {alerta_id} atualizado com sucesso para o usuário {uid}.")

        # 5. COMMIT FINAL
        cursor._connection.commit()

        return jsonify({"status": "sucesso", "mensagem": "Alerta atualizado com sucesso."}), 200

    except Exception as e:
        app.logger.error(f"Erro ao editar alerta {alerta_id}: {e}")
        return jsonify({'erro': "Erro interno ao atualizar alerta."}), 500


@app.route('/api/alertas/<int:alerta_id>', methods=['DELETE'])
@login_firebase_required
@with_db_cursor
def deletar_alerta(uid, email, cursor, alerta_id):
    """Remove (desativa) um alerta"""
    try:
        cursor.execute("SELECT id FROM usuarios_status WHERE uid_externo = %s", (uid,))
        user_row = cursor.fetchone()
        
        if not user_row:
             return jsonify({"erro": "Usuário não encontrado."}), 404

        # Deleta apenas se pertencer ao usuário (Segurança!)
        query = "DELETE FROM preferencias_alertas WHERE id = %s AND usuario_id = %s"
        cursor.execute(query, (alerta_id, user_row['id']))
        cursor._connection.commit()
        app.logger.info(f"ALERTA: Deletando alerta {alerta_id} do usuário {uid}.")
        
        if cursor.rowcount > 0:
            return jsonify({"status": "sucesso", "mensagem": "Alerta removido."})
        else:
            return jsonify({"erro": "Alerta não encontrado ou não pertence a você."}), 404
    
    except Exception as e:
        app.logger.error(f"Erro ao deletar alerta: {e}")
        return jsonify({'erro': "Erro interno."}), 500
# Fim da logica de alertas e usuarios

# ============================================================================
# --- Rota para Sincronizar LICITAÇÕES Favoritos ---
@app.route('/api/favoritos/sincronizar', methods=['POST'])
@login_firebase_required
@with_db_cursor
def sincronizar_favoritos(uid, email, cursor):
    data = request.json or {}
    ids_locais = data.get('ids_locais', [])
    
    # 1. Busca Usuario
    cursor.execute("SELECT id, is_pro FROM usuarios_status WHERE uid_externo = %s", (uid,))
    user_row = cursor.fetchone()
    if not user_row: return jsonify({"erro": "Usuario nao encontrado"}), 404
    user_id = user_row['id']
    app.logger.info(f"FAVORITOS: Sincronizando favoritos para usuario {user_id} (PRO={user_row['is_pro']})")
    
    # 2. Verifica Limite (Ex: 100)
    LIMITE_FAVORITOS = 100
    cursor.execute("SELECT COUNT(*) as total FROM usuarios_licitacoes_favoritas WHERE usuario_id = %s", (user_id,))
    total_atual = cursor.fetchone()['total']
    
    # Se ja passou do limite, nao insere novos, mas devolve a lista existente
    pode_inserir = total_atual < LIMITE_FAVORITOS

    if ids_locais and pode_inserir:
        # Filtra para nao estourar o limite na inserção em lote
        espaco_restante = LIMITE_FAVORITOS - total_atual
        ids_para_inserir = ids_locais[:espaco_restante]
        app.logger.info(f"FAVORITOS: Inserindo {len(ids_para_inserir)} novos favoritos para usuario {user_id}")

        valores = [(user_id, pncp) for pncp in ids_para_inserir]
        if valores:
            cursor.executemany("INSERT IGNORE INTO usuarios_licitacoes_favoritas (usuario_id, licitacao_pncp) VALUES (%s, %s)", valores)
            cursor._connection.commit()

    # 3. Retorna TUDO que está no banco para o app atualizar
    cursor.execute("SELECT licitacao_pncp FROM usuarios_licitacoes_favoritas WHERE usuario_id = %s", (user_id,))
    todos = [row['licitacao_pncp'] for row in cursor.fetchall()]
    
    return jsonify({
        "status": "sucesso", 
        "favoritos_remotos": todos,
        "limite_atingido": len(todos) >= LIMITE_FAVORITOS
    })

# --- Remoção Individual licitações favoritas ---
@app.route('/api/favoritos/<path:pncp_id>', methods=['DELETE'])
@login_firebase_required
@with_db_cursor
def remover_favorito(uid, email, cursor, pncp_id):
    cursor.execute("SELECT id FROM usuarios_status WHERE uid_externo = %s", (uid,))
    user_row = cursor.fetchone()
    if not user_row: return jsonify({"erro": "Usuario"}), 404
    
    cursor.execute("DELETE FROM usuarios_licitacoes_favoritas WHERE usuario_id = %s AND licitacao_pncp = %s", (user_row['id'], pncp_id))
    cursor._connection.commit()
    app.logger.info(f"FAVORITOS: Removendo Licitação favorito {pncp_id} para usuario {user_row['id']}")
    
    return jsonify({"status": "sucesso"})

# ============================================================================
# --- Rota para Sincronizar Filtros Favoritos ---
@app.route('/api/filtros_favoritos/sincronizar', methods=['POST'])
@login_firebase_required
@with_db_cursor
def sincronizar_filtros_favoritos(uid, email, cursor):
    data = request.json or {}
    filtros_locais = data.get('filtros_locais', [])
    app.logger.info(f"SYNC FILTROS: Recebidos {len(filtros_locais)} filtros de {email}")
    
    # 1. Busca Usuário
    cursor.execute("SELECT id FROM usuarios_status WHERE uid_externo = %s", (uid,))
    user_row = cursor.fetchone()
    if not user_row: 
        return jsonify({"erro": "Usuario nao encontrado"}), 404
    user_id = user_row['id']
    
    # --- TRAVA DE LIMITE ---
    LIMITE_FILTROS = 30 
    cursor.execute("SELECT COUNT(*) as total FROM usuarios_filtros_salvos WHERE usuario_id = %s", (user_id,))
    res_count = cursor.fetchone()
    total_atual = res_count['total']

    espaco_livre = LIMITE_FILTROS - total_atual
    
    # Lógica de processamento
    filtros_para_processar = []

    if espaco_livre <= 0:
        # Já está cheio, não adiciona novos, mas LOGA para sabermos
        app.logger.warning(f"LIMITES: Usuario {user_id} atingiu limite ({total_atual}/{LIMITE_FILTROS}). Novos filtros ignorados.")
    else:
        # Se enviou mais do que cabe, corta a lista. Se enviou menos, processa tudo.
        if len(filtros_locais) > espaco_livre:
            filtros_para_processar = filtros_locais[:espaco_livre]
        else:
            filtros_para_processar = filtros_locais

        # Loop de inserção SEGURO
        for f in filtros_para_processar:
            id_mobile = f.get('id')
            nome = f.get('nome')
            config_json = json.dumps(f.get('filtros', {}))
            
            app.logger.info(f"FILTROS: Salvando '{nome}' (ID: {id_mobile})")
            
            cursor.execute("""
                INSERT INTO usuarios_filtros_salvos (usuario_id, id_mobile, nome_filtro, configuracao_json, created_at)
                VALUES (%s, %s, %s, %s, NOW())
                ON DUPLICATE KEY UPDATE 
                    nome_filtro = VALUES(nome_filtro),
                    configuracao_json = VALUES(configuracao_json),
                    updated_at = NOW()
            """, (user_id, id_mobile, nome, config_json))
    
    # Commit das alterações
    cursor._connection.commit()

    # 3. Retorna TUDO que está no banco (sincronização de volta para o app)
    cursor.execute("SELECT id_mobile, nome_filtro, configuracao_json FROM usuarios_filtros_salvos WHERE usuario_id = %s", (user_id,))
    rows = cursor.fetchall()
    
    filtros_remotos = []
    for row in rows:
        try:
            filtros_remotos.append({
                "id": row['id_mobile'],
                "nome": row['nome_filtro'],
                "filtros": json.loads(row['configuracao_json'])
            })
        except json.JSONDecodeError:
            # Caso algum dado antigo no banco esteja corrompido, não quebra a API
            continue
    
    return jsonify({
        "status": "sucesso", 
        "filtros_remotos": filtros_remotos
    })

# --- Rota para Deletar um Filtro Favorito Específico ---
@app.route('/api/filtros_favoritos/<string:id_mobile>', methods=['DELETE'])
@login_firebase_required
@with_db_cursor
def deletar_filtro_favorito(uid, email, cursor, id_mobile):
    # 1. Busca Usuario
    cursor.execute("SELECT id FROM usuarios_status WHERE uid_externo = %s", (uid,))
    user_row = cursor.fetchone()
    if not user_row: return jsonify({"erro": "Usuario"}), 404
    
    # 2. Deleta usando o ID gerado pelo mobile e o ID do usuário (segurança)
    cursor.execute("DELETE FROM usuarios_filtros_salvos WHERE usuario_id = %s AND id_mobile = %s", (user_row['id'], id_mobile))
    cursor._connection.commit()
    app.logger.info(f"FILTROS: Deletando filtro favorito (ID Mobile: {id_mobile}) para usuario {user_row['id']}")
    
    if cursor.rowcount > 0:
        return jsonify({"status": "sucesso", "mensagem": "Filtro removido."})
    else:
        return jsonify({"erro": "Filtro não encontrado."}), 404
# ============================================================================


if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    # Em produção real, você não usaria app.run(), mas sim um servidor WSGI como Gunicorn.
    # O debug=True também deve ser False ou controlado por uma variável de ambiente em produção.
    is_debug_mode = os.getenv('FLASK_DEBUG', '0') == '1'
    app.run(debug=is_debug_mode, host='0.0.0.0', port=port) # Modo debug esta configurado no arquivo .env
