# backend/notificacoes.py
# Precisa definir o Tipo de notificação para diferencias notificações se sistema, atualização, oportunidades, ect.
# Aqui por padrão é do tipo Oportunidade (licitação nova)!

import os
import firebase_admin
from firebase_admin import credentials, messaging
from dotenv import load_dotenv
import mysql.connector
import requests
import logging
from logging.handlers import RotatingFileHandler
import time
import html

load_dotenv()

# ==============================================================================
# CONFIGURAÇÃO DE LOGGING (Padronizado)
# ==============================================================================
# Garante que o diretório de logs exista
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, '../logs') # Ajuste se sua pasta logs estiver na raiz
if not os.path.exists(LOG_DIR):
    try:
        os.makedirs(LOG_DIR)
    except OSError:
        pass # Se já existir ou erro de permissão (tenta usar local)
        LOG_DIR = 'logs'
        if not os.path.exists(LOG_DIR): os.makedirs(LOG_DIR)

LOG_FILE = os.path.join(LOG_DIR, 'notificacoes.log')

# Cria o logger
logger = logging.getLogger('worker_notificacoes')
logger.setLevel(logging.INFO)

# Formato do log
formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')

# 1. Handler de Arquivo (Rotaciona a cada 10MB, guarda 5 arquivos)
file_handler = RotatingFileHandler(LOG_FILE, maxBytes=10240000, backupCount=5)
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.INFO)

# 2. Handler de Console (Para ver no terminal se rodar manual)
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
stream_handler.setLevel(logging.INFO)

# Adiciona os handlers (evita duplicação se recarregar)
if not logger.handlers:
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)

logger.info("--- WORKER DE NOTIFICAÇÕES INICIADO ---")
# ==============================================================================

# Firebase Init (Robusto)
if not firebase_admin._apps:
    try:
        # Tenta achar o arquivo em múltiplos lugares
        base_dir = os.path.dirname(os.path.abspath(__file__)) # Pasta atual (backend)
        root_dir = os.path.dirname(base_dir) # Pasta pai (radar-pncp)
        
        caminhos_possiveis = [
            os.path.join(base_dir, 'firebase_credentials.json'),      # ./backend/firebase_credentials.json
            os.path.join(root_dir, 'firebase_credentials.json'),      # ./firebase_credentials.json
            '/var/www/radar-pncp/firebase_credentials.json'           # Caminho absoluto hardcoded (último recurso)
        ]
        
        cred_path = None
        for p in caminhos_possiveis:
            if os.path.exists(p):
                cred_path = p
                break
        
        if not cred_path:
            raise FileNotFoundError(f"Arquivo firebase_credentials.json não encontrado em: {caminhos_possiveis}")

        logger.info(f"Carregando credenciais Firebase de: {cred_path}")
        cred = credentials.Certificate(cred_path)
        firebase_admin.initialize_app(cred)
        logger.info("Firebase Admin inicializado.")
        
    except Exception as e:
        logger.critical(f"ERRO CRÍTICO AO INICIAR FIREBASE: {e}")
        # IMPORTANTE: Se não conectar no Firebase, o script DEVE parar, senão fica em loop de erro
        exit(1)

def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv('MARIADB_HOST'), user=os.getenv('MARIADB_USER'),
        password=os.getenv('MARIADB_PASSWORD'), database=os.getenv('MARIADB_DATABASE')
    )

# Helper para o corpo de email
# Precisa ainda configurar a ação do click no link. ATENÇÃO!!!
def gerar_html_email(nome_usuario, titulo_licitacao, orgao, valor, municipio, uf, link_pncp, nome_alerta):
    # SEGURANÇA: Limpa caracteres perigosos para evitar quebrar o HTML
    titulo_limpo = html.escape(titulo_licitacao)
    orgao_limpo = html.escape(orgao)
    municipio_limpo = html.escape(municipio)
    
    # Cores da sua marca
    COR_PRIMARIA = "#0056b3"
    COR_FUNDO = "#f4f4f7"
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
        <style>
            body {{ background-color: {COR_FUNDO}; font-family: sans-serif; font-size: 14px; line-height: 1.4; margin: 0; padding: 0; }}
            .container {{ display: block; margin: 0 auto !important; max-width: 580px; padding: 10px; width: 580px; }}
            .content {{ box-sizing: border-box; display: block; margin: 0 auto; max-width: 580px; padding: 10px; }}
            .main {{ background: #ffffff; border-radius: 3px; width: 100%; }}
            .wrapper {{ box-sizing: border-box; padding: 20px; }}
            .btn a {{ background-color: #ffffff; border: solid 1px {COR_PRIMARIA}; border-radius: 5px; color: {COR_PRIMARIA}; display: inline-block; font-weight: bold; padding: 12px 25px; text-decoration: none; }}
            .btn-primary a {{ background-color: {COR_PRIMARIA}; color: #ffffff; }}
            .infos {{ background-color: #f8f9fa; padding: 15px; border-radius: 4px; margin-bottom: 20px; border-left: 4px solid {COR_PRIMARIA}; }}
        </style>
    </head>
    <body>
        <table role="presentation" border="0" cellpadding="0" cellspacing="0" class="body">
        <tr>
            <td>&nbsp;</td>
            <td class="container">
            <div class="content">
                <table role="presentation" class="main">
                <tr>
                    <td class="wrapper">
                        <p>Olá, <strong>{html.escape(nome_usuario)}</strong>!</p>
                        <p>O seu alerta <strong>"{html.escape(nome_alerta)}"</strong> encontrou uma nova oportunidade:</p>
                        
                        <div class="infos">
                            <p style="font-size: 16px;"><strong>{titulo_limpo}</strong></p>
                            <p>🏛️ {orgao_limpo}</p>
                            <p>📍 {municipio_limpo} - {uf}</p>
                            <p>💰 <strong>Valor Estimado: {valor}</strong></p>
                        </div>

                        <p>Toque no botão abaixo para ver no aplicativo:</p>
                        
                        <table role="presentation" border="0" cellpadding="0" cellspacing="0" class="btn btn-primary">
                        <tbody>
                            <tr>
                                <td align="center">
                                    <a href="{link_pncp}" target="_blank">Ver Oportunidade</a>
                                </td>
                            </tr>
                        </tbody>
                        </table>
                        
                        <p style="font-size: 12px; color: #777; margin-top: 20px;">
                           Link direto: {link_pncp}
                        </p>
                    </td>
                </tr>
                </table>
            </div>
            </td>
            <td>&nbsp;</td>
        </tr>
        </table>
    </body>
    </html>
    """
    return html_content

def enviar_email_mailgun(destinatario_email, destinatario_nome, assunto, html_body):
    """Envia o e-mail usando a API do Mailgun"""
    try:
        domain = os.getenv('MAILGUN_DOMAIN')
        api_key = os.getenv('MAILGUN_API_KEY')
        sender = os.getenv('EMAIL_REMETENTE', f'Finnd Alertas <no-reply@{domain}>')
        
        if not domain or not api_key:
            logger.error("Mailgun não configurado no .env")
            return

        response = requests.post(
            f"https://api.mailgun.net/v3/{domain}/messages",
            auth=("api", api_key),
            data={
                "from": sender,
                "to": [destinatario_email],
                "subject": assunto,
                "html": html_body
            },
            timeout=5
        )
        if response.status_code != 200:
            # Mudei para CRITICAL para garantir que vc veja no arquivo de log
            logger.critical(f"FALHA MAILGUN EMAIL para {destinatario_email}: Status {response.status_code} - Resposta: {response.text}")
        else:
            logger.info(f"EMAIL ENVIADO com sucesso para {destinatario_email}")
            
    except Exception as e:
        logger.error(f"Exceção ao enviar email: {e}")

# Segurança: Resgata licitações travadas (ZUMBIS)
def resgatar_zumbis(cursor, conn):
    """
    Faxina de segurança: Procura licitações travadas no status 2 (Processando)
    há mais de 15 minutos (possível crash do script anterior) e reseta para 0.
    """
    try:
        cursor.execute("""
            UPDATE licitacoes 
            SET notificacao_processada = 0, 
                processamento_inicio = NULL 
            WHERE notificacao_processada = 2 
            AND processamento_inicio < DATE_SUB(NOW(), INTERVAL 15 MINUTE)
        """)
        
        afetados = cursor.rowcount
        if afetados > 0:
            conn.commit()
            logger.warning(f"🧟 ZUMBIS RESGATADOS: {afetados} licitações travadas foram resetadas para fila.")
            
    except mysql.connector.Error as err:
        # Se der erro pq a coluna não existe, avisa mas não trava tudo
        if err.errno == 1054: # Unknown column
            logger.error("Erro Zumbi: Coluna 'processamento_inicio' não existe na tabela licitacoes. Rode o SQL de atualização.")
        else:
            logger.error(f"Erro ao resgatar zumbis: {err}")


def processar_notificacoes():
    licitacoes_para_processar = []
    
    # --- FASE 1: COLETA DE DADOS (Rápido) ---
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # 1. Resgate Zumbis
        resgatar_zumbis(cursor, conn)

        # 2. Marca Lote para processamento (Status 2)
        # Limite de 50 é bom para e-mail. Se fosse só push, poderia ser 200.
        cursor.execute("""
            UPDATE licitacoes 
            SET notificacao_processada = 2, processamento_inicio = NOW() 
            WHERE notificacao_processada = 0 
            LIMIT 50
        """)
        conn.commit()

        # 3. Seleciona Dados
        cursor.execute("""
            SELECT id, numeroControlePNCP, objetoCompra, valorTotalEstimado, situacaoReal,
                   unidadeOrgaoUfSigla, unidadeOrgaoMunicipioNome, modalidadeId, orgaoEntidadeRazaoSocial
            FROM licitacoes 
            WHERE notificacao_processada = 2
        """)
        licitacoes = cursor.fetchall()

        if not licitacoes:
            cursor.close()
            conn.close()
            return

        logger.info(f"Processando lote de {len(licitacoes)} licitações...")

        # 4. Busca Reversa (Matches)
        # Nota: Movido query string para fora do loop é melhor, mas aqui funciona.
        query_match = """
            SELECT DISTINCT d.token_push, d.tipo as device_type, pa.enviar_email, 
                   u.email as email_user, u.nome as nome_user, 
                   pa.nome_alerta, 
                   pa.id as alerta_id
            FROM preferencias_alertas pa
            JOIN usuarios_status u ON pa.usuario_id = u.id
            LEFT JOIN usuarios_dispositivos d ON pa.usuario_id = d.usuario_id
            WHERE pa.ativo = 1 
             AND (
                (pa.enviar_push = 1 AND d.token_push IS NOT NULL) 
                OR 
                (pa.enviar_email = 1 AND u.email IS NOT NULL AND u.email != '')
            )
            AND u.is_pro = 1 AND u.status_assinatura IN ('active', 'trial', 'grace_period')
            AND (NOT EXISTS (SELECT 1 FROM alertas_ufs WHERE alerta_id = pa.id) OR EXISTS (SELECT 1 FROM alertas_ufs au WHERE au.alerta_id = pa.id AND au.uf = %s))
            AND (NOT EXISTS (SELECT 1 FROM alertas_municipios WHERE alerta_id = pa.id) OR EXISTS (SELECT 1 FROM alertas_municipios am WHERE am.alerta_id = pa.id AND am.municipio_nome = %s))
            AND (NOT EXISTS (SELECT 1 FROM alertas_modalidades WHERE alerta_id = pa.id) OR EXISTS (SELECT 1 FROM alertas_modalidades am WHERE am.alerta_id = pa.id AND am.modalidade_id = %s))
            AND EXISTS (SELECT 1 FROM alertas_termos at WHERE at.alerta_id = pa.id AND at.tipo = 'INCLUSAO' AND INSTR(%s, at.termo) > 0)
            AND NOT EXISTS (SELECT 1 FROM alertas_termos at WHERE at.alerta_id = pa.id AND at.tipo = 'EXCLUSAO' AND INSTR(%s, at.termo) > 0)
        """

        for lic in licitacoes:
            obj = (lic['objetoCompra'] or "").lower()
            uf = (lic['unidadeOrgaoUfSigla'] or "")
            mun = (lic['unidadeOrgaoMunicipioNome'] or "")
            mod = lic['modalidadeId']

            cursor.execute(query_match, (uf, mun, mod, obj, obj))
            matches = cursor.fetchall()
            
            if matches:
                licitacoes_para_processar.append({
                    'licitacao': lic,
                    'destinatarios': matches
                })
            else:
                # Se não deu match com ninguém, ainda assim precisamos marcar como lida depois
                # Adicionamos na lista com destinatarios vazio, apenas para dar baixa
                licitacoes_para_processar.append({
                    'licitacao': lic,
                    'destinatarios': []
                })

        cursor.close()
        conn.close()

    except Exception as e:
        logger.error(f"Erro na Fase 1 (Banco): {e}")
        if conn and conn.is_connected(): conn.close()
        return

    # --- FASE 2: ENVIO (API/FIREBASE) COM BAIXA IMEDIATA ---
    emails_enviados_ciclo = set()
    
    # [OTIMIZAÇÃO] Abre a conexão de update UMA VEZ antes do loop
    conn_up = None
    try:
        conn_up = get_db_connection()
        c_up = conn_up.cursor()

        for item in licitacoes_para_processar:
            lic = item['licitacao']
            destinatarios = item['destinatarios']
            mensagens_push_deste_item = []
            
            # Se tiver destinatários, prepara o envio
            if destinatarios:
                for dest in destinatarios:
                    # 1. Monta Push Notification
                    if dest['token_push']:
                        try:
                            # Título curto e direto para mobile
                            titulo = f"Nova em {lic['unidadeOrgaoMunicipioNome']}/{lic['unidadeOrgaoUfSigla']}"
                            # Corpo truncado
                            corpo = f"{lic['objetoCompra'][:120]}..."
                            
                            data_payload = {
                                "click_action": "FLUTTER_NOTIFICATION_CLICK", 
                                "tipo": "oportunidade",
                                # [CORREÇÃO] Enviar ID numérico E Código PNCP
                                "licitacao_id": str(lic['id']),       # ID do banco (Inteiro)
                                "pncp": str(lic['numeroControlePNCP']), # Código PNCP
                                "alerta_id": str(dest['alerta_id'])
                            }

                            # Configuração Otimizada (iOS + Android)
                            msg = messaging.Message(
                                token=dest['token_push'],
                                notification=messaging.Notification(title=titulo, body=corpo),
                                data=data_payload,
                                android=messaging.AndroidConfig(
                                    priority='high',
                                    # CORREÇÃO: Especificar o canal para garantir som/vibração
                                    notification=messaging.AndroidNotification(
                                        channel_id='high_importance_channel',
                                        click_action='FLUTTER_NOTIFICATION_CLICK'
                                    )
                                ),
                                apns=messaging.APNSConfig(
                                    payload=messaging.APNSPayload(
                                        aps=messaging.Aps(content_available=True, sound='default')
                                    )
                                )
                            )
                            mensagens_push_deste_item.append(msg)
                        except Exception as e: 
                            logger.error(f"Erro montagem push: {e}")

                    # 2. Envia Email
                    if dest['enviar_email'] and dest['email_user']:
                        chave = f"{dest['email_user']}_{lic['id']}"
                        if chave not in emails_enviados_ciclo:
                            emails_enviados_ciclo.add(chave)
                            val_est = f"R$ {float(lic['valorTotalEstimado']):,.2f}" if lic['valorTotalEstimado'] else "R$ N/I"
                            
                            html_body = gerar_html_email(
                                dest['nome_user'] or "Assinante", 
                                lic['objetoCompra'], 
                                lic.get('orgaoEntidadeRazaoSocial') or "Órgão",
                                val_est, 
                                lic['unidadeOrgaoMunicipioNome'], 
                                lic['unidadeOrgaoUfSigla'],
                                # Ajuste o link para abrir seu App ou Site corretamente
                                f"https://finnd.com.br/detalhes/{lic['numeroControlePNCP']}",   # CORRIGIR ISSOOOO
                                dest['nome_alerta']
                            )
                            enviar_email_mailgun(dest['email_user'], dest['nome_user'], f"Oportunidade: {lic['objetoCompra'][:30]}...", html_body)

                # B) Dispara Push deste item (Batch)
                if mensagens_push_deste_item:
                    try:
                        for i in range(0, len(mensagens_push_deste_item), 500):
                            batch = mensagens_push_deste_item[i:i+500]
                            messaging.send_each(batch)
                    except Exception as e:
                        logger.error(f"Erro envio Firebase Batch: {e}")

            # C) BAIXA IMEDIATA (Reutilizando a conexão aberta)
            try:
                c_up.execute("UPDATE licitacoes SET notificacao_processada = 1, processamento_inicio = NULL WHERE id = %s", (lic['id'],))
                conn_up.commit()
            except Exception as e:
                logger.critical(f"ERRO AO DAR BAIXA NA LICITACAO {lic['id']}: {e}")

        logger.info(f"Ciclo finalizado. {len(licitacoes)} processadas.")

    except Exception as e:
        logger.error(f"Erro crítico na Fase 2: {e}")
    finally:
        # Fecha a conexão de update de forma segura
        if conn_up and conn_up.is_connected():
            c_up.close()
            conn_up.close()

if __name__ == "__main__":
    logger.info("Worker iniciado em loop contínuo.")
    while True:
        try:
            processar_notificacoes()
        except KeyboardInterrupt:
            logger.info("Worker interrompido pelo usuário.")
            break
        except Exception as e:
            logger.critical(f"Erro fatal não tratado no loop: {e}")
            time.sleep(30)
        
        time.sleep(10) # Intervalo entre verificações