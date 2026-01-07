    # Usa uma imagem base Python leve
    FROM python:3.10-slim-buster

    # Define o diretório de trabalho dentro do container
    WORKDIR /app

    # Copia o arquivo requirements.txt para o diretório de trabalho
    COPY requirements.txt .

    # Instala as dependências Python
    RUN pip install --no-cache-dir -r requirements.txt

    # Copia todo o resto do código da aplicação para o diretório de trabalho
    COPY . .

    # Expõe a porta que a aplicação vai usar
    EXPOSE 8080

    # Comando para iniciar a aplicação com Gunicorn
    CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]
