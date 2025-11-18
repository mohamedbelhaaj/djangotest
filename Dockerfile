# 1️⃣ Image Python officielle
FROM python:3.11-slim

# 2️⃣ Définir le répertoire de travail
WORKDIR /app

# 3️⃣ Copier les dépendances et les installer
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4️⃣ Copier le code du projet
COPY . .

# 5️⃣ Exposer le port sur lequel Django va tourner
EXPOSE 8000

# 6️⃣ Lancer collectstatic et Gunicorn via un script d'entrée
#     Les secrets viendront du fichier .env monté par docker-compose
CMD ["sh", "-c", "python manage.py collectstatic --noinput && gunicorn virus_analyzer.wsgi:application --bind 0.0.0.0:8000"]
