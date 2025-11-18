import requests
import re
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

# Expressions régulières pour la détection de type
IP_REGEX = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
URL_REGEX = re.compile(r"httpsa?://[^\s]+")
DOMAIN_REGEX = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$")
MD5_REGEX = re.compile(r"^[a-f0-9]{32}$")
SHA1_REGEX = re.compile(r"^[a-f0-9]{40}$")
SHA256_REGEX = re.compile(r"^[a-f0-9]{64}$")

def detect_input_type(input_value):
    """Détecte le type d'indicateur (IP, URL, Hash, Domaine)."""
    if IP_REGEX.match(input_value):
        return 'ip'
    if URL_REGEX.match(input_value):
        return 'url'
    if DOMAIN_REGEX.match(input_value):
        return 'domain' # Vous devriez ajouter 'domain' à vos TYPE_CHOICES dans models.py
    if MD5_REGEX.match(input_value) or SHA1_REGEX.match(input_value) or SHA256_REGEX.match(input_value):
        return 'hash'
    return 'unknown' # Ou 'domain' par défaut si ce n'est pas une URL

# --- Fonctions de l'API VirusTotal ---

VT_API_URL = "https://www.virustotal.com/api/v3"
VT_API_KEY = settings.VIRUSTOTAL_API_KEY

def vt_scan_file(file_obj):
    """Scan un fichier uploadé avec VirusTotal."""
    if not VT_API_KEY:
        return {'error': 'Clé API VirusTotal non configurée.'}
    
    url = f"{VT_API_URL}/files"
    headers = {"x-apikey": VT_API_KEY}
    files = {"file": (file_obj.name, file_obj.read())}
    
    try:
        response = requests.post(url, headers=headers, files=files, timeout=20)
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"Erreur VT File Scan {response.status_code}: {response.text}")
            return {'error': f"API Error {response.status_code}", 'details': response.json()}
    except Exception as e:
        logger.error(f"Erreur requête VT File Scan : {e}")
        return {'error': str(e)}

def vt_get_analysis_report(analysis_id):
    """Récupère un rapport d'analyse en cours de VT (pour les fichiers)."""
    url = f"{VT_API_URL}/analyses/{analysis_id}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        return response.json() if response.status_code == 200 else {'error': f"API Error {response.status_code}"}
    except Exception as e:
        return {'error': str(e)}

def vt_scan_url(target_url):
    """Scan une URL avec VirusTotal."""
    if not VT_API_KEY:
        return {'error': 'Clé API VirusTotal non configurée.'}
        
    url = f"{VT_API_URL}/urls"
    headers = {"x-apikey": VT_API_KEY}
    data = {"url": target_url}
    
    try:
        response = requests.post(url, headers=headers, data=data, timeout=10)
        if response.status_code == 200:
            # L'API retourne un ID d'analyse, nous devons ensuite récupérer le rapport
            analysis_id = response.json().get('data', {}).get('id')
            if analysis_id:
                # Il faut un délai pour que l'analyse se termine
                # Pour une API, il vaut mieux retourner l'ID et le vérifier plus tard
                # Mais pour la simplicité, nous allons essayer de le récupérer
                import time
                time.sleep(15) # PAS IDÉAL POUR UNE API - Envisagez Celery
                report_url = f"{VT_API_URL}/analyses/{analysis_id}"
                report_response = requests.get(report_url, headers=headers, timeout=10)
                return report_response.json() if report_response.status_code == 200 else {'error': f"Report Error {report_response.status_code}"}
            return {'error': 'ID d\'analyse non trouvé dans la réponse VT'}
        else:
            logger.error(f"Erreur VT URL Scan {response.status_code}: {response.text}")
            return {'error': f"API Error {response.status_code}", 'details': response.json()}
    except Exception as e:
        logger.error(f"Erreur requête VT URL Scan : {e}")
        return {'error': str(e)}

def vt_scan_ip(ip_address):
    """Récupère le rapport pour une IP de VirusTotal."""
    url = f"{VT_API_URL}/ip_addresses/{ip_address}"
    return vt_generic_get_request(url)

def vt_scan_hash(file_hash):
    """Récupère le rapport pour un Hash de VirusTotal."""
    url = f"{VT_API_URL}/files/{file_hash}"
    return vt_generic_get_request(url)

def vt_scan_domain(domain):
    """Récupère le rapport pour un Domaine de VirusTotal."""
    url = f"{VT_API_URL}/domains/{domain}"
    return vt_generic_get_request(url)

def vt_generic_get_request(url):
    """Fonction générique pour les requêtes GET VT."""
    if not VT_API_KEY:
        return {'error': 'Clé API VirusTotal non configurée.'}
    
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"Erreur VT GET {response.status_code}: {response.text}")
            return {'error': f"API Error {response.status_code}", 'details': response.json()}
    except Exception as e:
        logger.error(f"Erreur requête VT GET : {e}")
        return {'error': str(e)}

# --- Fonctions de l'API OTX ---

OTX_API_URL = "https://otx.alienvault.com/api/v1"
OTX_API_KEY = settings.OTX_API_KEY

def otx_scan_ip(ip_address):
    """Récupère le rapport pour une IP d'OTX."""
    url = f"{OTX_API_URL}/indicators/IPv4/{ip_address}/general"
    return otx_generic_get_request(url)

def otx_scan_url(target_url):
    """Récupère le rapport pour une URL d'OTX."""
    # OTX utilise un encodage spécial pour les URLs
    import base64
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    url = f"{OTX_API_URL}/indicators/url/{url_id}/general"
    return otx_generic_get_request(url)

def otx_scan_hash(file_hash):
    """Récupère le rapport pour un Hash d'OTX."""
    url = f"{OTX_API_URL}/indicators/file/{file_hash}/general"
    return otx_generic_get_request(url)

def otx_generic_get_request(url):
    """Fonction générique pour les requêtes GET OTX."""
    if not OTX_API_KEY:
        return {'error': 'Clé API OTX non configurée.'}
        
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"Erreur OTX GET {response.status_code}: {response.text}")
            return {'error': f"API Error {response.status_code}", 'details': response.json()}
    except Exception as e:
        logger.error(f"Erreur requête OTX GET : {e}")
        return {'error': str(e)}

# --- Fonction de l'API IPInfo ---

IPINFO_TOKEN = settings.IPINFO_TOKEN

def get_ip_info(ip_address):
    """Récupère les infos de géolocalisation d'IPInfo."""
    if not IPINFO_TOKEN:
        return {'error': 'Token IPInfo non configuré.'}
        
    url = f"https://ipinfo.io/{ip_address}"
    headers = {"Authorization": f"Bearer {IPINFO_TOKEN}"}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            return response.json()
        else:
            logger.error(f"Erreur IPInfo {response.status_code}: {response.text}")
            return {'error': f"API Error {response.status_code}", 'details': response.json()}
    except Exception as e:
        logger.error(f"Erreur requête IPInfo : {e}")
        return {'error': str(e)}