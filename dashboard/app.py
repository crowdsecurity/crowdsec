#!/usr/bin/env python3
"""
Tableau de bord CrowdSec - Backend Flask
Ce serveur agit comme un proxy entre le navigateur et l'API locale CrowdSec (LAPI).
"""

import os
import sys
import json
import subprocess
import time
from datetime import datetime, timedelta
from functools import wraps

import yaml
import requests
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# Configuration globale
config = {}
jwt_token = None
jwt_expiry = None


def load_config():
    """Charge la configuration depuis config.yaml"""
    global config
    config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
    
    if not os.path.exists(config_path):
        print(f"❌ Fichier de configuration introuvable : {config_path}")
        print("📝 Copiez config.example.yaml vers config.yaml et configurez-le.")
        sys.exit(1)
    
    with open(config_path, 'r') as f:
        config = yaml.safe_load(f)
    
    print("✅ Configuration chargée avec succès")


def get_jwt_token():
    """Obtient un token JWT en se connectant comme machine"""
    global jwt_token, jwt_expiry
    
    # Vérifier si le token est toujours valide
    if jwt_token and jwt_expiry and datetime.now() < jwt_expiry:
        return jwt_token
    
    # Obtenir un nouveau token
    lapi_url = config['lapi']['url']
    login_url = f"{lapi_url}/v1/watchers/login"
    
    payload = {
        'machine_id': config['lapi']['machine_id'],
        'password': config['lapi']['machine_password']
    }
    
    try:
        response = requests.post(login_url, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        jwt_token = data.get('token')
        # Le token expire généralement après 2 heures, on le renouvelle après 1h50
        jwt_expiry = datetime.now() + timedelta(minutes=110)
        
        print(f"🔑 Token JWT obtenu, expire à {jwt_expiry.strftime('%H:%M:%S')}")
        return jwt_token
    
    except requests.exceptions.RequestException as e:
        print(f"❌ Erreur lors de l'authentification JWT : {e}")
        return None


def jwt_required(f):
    """Décorateur pour les routes nécessitant une authentification JWT"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = get_jwt_token()
        if not token:
            return jsonify({'error': 'Authentification échouée'}), 401
        return f(*args, **kwargs)
    return decorated_function


def run_cscli_command(command_args):
    """Exécute une commande cscli et retourne le résultat JSON"""
    try:
        result = subprocess.run(
            command_args,
            shell=False,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            print(f"❌ Erreur cscli : {result.stderr}")
            return None
        
        # Parser le JSON de sortie
        return json.loads(result.stdout)
    
    except subprocess.TimeoutExpired:
        print(f"⏱️ Timeout lors de l'exécution de : {' '.join(command_args)}")
        return None
    except json.JSONDecodeError as e:
        print(f"❌ Erreur de parsing JSON : {e}")
        return None
    except Exception as e:
        print(f"❌ Erreur lors de l'exécution de cscli : {e}")
        return None


# Routes de l'application

@app.route('/')
def index():
    """Sert le SPA (Single Page Application)"""
    # Valider et assainir l'intervalle de rafraîchissement
    refresh_interval = config['dashboard'].get('refresh_interval', 30)
    try:
        refresh_interval = int(refresh_interval)
        if refresh_interval < 5 or refresh_interval > 3600:
            refresh_interval = 30  # Par défaut si hors limites
    except (ValueError, TypeError):
        refresh_interval = 30  # Par défaut si invalide
    
    return render_template('index.html', refresh_interval=refresh_interval)


@app.route('/api/health')
def health():
    """Endpoint de santé - proxy vers LAPI /health"""
    lapi_url = config['lapi']['url']
    try:
        response = requests.get(f"{lapi_url}/health", timeout=5)
        return jsonify({'status': 'ok' if response.status_code == 200 else 'error'}), response.status_code
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 503


@app.route('/api/alerts')
@jwt_required
def get_alerts():
    """Récupère la liste des alertes"""
    lapi_url = config['lapi']['url']
    token = get_jwt_token()
    
    # Récupérer les paramètres de requête (filtres, pagination, etc.)
    query_params = request.args.to_dict()
    
    try:
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.get(
            f"{lapi_url}/v1/alerts",
            headers=headers,
            params=query_params,
            timeout=10
        )
        response.raise_for_status()
        return jsonify(response.json()), response.status_code
    
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts/<int:alert_id>')
@jwt_required
def get_alert(alert_id):
    """Récupère une alerte spécifique"""
    lapi_url = config['lapi']['url']
    token = get_jwt_token()
    
    try:
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.get(
            f"{lapi_url}/v1/alerts/{alert_id}",
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        return jsonify(response.json()), response.status_code
    
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/alerts/<int:alert_id>', methods=['DELETE'])
@jwt_required
def delete_alert(alert_id):
    """Supprime une alerte"""
    lapi_url = config['lapi']['url']
    token = get_jwt_token()
    
    try:
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.delete(
            f"{lapi_url}/v1/alerts/{alert_id}",
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        return jsonify({'message': 'Alerte supprimée'}), 200
    
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/decisions')
def get_decisions():
    """Récupère la liste des décisions (authentification via API key bouncer)"""
    lapi_url = config['lapi']['url']
    api_key = config['lapi']['bouncer_api_key']
    
    # Récupérer les paramètres de requête
    query_params = request.args.to_dict()
    
    try:
        headers = {'X-Api-Key': api_key}
        response = requests.get(
            f"{lapi_url}/v1/decisions",
            headers=headers,
            params=query_params,
            timeout=10
        )
        response.raise_for_status()
        return jsonify(response.json()), response.status_code
    
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/decisions/<int:decision_id>', methods=['DELETE'])
@jwt_required
def delete_decision(decision_id):
    """Supprime une décision"""
    lapi_url = config['lapi']['url']
    token = get_jwt_token()
    
    try:
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.delete(
            f"{lapi_url}/v1/decisions/{decision_id}",
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        return jsonify({'message': 'Décision supprimée'}), 200
    
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/machines')
def get_machines():
    """Récupère la liste des machines via cscli"""
    result = run_cscli_command(['cscli', 'machines', 'list', '-o', 'json'])
    
    if result is None:
        return jsonify({'error': 'Erreur lors de la récupération des machines'}), 500
    
    return jsonify(result), 200


@app.route('/api/bouncers')
def get_bouncers():
    """Récupère la liste des bouncers via cscli"""
    result = run_cscli_command(['cscli', 'bouncers', 'list', '-o', 'json'])
    
    if result is None:
        return jsonify({'error': 'Erreur lors de la récupération des bouncers'}), 500
    
    return jsonify(result), 200


@app.route('/api/metrics')
def get_metrics():
    """Récupère les métriques via cscli"""
    result = run_cscli_command(['cscli', 'metrics', 'show', '-o', 'json'])
    
    if result is None:
        return jsonify({'error': 'Erreur lors de la récupération des métriques'}), 500
    
    return jsonify(result), 200


if __name__ == '__main__':
    print("=" * 60)
    print("🛡️  Tableau de bord CrowdSec")
    print("=" * 60)
    
    load_config()
    
    host = config['dashboard']['host']
    port = config['dashboard']['port']
    
    print(f"\n🚀 Démarrage du serveur sur http://{host}:{port}")
    print(f"📊 Accédez au tableau de bord : http://localhost:{port}\n")
    
    app.run(
        host=host,
        port=port,
        debug=False
    )
