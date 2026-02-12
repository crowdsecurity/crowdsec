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
import ipaddress
from datetime import datetime, timedelta
from functools import wraps
from collections import Counter

import yaml
import requests
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

# Configuration globale
config = {}
jwt_token = None
jwt_expiry = None

# Cache GeoIP
geoip_cache = {}
GEOIP_CACHE_DURATION = 86400  # 24h par défaut

# Constantes pour les estimations de métriques
# Note: Ces valeurs sont des approximations arbitraires utilisées pour estimer
# les ressources économisées. Les valeurs réelles varient selon les types d'attaque.
BYTES_PER_DECISION = 1024      # Average bytes blocked per decision
PACKETS_PER_DECISION = 1       # One packet per decision (simplified)
LOG_LINES_PER_DECISION = 10    # Estimated log lines saved per decision
BYTES_PER_LOG_LINE = 200       # Average bytes per log line


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


def get_country_flag(country_code):
    """Convertit un code pays ISO en emoji de drapeau"""
    if not country_code or len(country_code) != 2:
        return '🏴'
    
    try:
        # Convertir le code ISO en emoji de drapeau
        # A = U+1F1E6, donc 'A' - 'A' + U+1F1E6 = U+1F1E6
        code_points = [ord(char) + 127397 for char in country_code.upper()]
        return chr(code_points[0]) + chr(code_points[1])
    except Exception:
        return '🏴'


def enrich_ip_with_geoip(ip):
    """Enrichit une IP avec les données GeoIP (pays, AS)"""
    # Valider l'adresse IP pour prévenir les attaques SSRF
    try:
        ip_obj = ipaddress.ip_address(ip)
        # Rejeter les adresses privées et loopback pour éviter SSRF
        if ip_obj.is_private or ip_obj.is_loopback:
            return {
                'ip': ip,
                'country_code': None,
                'country_name': 'Private/Loopback',
                'country_flag': '🏴',
                'as_number': None,
                'as_name': None
            }
    except ValueError:
        # IP invalide
        return {
            'ip': ip,
            'country_code': None,
            'country_name': None,
            'country_flag': None,
            'as_number': None,
            'as_name': None
        }
    
    # Vérifier si GeoIP est activé
    geoip_config = config.get('geoip', {})
    if not geoip_config.get('enabled', False):
        return {
            'ip': ip,
            'country_code': None,
            'country_name': None,
            'country_flag': None,
            'as_number': None,
            'as_name': None
        }
    
    # Vérifier le cache
    cache_duration = geoip_config.get('cache_duration', GEOIP_CACHE_DURATION)
    if ip in geoip_cache:
        cached = geoip_cache[ip]
        if time.time() - cached['timestamp'] < cache_duration:
            return cached['data']
    
    # Déterminer le fournisseur
    provider = geoip_config.get('provider', 'ip-api')
    
    try:
        if provider == 'ip-api':
            # ip-api.com - gratuit, 45 req/min
            # IP est déjà validée, safe pour interpolation
            url = f"https://ip-api.com/json/{ip}"
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            data = response.json()
            
            if data.get('status') == 'success':
                result = {
                    'ip': ip,
                    'country_code': data.get('countryCode'),
                    'country_name': data.get('country'),
                    'country_flag': get_country_flag(data.get('countryCode')),
                    'as_number': data.get('as', '').split()[0] if data.get('as') else None,
                    'as_name': ' '.join(data.get('as', '').split()[1:]) if data.get('as') else None
                }
            else:
                result = {'ip': ip, 'country_code': None, 'country_name': None, 
                         'country_flag': None, 'as_number': None, 'as_name': None}
        
        elif provider == 'ipapi':
            # ipapi.co - gratuit, 1000 req/jour
            api_key = geoip_config.get('api_key', '')
            url = f"https://ipapi.co/{ip}/json/"
            headers = {}
            if api_key:
                headers['Authorization'] = f'Bearer {api_key}'
            
            response = requests.get(url, headers=headers, timeout=5)
            response.raise_for_status()
            data = response.json()
            
            result = {
                'ip': ip,
                'country_code': data.get('country_code'),
                'country_name': data.get('country_name'),
                'country_flag': get_country_flag(data.get('country_code')),
                'as_number': data.get('asn'),
                'as_name': data.get('org')
            }
        
        else:
            result = {'ip': ip, 'country_code': None, 'country_name': None,
                     'country_flag': None, 'as_number': None, 'as_name': None}
        
        # Mettre en cache
        geoip_cache[ip] = {
            'data': result,
            'timestamp': time.time()
        }
        
        return result
    
    except Exception as e:
        print(f"⚠️ Erreur GeoIP pour {ip}: {e}")
        # Retourner des valeurs par défaut en cas d'erreur
        result = {'ip': ip, 'country_code': None, 'country_name': None,
                 'country_flag': None, 'as_number': None, 'as_name': None}
        # Ne pas mettre en cache les erreurs
        return result


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
    """Récupère la liste des alertes avec enrichissement GeoIP"""
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
        alerts = response.json()
        
        # Enrichir les alertes avec GeoIP si activé
        if config.get('geoip', {}).get('enabled', False) and isinstance(alerts, list):
            for alert in alerts:
                source_ip = alert.get('source', {}).get('value')
                if source_ip:
                    geoip_data = enrich_ip_with_geoip(source_ip)
                    alert['geoip'] = geoip_data
        
        return jsonify(alerts), response.status_code
    
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
    """Récupère la liste des machines via cscli (nécessite sudo si cscli n'est pas accessible)
    Note: Pas de JWT requis car utilise cscli, pas l'API LAPI"""
    result = run_cscli_command(['cscli', 'machines', 'list', '-o', 'json'])
    
    if result is None:
        return jsonify({'error': 'Erreur lors de la récupération des machines'}), 500
    
    # Enrichir avec les hostnames depuis la config
    hostnames = config.get('machines_hostnames', {})
    if isinstance(result, list):
        for machine in result:
            machine_id = machine.get('machineId') or machine.get('name')
            if machine_id and machine_id in hostnames:
                machine['hostname'] = hostnames[machine_id]
    
    return jsonify(result), 200


@app.route('/api/machines/<machine_id>')
def get_machine(machine_id):
    """Récupère une machine spécifique
    Note: Pas de JWT requis car utilise cscli, pas l'API LAPI"""
    result = run_cscli_command(['cscli', 'machines', 'list', '-o', 'json'])
    
    if result is None:
        return jsonify({'error': 'Erreur lors de la récupération des machines'}), 500
    
    # Trouver la machine spécifique
    machine = None
    if isinstance(result, list):
        for m in result:
            if m.get('machineId') == machine_id or m.get('name') == machine_id:
                machine = m
                break
    
    if machine is None:
        return jsonify({'error': 'Machine non trouvée'}), 404
    
    # Enrichir avec le hostname
    hostnames = config.get('machines_hostnames', {})
    machine_id_key = machine.get('machineId') or machine.get('name')
    if machine_id_key and machine_id_key in hostnames:
        machine['hostname'] = hostnames[machine_id_key]
    
    return jsonify(machine), 200


@app.route('/api/machines/<machine_id>/alerts')
@jwt_required  # Required because this endpoint queries LAPI /v1/alerts which needs JWT auth
def get_machine_alerts(machine_id):
    """Récupère les alertes d'une machine spécifique"""
    lapi_url = config['lapi']['url']
    token = get_jwt_token()
    
    try:
        headers = {'Authorization': f'Bearer {token}'}
        # Filtrer par machine_id via paramètre de requête
        params = {'machine_id': machine_id}
        response = requests.get(
            f"{lapi_url}/v1/alerts",
            headers=headers,
            params=params,
            timeout=10
        )
        response.raise_for_status()
        return jsonify(response.json()), response.status_code
    
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/bouncers')
def get_bouncers():
    """Récupère la liste des bouncers via cscli (nécessite sudo si cscli n'est pas accessible)
    Note: Pas de JWT requis car utilise cscli, pas l'API LAPI"""
    result = run_cscli_command(['cscli', 'bouncers', 'list', '-o', 'json'])
    
    if result is None:
        return jsonify({'error': 'Erreur lors de la récupération des bouncers'}), 500
    
    return jsonify(result), 200


@app.route('/api/config/hostnames')
def get_hostnames():
    """Expose le mapping machine_id -> hostname pour le frontend"""
    hostnames = config.get('machines_hostnames', {})
    return jsonify(hostnames), 200


@app.route('/api/metrics')
def get_metrics():
    """Récupère les métriques via cscli"""
    result = run_cscli_command(['cscli', 'metrics', 'show', '-o', 'json'])
    
    if result is None:
        return jsonify({'error': 'Erreur lors de la récupération des métriques'}), 500
    
    return jsonify(result), 200


@app.route('/api/enrich/ip/<ip>')
def enrich_ip(ip):
    """Enrichit une IP avec GeoIP et ASN"""
    geoip_data = enrich_ip_with_geoip(ip)
    return jsonify(geoip_data), 200


@app.route('/api/stats/alerts')
@jwt_required
def get_alerts_stats():
    """Retourne les statistiques agrégées des alertes"""
    lapi_url = config['lapi']['url']
    token = get_jwt_token()
    
    try:
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.get(
            f"{lapi_url}/v1/alerts",
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        alerts = response.json()
        
        if not isinstance(alerts, list):
            alerts = []
        
        # Enrichir les IPs
        for alert in alerts:
            source_ip = alert.get('source', {}).get('value')
            if source_ip and config.get('geoip', {}).get('enabled', False):
                alert['geoip'] = enrich_ip_with_geoip(source_ip)
        
        # Calculer les statistiques
        stats = {
            'total_alerts': len(alerts),
            'noise_canceling': 0,  # Pas encore implémenté
        }
        
        # Compter les IPs distinctes
        source_ips = [alert.get('source', {}).get('value') for alert in alerts if alert.get('source', {}).get('value')]
        ip_counts = Counter(source_ips)
        stats['unique_ips'] = len(ip_counts)
        
        # Top 3 IPs
        top_ips = []
        for ip, count in ip_counts.most_common(3):
            geoip = enrich_ip_with_geoip(ip) if config.get('geoip', {}).get('enabled', False) else {}
            top_ips.append({
                'ip': ip,
                'count': count,
                'percentage': round((count / len(alerts)) * 100, 1) if alerts else 0,
                'as_name': geoip.get('as_name', 'N/A'),
                'country': geoip.get('country_name', 'N/A'),
                'country_flag': geoip.get('country_flag', '🏴')
            })
        stats['top_ips'] = top_ips
        
        # Compter les AS distincts
        as_numbers = []
        for alert in alerts:
            geoip = alert.get('geoip', {})
            if geoip and geoip.get('as_number'):
                as_numbers.append(geoip.get('as_number'))
        as_counts = Counter(as_numbers)
        stats['unique_as'] = len(as_counts)
        
        # Top 3 AS
        top_as = []
        for as_num, count in as_counts.most_common(3):
            # Trouver un exemple d'alerte avec cet AS pour obtenir le nom
            as_name = 'N/A'
            country = 'N/A'
            country_flag = '🏴'
            for alert in alerts:
                geoip = alert.get('geoip', {})
                if geoip and geoip.get('as_number') == as_num:
                    as_name = geoip.get('as_name', 'N/A')
                    country = geoip.get('country_name', 'N/A')
                    country_flag = geoip.get('country_flag', '🏴')
                    break
            
            top_as.append({
                'as_number': as_num,
                'as_name': as_name,
                'count': count,
                'percentage': round((count / len(alerts)) * 100, 1) if alerts else 0,
                'country': country,
                'country_flag': country_flag
            })
        stats['top_as'] = top_as
        
        # Compter les pays distincts
        countries = []
        for alert in alerts:
            geoip = alert.get('geoip', {})
            if geoip and geoip.get('country_code'):
                countries.append(geoip.get('country_code'))
        country_counts = Counter(countries)
        stats['unique_countries'] = len(country_counts)
        
        # Top 3 pays
        top_countries = []
        for country_code, count in country_counts.most_common(3):
            # Trouver un exemple pour obtenir le nom complet
            country_name = 'N/A'
            country_flag = '🏴'
            for alert in alerts:
                geoip = alert.get('geoip', {})
                if geoip and geoip.get('country_code') == country_code:
                    country_name = geoip.get('country_name', 'N/A')
                    country_flag = geoip.get('country_flag', '🏴')
                    break
            
            top_countries.append({
                'country_code': country_code,
                'country_name': country_name,
                'country_flag': country_flag,
                'count': count,
                'percentage': round((count / len(alerts)) * 100, 1) if alerts else 0
            })
        stats['top_countries'] = top_countries
        
        # Top scénarios
        scenarios = [alert.get('scenario') for alert in alerts if alert.get('scenario')]
        scenario_counts = Counter(scenarios)
        stats['unique_scenarios'] = len(scenario_counts)
        
        top_scenarios = []
        for scenario, count in scenario_counts.most_common(10):
            top_scenarios.append({
                'scenario': scenario,
                'count': count,
                'percentage': round((count / len(alerts)) * 100, 1) if alerts else 0
            })
        stats['top_scenarios'] = top_scenarios
        
        # Top Security Engines (machines)
        machines = [alert.get('machine_id') for alert in alerts if alert.get('machine_id')]
        machine_counts = Counter(machines)
        stats['unique_machines'] = len(machine_counts)
        
        hostnames = config.get('machines_hostnames', {})
        top_machines = []
        for machine_id, count in machine_counts.most_common(10):
            hostname = hostnames.get(machine_id, machine_id)
            top_machines.append({
                'machine_id': machine_id,
                'hostname': hostname,
                'count': count,
                'percentage': round((count / len(alerts)) * 100, 1) if alerts else 0
            })
        stats['top_machines'] = top_machines
        
        return jsonify(stats), 200
    
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/stats/metrics')
def get_metrics_stats():
    """Retourne les métriques de trafic bloqué
    
    Note: Les estimations de ressources économisées (bytes, logs, storage)
    sont des approximations basées sur des formules arbitraires définies
    dans les constantes BYTES_PER_DECISION, LOG_LINES_PER_DECISION, etc.
    
    Les valeurs réelles peuvent varier significativement selon les types
    d'attaque, les configurations réseau et les volumes de trafic.
    Ces métriques sont fournies à titre indicatif uniquement.
    """
    decisions = fetchAPI_internal('decisions')
    
    if not decisions:
        decisions = []
    
    # Calculate estimated metrics using defined constants
    total_decisions = len(decisions)
    
    bytes_dropped = total_decisions * BYTES_PER_DECISION
    packets_dropped = total_decisions * PACKETS_PER_DECISION
    requests_dropped = 0  # No data available from API
    
    # Breakdown par origine
    origins = [d.get('origin', 'unknown') for d in decisions]
    origin_counts = Counter(origins)
    
    origin_breakdown = []
    for origin, count in origin_counts.items():
        origin_breakdown.append({
            'origin': origin,
            'count': count,
            'percentage': round((count / total_decisions) * 100, 1) if total_decisions else 0
        })
    
    # Extraction des types d'attaque depuis les scénarios
    scenarios = [d.get('scenario', '') for d in decisions if d.get('scenario')]
    attack_types = Counter()
    
    for scenario in scenarios:
        scenario_lower = scenario.lower()
        if 'brute' in scenario_lower or 'bruteforce' in scenario_lower:
            attack_types['bruteforce'] += 1
        elif 'scan' in scenario_lower:
            attack_types['scan'] += 1
        elif 'exploit' in scenario_lower:
            attack_types['exploit'] += 1
        elif 'dos' in scenario_lower or 'ddos' in scenario_lower:
            attack_types['dos'] += 1
        elif 'bot' in scenario_lower:
            attack_types['bot'] += 1
        else:
            attack_types['other'] += 1
    
    attack_distribution = []
    total_attacks = sum(attack_types.values())
    for attack_type, count in attack_types.items():
        attack_distribution.append({
            'type': attack_type,
            'count': count,
            'percentage': round((count / total_attacks) * 100, 1) if total_attacks else 0
        })
    
    # Resources saved (estimations based on constants)
    outgoing_traffic_dropped = bytes_dropped / (1024 * 1024)  # Convert to MB
    log_lines_saved = total_decisions * LOG_LINES_PER_DECISION
    storage_saved = (log_lines_saved * BYTES_PER_LOG_LINE) / 1024  # Convert to KB
    
    stats = {
        'traffic': {
            'bytes_dropped': bytes_dropped,
            'packets_dropped': packets_dropped,
            'requests_dropped': requests_dropped,
            'origin_breakdown': origin_breakdown
        },
        'attack_distribution': attack_distribution,
        'resources_saved': {
            'outgoing_traffic_mb': round(outgoing_traffic_dropped, 2),
            'log_lines': log_lines_saved,
            'storage_kb': round(storage_saved, 2)
        }
    }
    
    return jsonify(stats), 200


@app.route('/api/stats/timeline')
@jwt_required
def get_alerts_timeline():
    """Retourne les alertes groupées par heure/jour pour le graphique"""
    lapi_url = config['lapi']['url']
    token = get_jwt_token()
    
    try:
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.get(
            f"{lapi_url}/v1/alerts",
            headers=headers,
            timeout=10
        )
        response.raise_for_status()
        alerts = response.json()
        
        if not isinstance(alerts, list):
            alerts = []
        
        # Grouper par heure
        timeline = {}
        for alert in alerts:
            created_at = alert.get('created_at')
            if created_at:
                try:
                    dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                    # Arrondir à l'heure
                    hour_key = dt.strftime('%Y-%m-%d %H:00')
                    timeline[hour_key] = timeline.get(hour_key, 0) + 1
                except Exception:
                    pass
        
        # Convertir en liste triée pour Chart.js
        timeline_list = []
        for time_key in sorted(timeline.keys()):
            timeline_list.append({
                'time': time_key,
                'count': timeline[time_key]
            })
        
        return jsonify(timeline_list), 200
    
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500


def fetchAPI_internal(endpoint):
    """Fonction interne pour récupérer des données API"""
    try:
        lapi_url = config['lapi']['url']
        
        if endpoint == 'decisions':
            api_key = config['lapi']['bouncer_api_key']
            headers = {'X-Api-Key': api_key}
            response = requests.get(
                f"{lapi_url}/v1/decisions",
                headers=headers,
                timeout=10
            )
        else:
            token = get_jwt_token()
            if not token:
                return None
            headers = {'Authorization': f'Bearer {token}'}
            response = requests.get(
                f"{lapi_url}/v1/{endpoint}",
                headers=headers,
                timeout=10
            )
        
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"❌ Erreur fetchAPI_internal {endpoint}: {e}")
        return None


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
