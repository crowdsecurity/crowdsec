# 🛡️ Tableau de bord CrowdSec

Un tableau de bord web moderne et autonome pour CrowdSec, remplaçant `app.crowdsec.net` en interrogeant directement l'API locale (LAPI).

## ✨ Caractéristiques

- 🎨 **Interface sombre premium** inspirée de dashboardicons.com
- 🌈 **Effets visuels animés** (bande RGB, bordures arc-en-ciel au survol)
- 📊 **Vue d'ensemble en temps réel** des alertes, décisions, machines et bouncers
- 🖥️ **Vue détaillée des machines** avec alertes et décisions associées
- 🏷️ **Mapping hostname** configurable pour nommer vos machines
- 🔍 **Recherche et filtrage** des alertes et décisions
- 📍 **Indicateur de fraîcheur** pour les bouncers (actif/inactif)
- 🚀 **Application monopage (SPA)** sans dépendances externes
- 🔄 **Rafraîchissement automatique** configurable
- 🔐 **Autonome** - fonctionne entièrement hors ligne, aucune communication avec crowdsec.net

## 📋 Prérequis

- **Python 3.8+** installé
- **CrowdSec** installé et en cours d'exécution
- Accès à la commande `cscli` avec les droits nécessaires (voir note ci-dessous)

**⚠️ Note importante sur les permissions :**

Le dashboard utilise `cscli machines list` et `cscli bouncers list` pour obtenir les informations sur les machines et bouncers. Ces commandes nécessitent des droits de lecture sur `/etc/crowdsec/config.yaml`.

Vous avez deux options :

1. **Lancer le dashboard avec sudo** (recommandé pour le développement)
   ```bash
   sudo python3 app.py
   ```

2. **Ajouter votre utilisateur au groupe crowdsec** (recommandé pour la production)
   ```bash
   sudo usermod -aG crowdsec $USER
   # Puis déconnectez-vous et reconnectez-vous pour appliquer les changements
   ```

## 🚀 Installation

### 1. Cloner ou copier le répertoire dashboard

Le répertoire `dashboard/` doit se trouver à la racine du dépôt CrowdSec.

### 2. Installer les dépendances Python

```bash
cd dashboard
pip install -r requirements.txt
```

### 3. Créer les identifiants CrowdSec

#### a. Créer une machine pour l'authentification JWT

```bash
# Créer une machine dédiée au tableau de bord
sudo cscli machines add dashboard-machine -a

# Notez le mot de passe généré (ou définissez-le avec -p)
# Exemple de sortie :
# Machine 'dashboard-machine' created successfully
# API credentials:
# - Machine ID: dashboard-machine
# - Password: <votre-mot-de-passe>
```

#### b. Créer un bouncer pour interroger les décisions

```bash
# Créer un bouncer dédié au tableau de bord
sudo cscli bouncers add dashboard-bouncer

# Notez la clé API générée
# Exemple de sortie :
# API key for 'dashboard-bouncer':
# <votre-cle-api-bouncer>
```

### 4. Configurer le tableau de bord

Copiez le fichier de configuration d'exemple et remplissez vos identifiants :

```bash
cp config.example.yaml config.yaml
nano config.yaml  # ou utilisez votre éditeur préféré
```

Modifiez les valeurs suivantes dans `config.yaml` :

```yaml
lapi:
  url: "http://127.0.0.1:8080"  # URL de votre LAPI (par défaut)
  machine_id: "dashboard-machine"  # ID de la machine créée à l'étape 3a
  machine_password: "votre-mot-de-passe"  # Mot de passe de l'étape 3a
  bouncer_api_key: "votre-cle-api-bouncer"  # Clé API de l'étape 3b

dashboard:
  host: "0.0.0.0"  # Écoute sur toutes les interfaces (ou "127.0.0.1" pour localhost uniquement)
  port: 3000  # Port d'écoute du tableau de bord
  refresh_interval: 30  # Intervalle de rafraîchissement en secondes

# Optionnel : Mapping des machine_id vers des noms personnalisés
machines_hostnames:
  # Trouvez vos machine_id avec: sudo cscli machines list
  # "machine-id-long": "MonServeur"
  # "another-machine": "Serveur-Web"
```

**⚠️ Sécurité :** Assurez-vous que `config.yaml` n'est pas accessible publiquement (les permissions recommandées sont `600`).

```bash
chmod 600 config.yaml
```

## 🎯 Utilisation

### Démarrage manuel

```bash
cd dashboard
# Si vous avez ajouté votre utilisateur au groupe crowdsec :
python app.py

# Sinon, utilisez sudo :
sudo python app.py
```

Le tableau de bord sera accessible à l'adresse : **http://localhost:3000**

Vous verrez une sortie similaire à :

```
============================================================
🛡️  Tableau de bord CrowdSec
============================================================
✅ Configuration chargée avec succès

🚀 Démarrage du serveur sur http://0.0.0.0:3000
📊 Accédez au tableau de bord : http://localhost:3000
```

### Configuration en tant que service systemd

Pour démarrer automatiquement le tableau de bord au démarrage du système :

#### 1. Créer le fichier de service

```bash
sudo nano /etc/systemd/system/crowdsec-dashboard.service
```

Ajoutez le contenu suivant (adaptez les chemins si nécessaire) :

```ini
[Unit]
Description=CrowdSec Dashboard
After=network.target crowdsec.service
Requires=crowdsec.service

[Service]
Type=simple
# Note: Remplacez 'crowdsec' par l'utilisateur approprié sur votre système
# Pour vérifier si l'utilisateur crowdsec existe : getent passwd crowdsec
# Vous pouvez aussi utiliser votre utilisateur actuel ou créer un utilisateur dédié
User=crowdsec
Group=crowdsec
WorkingDirectory=/chemin/vers/crowdsec/dashboard
ExecStart=/usr/bin/python3 /chemin/vers/crowdsec/dashboard/app.py
Restart=on-failure
RestartSec=10

# Sécurité
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/chemin/vers/crowdsec/dashboard

[Install]
WantedBy=multi-user.target
```

**Note :** Remplacez `/chemin/vers/crowdsec/dashboard` par le chemin absolu réel.

#### 2. Activer et démarrer le service

```bash
# Recharger la configuration systemd
sudo systemctl daemon-reload

# Activer le service au démarrage
sudo systemctl enable crowdsec-dashboard

# Démarrer le service
sudo systemctl start crowdsec-dashboard

# Vérifier le statut
sudo systemctl status crowdsec-dashboard

# Voir les logs
sudo journalctl -u crowdsec-dashboard -f
```

## 📱 Interface utilisateur

Le tableau de bord comprend 5 pages principales :

### 1. 🏠 Vue d'ensemble (`#/`)

- 4 cartes de statistiques : Total des alertes, Décisions actives (avec détail par type : ban/captcha/throttle), Machines en ligne, Bouncers actifs
- Mini-cartes cliquables des 4 premières machines (avec hostname si configuré)
- Tableau des alertes récentes (20 dernières) avec la machine source
- Tableau des décisions actives
- Rafraîchissement automatique toutes les 30 secondes (configurable)

### 2. 🚨 Alertes (`#/alerts`)

- Barre de recherche avec bande RGB animée
- Liste complète des alertes
- Affichage du hostname de la machine source (si configuré)
- Filtrage par scénario, IP source, date
- Détails extensibles de chaque alerte (clic sur "Détails")
- Suppression d'alertes (clic sur "Supprimer")

### 3. ⚖️ Décisions (`#/decisions`)

- Barre de recherche avec bande RGB animée
- Liste des décisions actives (bans, captchas, throttles)
- Badges de couleur par type :
  - 🔴 **Ban** (rouge)
  - 🟠 **Captcha** (ambre)
  - 🔵 **Throttle** (bleu)
- Suppression de décisions

### 4. 🖥️ Machines (`#/machines`)

- Grille de cartes pour chaque machine (cliquables)
- **Hostname personnalisé** affiché en gros (si configuré) avec machine_id en dessous
- État (validée / en attente)
- IP, version, dernière mise à jour
- Effet de bordure arc-en-ciel au survol
- **Clic sur une carte** pour accéder à la vue détaillée

#### Vue détaillée d'une machine (`#/machines/<machine_id>`)

- En-tête avec hostname, machine_id et statut de validation
- 6 informations détaillées : IP, version, OS, type d'authentification, dernière mise à jour, date d'enregistrement
- **Tableau des alertes de cette machine** avec possibilité de suppression
- **Tableau des décisions associées** aux alertes de cette machine
- Bouton retour vers la liste des machines

### 5. 🛡️ Bouncers (`#/bouncers`)

- Grille de cartes pour chaque bouncer
- **Indicateur de fraîcheur** avec code couleur :
  - 🟢 **Actif** (< 5 minutes)
  - 🟡 **Avertissement** (< 30 minutes)
  - 🔴 **Inactif** (> 30 minutes)
- Type d'authentification, IP, dernière activité
- Version du bouncer
- Effet de bordure arc-en-ciel au survol

## 🎨 Design

Le tableau de bord s'inspire fortement de [dashboardicons.com](https://dashboardicons.com/) :

- **Thème sombre** avec fond `#0a0a0a`, cartes `#1a1a1a`
- **Bande RGB animée** sous les barres de recherche
- **Bordures arc-en-ciel animées** au survol des cartes (effet conic-gradient)
- **Typographie Inter** (Google Fonts)
- **Transitions fluides** (0.2-0.3s ease)
- **Design minimaliste** avec espaces généreux

## 🏗️ Architecture

```
┌─────────────────┐
│   Navigateur    │
│   (SPA HTML)    │
└────────┬────────┘
         │ HTTP
         ▼
┌─────────────────┐
│  Flask Backend  │
│    (Proxy)      │
└────┬───────┬────┘
     │       │
     │       ├─────► cscli (machines, bouncers, metrics)
     │       │
     ▼       ▼
┌─────────────────┐
│  CrowdSec LAPI  │
│  (Local API)    │
└─────────────────┘
```

### Backend (app.py)

- **Proxy LAPI** : Transmet les requêtes du navigateur vers l'API CrowdSec
- **Authentification JWT** : Se connecte comme une machine pour les endpoints `/v1/alerts`
- **Authentification API Key** : Utilise une clé bouncer pour `/v1/decisions`
- **Cache de token** : Renouvelle le JWT uniquement lorsqu'il expire
- **Appels cscli** : Exécute `cscli` en sous-processus pour machines/bouncers/metrics (nécessite les permissions appropriées)
- **Enrichissement hostname** : Injecte les hostnames configurés dans les réponses machines

### Frontend (index.html)

- **Application monopage** : Tout dans un seul fichier HTML (CSS + JS inclus)
- **Routage hash** : Navigation via `#/page` (pas de rechargement de page)
- **Vanilla JavaScript** : Aucune dépendance externe (pas de React, Vue, etc.)
- **CSS moderne** : Animations, gradients, propriétés CSS personnalisées
- **Responsive** : Fonctionne sur desktop et tablette

## 🔒 Sécurité

### Bonnes pratiques

1. **Permissions du fichier de configuration**
   ```bash
   chmod 600 config.yaml
   ```

2. **Écoute sur localhost uniquement** (si pas besoin d'accès distant)
   ```yaml
   dashboard:
     host: "127.0.0.1"
   ```

3. **Reverse proxy recommandé** pour l'exposition publique
   - Utilisez Nginx ou Apache avec HTTPS
   - Ajoutez une authentification basique
   - Limitez l'accès par IP

4. **Pare-feu**
   ```bash
   # Autoriser uniquement localhost
   sudo ufw deny 3000
   sudo ufw allow from 127.0.0.1 to any port 3000
   ```

### Exemple de configuration Nginx avec HTTPS

```nginx
server {
    listen 443 ssl http2;
    server_name dashboard.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        
        # Authentification basique
        auth_basic "CrowdSec Dashboard";
        auth_basic_user_file /etc/nginx/.htpasswd;
    }
}
```

## 🐛 Dépannage

### Le serveur ne démarre pas

**Problème** : `Erreur lors de l'authentification JWT`

**Solution** : Vérifiez que :
- La machine existe : `sudo cscli machines list`
- Les identifiants dans `config.yaml` sont corrects
- Le LAPI est accessible : `curl http://127.0.0.1:8080/health`

### Aucune donnée n'apparaît

**Problème** : Les tableaux sont vides

**Solution** :
1. Vérifiez que CrowdSec génère des alertes : `sudo cscli alerts list`
2. Vérifiez les logs du tableau de bord : `journalctl -u crowdsec-dashboard -f`
3. Vérifiez la console du navigateur (F12) pour les erreurs JavaScript

### Erreur de permission cscli

**Problème** : `Erreur lors de la récupération des machines`

**Solution** : L'utilisateur qui exécute `app.py` doit avoir les permissions pour exécuter `cscli`.
- Ajoutez l'utilisateur au groupe `crowdsec` : `sudo usermod -aG crowdsec <utilisateur>`
- Ou exécutez avec `sudo` (non recommandé en production)

### Port déjà utilisé

**Problème** : `Address already in use`

**Solution** : Changez le port dans `config.yaml` ou arrêtez le service utilisant le port 3000 :
```bash
sudo lsof -i :3000
sudo systemctl stop <service>
```

## 📝 Notes de développement

### Structure des fichiers

```
dashboard/
├── app.py                    # Backend Flask
├── config.yaml               # Configuration (à créer)
├── config.example.yaml       # Configuration d'exemple
├── requirements.txt          # Dépendances Python
├── README.md                 # Ce fichier
└── templates/
    └── index.html            # Frontend SPA
```

### API exposées par le backend

| Route | Méthode | Description |
|-------|---------|-------------|
| `/` | GET | Sert le SPA |
| `/api/health` | GET | État du LAPI |
| `/api/alerts` | GET | Liste des alertes (JWT, supporte `?machine_id=xxx`) |
| `/api/alerts/<id>` | GET | Détail d'une alerte (JWT) |
| `/api/alerts/<id>` | DELETE | Supprime une alerte (JWT) |
| `/api/decisions` | GET | Liste des décisions (API Key) |
| `/api/decisions/<id>` | DELETE | Supprime une décision (JWT) |
| `/api/machines` | GET | Liste des machines (cscli, enrichi avec hostnames) |
| `/api/machines/<machine_id>` | GET | Détail d'une machine (cscli, enrichi avec hostname) |
| `/api/machines/<machine_id>/alerts` | GET | Alertes d'une machine (JWT) |
| `/api/bouncers` | GET | Liste des bouncers (cscli) |
| `/api/config/hostnames` | GET | Mapping machine_id → hostname |
| `/api/metrics` | GET | Métriques (cscli) |

## 🤝 Contribution

Les contributions sont les bienvenues ! Pour proposer des améliorations :

1. Fork le dépôt
2. Créez une branche (`git checkout -b feature/amelioration`)
3. Committez vos changements (`git commit -m 'Ajout d'une amélioration'`)
4. Pushez vers la branche (`git push origin feature/amelioration`)
5. Ouvrez une Pull Request

## 📄 Licence

Ce projet suit la licence du projet CrowdSec principal.

## 🙏 Remerciements

- Design inspiré de [dashboardicons.com](https://dashboardicons.com/)
- Propulsé par [CrowdSec](https://www.crowdsec.net/)
- Typographie : [Inter](https://rsms.me/inter/)

---

**Développé avec ❤️ pour la communauté CrowdSec**
