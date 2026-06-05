# AI-IDS Dashboard

Dashboard React + Node.js pour le système AI-IDS.

## Architecture

```
React (port 3000)  ←→  Node.js Express (port 3001)  ←→  MongoDB (port 27017)
                                                              ↑
                                                      Python IDS (manager.py)
```

## Installation

### Prérequis
- Node.js 18+
- MongoDB (optionnel — mock data si absent)

### Backend
```bash
cd backend
npm install
node server.js
```

### Frontend (développement)
```bash
cd frontend
npm install
npm run dev
# → http://localhost:3000
```

### Frontend (production)
```bash
cd frontend
npm run build
# Servir dist/ avec nginx ou vite preview
```

## MongoDB (Kali Linux)

```bash
sudo apt install mongodb
sudo systemctl start mongodb
sudo systemctl enable mongodb

pip install pymongo --break-system-packages
sudo pip install pymongo --break-system-packages
```

> Si MongoDB est absent, le backend utilise automatiquement des données mock
> avec alertes live simulées toutes les 4 secondes.

## Pages

| Page | Route | Description |
|------|-------|-------------|
| Live Feed | `/` | Alertes en temps réel avec WebSocket |
| Statistics | — | Charts par type, sévérité, timeline 24h |
| Detectors | — | 7 cartes avec config live + reset |
| Threat Map | — | IPs attaquantes avec détail expandable |
| System Health | — | Paquets, MongoDB, modèles AI |

## API Endpoints

```
GET  /api/alerts?limit=50&severity=HIGH    → alertes récentes
GET  /api/alerts/stats                     → counts par type/sévérité
GET  /api/alerts/top-ips                   → top IPs attaquantes
GET  /api/detectors                        → statut 7 détecteurs
PUT  /api/detectors/:name/config           → mise à jour threshold live
POST /api/detectors/:name/reset            → reset état détecteur
GET  /api/system/stats                     → stats système
WS   ws://localhost:3001                   → stream alertes live
```

## Notes

- Le backend se connecte à `mongodb://localhost:27017/ai_ids` (collection `alerts`)
- En mode mock, des alertes sont générées toutes les 4 secondes
- Les WebSockets reconnectent automatiquement si la connexion est perdue
- Le frontend proxie `/api` et `/ws` vers le backend via Vite (dev mode)
