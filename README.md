# FolderGuard

Petits outils de défense, construits pour apprendre la logique de détection d'un SOC : un outil en ligne de commande écrit en Rust et un site web pour contrôler un dossier.

**Site : https://mickaelb06.github.io/folderguard/**

| Outil | Rôle | État |
|---|---|---|
| [`fim`](fim/) | File Integrity Monitor en ligne de commande : détecte les fichiers modifiés, ajoutés ou supprimés | Disponible |
| [Site web](https://mickaelb06.github.io/folderguard/) | Même contrôle dans le navigateur : on dépose un dossier, rien n'est envoyé (code dans [`docs/`](docs/)) | Disponible |
| [`honeypot`](honeypot/) | Faux service réseau qui journalise les tentatives de connexion | Disponible |

## Site web

Le dossier [`docs/`](docs/) contient une page unique (HTML et JavaScript, sans serveur), publiée avec GitHub Pages. On y dépose un dossier : le navigateur calcule le SHA-256 de chaque fichier, garde une « photo » et la compare aux dépôts suivants. Les fichiers ne quittent jamais l'ordinateur. La photo est stockée dans le navigateur ; elle est propre à ce site et n'est pas partagée avec l'outil `fim`.

## fim

### Principe
1. `fim init` parcourt un dossier et enregistre le **SHA-256** de chaque fichier dans une référence (baseline).
2. `fim check` recalcule les hashes et les compare à la référence, puis signale :
   - `MODIFIÉ` : même chemin, contenu différent ;
   - `AJOUTÉ` : fichier absent de la référence ;
   - `SUPPRIMÉ` : fichier présent dans la référence mais disparu ;
   - `ILLISIBLE` : fichier ou dossier impossible à relire (permissions) : on ne prétend pas qu'il a disparu.

Les chemins de la référence sont relatifs au dossier surveillé : `./cible` et `/chemin/absolu/cible` donnent le même résultat. Une référence mal formée fait échouer `check` (code 2) au lieu d'être lue partiellement.

### Installation
```bash
# Installer Rust si besoin : https://rustup.rs
git clone https://github.com/Mickaelb06/folderguard.git
cd folderguard
cargo test
cargo build --release
# le binaire est dans target/release/fim
```

### Utilisation
```bash
./target/release/fim init  /chemin/a/surveiller baseline.txt
./target/release/fim check /chemin/a/surveiller baseline.txt
```

Exemple de sortie après des changements :
```
MODIFIÉ   a.txt
AJOUTÉ    sous/d.txt
SUPPRIMÉ  b.txt

1 modifié(s), 1 ajouté(s), 1 supprimé(s), 0 illisible(s)
```

Codes de sortie : `0` aucun changement, `1` changements ou éléments illisibles, `2` erreur. Le code `1` permet de brancher l'outil dans un script ou une tâche planifiée.

### Limites connues
- **La référence doit être protégée.** Si un attaquant peut la modifier, il peut masquer ses changements. Garde-la hors du dossier surveillé, en lecture seule, ou sur un autre support.
- Les liens symboliques sont ignorés.
- Seul le contenu est vérifié, pas les permissions ni le propriétaire.
- Seul le fichier de référence lui-même est exclu du scan (par chemin complet, pas par nom).
- Contrôle à la demande : ce n'est pas une surveillance en temps réel.

### Lien avec MITRE ATT&CK
Ce type d'outil aide à détecter notamment :
- T1565.001 Data Manipulation: Stored Data Manipulation
- T1070.004 Indicator Removal: File Deletion
- T1554 Compromise Host Software Binary

### Pistes d'amélioration
- Sortie JSON et journalisation dans un fichier.
- Exclusions par motif (par exemple `*.log`).
- Vérification des permissions.
- Surveillance en temps réel avec les notifications du système de fichiers.

## honeypot

### Principe
Un honeypot est un leurre : un faux service que personne n'a de raison légitime d'utiliser. Toute connexion est donc suspecte. Celui-ci écoute sur un port, note ce que le visiteur tente, **refuse toujours l'accès** puis ferme la connexion. Il n'ouvre jamais de terminal et n'exécute jamais rien.

Deux services :
- `ssh` : un **vrai serveur SSH** (bibliothèque [`russh`](https://crates.io/crates/russh)). Il parle le vrai protocole, donc les scanners et les clients ordinaires s'y connectent normalement. Le journal contient les **identifiants et mots de passe** essayés et l'**empreinte des clés publiques** proposées. Il s'annonce comme un OpenSSH sur Ubuntu.
- `telnet` : un faux écran de connexion (identifiant puis mot de passe, toujours refusé, 3 essais), sans dépendance.

C'est un honeypot « à faible interaction » : l'attaquant n'obtient jamais de terminal. Les outils comme Cowrie vont plus loin avec un faux système de fichiers, ce qui permet d'enregistrer les commandes tapées.

### Utilisation
```bash
cargo build --release
./target/release/honeypot [port] [telnet|ssh] [journal] [clé_ssh]
# exemples :
./target/release/honeypot 2222 ssh                # SSH sur le port 2222
./target/release/honeypot 2323 telnet honeypot.log
```
Par défaut : port `2323`, service `telnet`, journal `honeypot.log`, clé du serveur `honeypot_host_key`.

Pour tester le service `ssh` depuis une autre fenêtre :
```bash
ssh -p 2222 admin@127.0.0.1     # tape un mot de passe : il sera refusé et noté
```
La clé du serveur est créée au premier lancement (permissions `0600`) et gardée ensuite : une clé qui change à chaque démarrage trahirait le leurre. **Ne la publie jamais** (elle est exclue par le `.gitignore`).

### Journal
Une ligne JSON par événement (`connexion`, `tentative`, `cle_publique`, `fermeture`) :
```json
{"ts":"2026-10-11T15:47:59Z","ip":"203.0.113.7","port":2222,"service":"ssh","evenement":"tentative","identifiant":"admin","mot_de_passe":"MotDePasse123"}
```
Tout ce que le visiteur envoie est échappé : il ne peut pas casser le format du journal.

### Précautions
- Ne l'expose pas sur Internet depuis ton réseau personnel sans isoler la machine (VM, conteneur ou serveur dédié) : un programme exposé reste une surface d'attaque, et `russh` est une dépendance externe à garder à jour.
- Ne l'installe jamais sur le port 22 d'une machine que tu administres par SSH. Les ports inférieurs à 1024 demandent des droits administrateur : garde un port élevé et redirige-le depuis le pare-feu.
- Le journal contient des adresses IP : il est exclu de Git par le `.gitignore`.
- Limites : 50 visiteurs simultanés, 120 secondes par session, 30 secondes d'inactivité, 6 essais par connexion SSH.

### Tableau de bord
La page [`docs/honeypot.html`](docs/honeypot.html) (en ligne : https://mickaelb06.github.io/folderguard/honeypot.html) lit le journal : on dépose `honeypot.log` et elle affiche les connexions par heure, les adresses les plus actives, les identifiants et mots de passe les plus testés. Le fichier reste dans le navigateur. Un bouton charge des données d'exemple.

### Lien avec MITRE ATT&CK
- T1110 Brute Force (identifiants testés)
- T1046 Network Service Discovery (scans de ports)
- T1078 Valid Accounts (identifiants volés réutilisés)

### Pistes d'amélioration
- Faux terminal qui enregistre les commandes (comme Cowrie).
- Autres faux services (HTTP, FTP, base de données).
- Blocage ou alerte après N tentatives.

## Licence
MIT : voir le fichier [LICENSE](LICENSE).
