# rust-blue-team

Petits outils de défense écrits en Rust, construits pour apprendre le langage et la logique de détection d'un SOC.

| Outil | Rôle | État |
|---|---|---|
| [`fim`](fim/) | File Integrity Monitor : détecte les fichiers modifiés, ajoutés ou supprimés | Disponible |
| `honeypot` | Faux service réseau qui journalise les tentatives de connexion | À venir |

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
git clone https://github.com/Mickaelb06/rust-blue-team.git
cd rust-blue-team
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
MODIFIÉ   cible/a.txt
AJOUTÉ    cible/sous/d.txt
SUPPRIMÉ  cible/b.txt

1 modifié(s), 1 ajouté(s), 1 supprimé(s)
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

## Licence
MIT : voir le fichier [LICENSE](LICENSE).
