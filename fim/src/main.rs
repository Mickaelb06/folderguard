//! FIM : File Integrity Monitor.
//!
//! Usage :
//!   fim init  <dossier> [baseline]   crée la référence (hash de chaque fichier)
//!   fim check <dossier> [baseline]   compare l'état actuel à la référence
//!
//! Les chemins de la référence sont relatifs au dossier surveillé : on peut donc
//! lancer `check` avec `./cible` ou `/home/moi/cible`, le résultat est le même.
//!
//! Code de sortie : 0 = aucun changement, 1 = changements ou fichiers illisibles, 2 = erreur.

use std::collections::{BTreeMap, BTreeSet}; // dictionnaire / ensemble triés (sortie toujours dans le même ordre)
use std::env; // pour lire les arguments de la ligne de commande
use std::fs::{self, File}; // fs = lire des dossiers ; File = ouvrir un fichier
use std::io::{self, BufRead, BufReader, Read, Write}; // outils de lecture/écriture
use std::path::{Path, PathBuf}; // Path = chemin emprunté, PathBuf = chemin possédé
use std::process; // pour quitter avec un code de sortie précis

use sha2::{Digest, Sha256}; // Sha256 = l'algorithme ; Digest = les méthodes new/update/finalize

/// Un alias de type : "Empreintes" = dictionnaire chemin relatif -> hash SHA-256 (en hexadécimal).
type Empreintes = BTreeMap<String, String>;

/// Résultat d'un parcours : les hashes calculés + les chemins qu'on n'a pas pu lire.
#[derive(Default)] // Default : permet de créer un Scan vide avec Scan::default()
struct Scan {
    empreintes: Empreintes,
    illisibles: BTreeSet<String>,
}

/// Calcule le SHA-256 d'un fichier en le lisant par petits blocs.
fn hash_fichier(chemin: &Path) -> io::Result<String> {
    let fichier = File::open(chemin)?; // le `?` renvoie l'erreur à l'appelant si ça échoue
    let mut lecteur = BufReader::new(fichier);
    let mut hasher = Sha256::new();
    let mut tampon = [0u8; 8192]; // tampon réutilisé : pas de gros fichier en RAM
    loop {
        let n = lecteur.read(&mut tampon)?; // n = nombre d'octets réellement lus
        if n == 0 {
            break; // 0 octet lu = fin du fichier
        }
        hasher.update(&tampon[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Chemin de `chemin` relatif à `racine`, en texte (ex. "sous/d.txt").
fn relatif(racine: &Path, chemin: &Path) -> String {
    let rel = chemin.strip_prefix(racine).unwrap_or(chemin); // retire le début commun
    rel.to_string_lossy().into_owned() // les noms non UTF-8 sont affichés avec des "�"
}

/// Parcourt `dossier` récursivement et remplit `scan`.
/// `racine` = dossier surveillé (pour les chemins relatifs), `ignorer` = chemin complet de la référence.
fn parcourir(racine: &Path, dossier: &Path, ignorer: &Path, scan: &mut Scan) -> io::Result<()> {
    for entree in fs::read_dir(dossier)? {
        let entree = entree?;
        let chemin = entree.path();
        let genre = entree.file_type()?; // type de l'entrée, SANS suivre les liens symboliques

        if genre.is_symlink() {
            continue; // on ignore les liens symboliques (évite les boucles et les sorties du dossier)
        }
        if genre.is_dir() {
            if let Err(e) = parcourir(racine, &chemin, ignorer, scan) {
                eprintln!("Avertissement : dossier illisible {} ({e})", chemin.display());
                scan.illisibles.insert(relatif(racine, &chemin)); // tout son contenu sera "illisible"
            }
        } else if genre.is_file() {
            // On saute UNIQUEMENT la référence elle-même (comparaison du chemin complet,
            // pas du nom : un autre fichier appelé pareil reste surveillé).
            if chemin == ignorer {
                continue;
            }
            let rel = relatif(racine, &chemin);
            match hash_fichier(&chemin) {
                Ok(h) => {
                    scan.empreintes.insert(rel, h);
                }
                Err(e) => {
                    eprintln!("Avertissement : fichier illisible {} ({e})", chemin.display());
                    scan.illisibles.insert(rel);
                }
            }
        }
    }
    Ok(())
}

/// Protège un chemin pour tenir sur une seule ligne : `\` -> `\\`, retour à la ligne -> `\n`.
fn echapper(chemin: &str) -> String {
    chemin.replace('\\', "\\\\").replace('\n', "\\n").replace('\r', "\\r")
}

/// Opération inverse de `echapper`.
fn desechapper(texte: &str) -> String {
    let mut sortie = String::new();
    let mut caracteres = texte.chars();
    while let Some(c) = caracteres.next() {
        if c != '\\' {
            sortie.push(c);
            continue;
        }
        match caracteres.next() {
            Some('n') => sortie.push('\n'),
            Some('r') => sortie.push('\r'),
            Some(autre) => sortie.push(autre), // `\\` -> `\`
            None => sortie.push('\\'),
        }
    }
    sortie
}

/// Écrit la référence : une ligne par fichier, "hash  chemin" (proche du format de sha256sum).
/// On écrit d'abord dans un fichier temporaire puis on renomme : jamais de référence à moitié écrite.
fn sauvegarder(baseline: &Path, empreintes: &Empreintes) -> io::Result<()> {
    let mut temporaire = baseline.as_os_str().to_owned();
    temporaire.push(".tmp");
    let temporaire = PathBuf::from(temporaire);
    {
        let mut f = File::create(&temporaire)?;
        for (chemin, hash) in empreintes {
            writeln!(f, "{hash}  {}", echapper(chemin))?;
        }
        f.sync_all()?; // force l'écriture sur le disque
    }
    fs::rename(&temporaire, baseline) // remplacement quasi instantané
}

/// Relit la référence. Une ligne mal formée est une erreur (une référence corrompue ne doit pas passer en silence).
fn charger(baseline: &Path) -> io::Result<Empreintes> {
    let mut empreintes = Empreintes::new();
    let f = File::open(baseline)?;
    for (numero, ligne) in BufReader::new(f).lines().enumerate() {
        let ligne = ligne?;
        let hash_valide = |h: &str| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit());
        match ligne.split_once("  ") {
            Some((hash, chemin)) if hash_valide(hash) => {
                empreintes.insert(desechapper(chemin), hash.to_string());
            }
            _ => {
                let message = format!("ligne {} mal formée dans la référence", numero + 1);
                return Err(io::Error::new(io::ErrorKind::InvalidData, message));
            }
        }
    }
    Ok(empreintes)
}

/// Un chemin est "couvert" par un illisible s'il est égal à lui ou situé dans ce dossier.
fn est_illisible(chemin: &str, illisibles: &BTreeSet<String>) -> bool {
    illisibles
        .iter()
        .any(|i| chemin == i || Path::new(chemin).starts_with(i))
}

/// Compare l'ancien et le nouvel état. Renvoie (modifiés, ajoutés, supprimés, illisibles).
/// Un fichier illisible n'est jamais déclaré "supprimé" : on ne sait pas, on le dit.
fn comparer(
    ancien: &Empreintes,
    nouveau: &Empreintes,
    illisibles: &BTreeSet<String>,
) -> (Vec<String>, Vec<String>, Vec<String>, Vec<String>) {
    let mut modifies = Vec::new();
    let mut ajoutes = Vec::new();
    let mut supprimes = Vec::new();
    let mut inconnus = Vec::new();

    for (chemin, hash) in nouveau {
        match ancien.get(chemin) {
            Some(ancien_hash) if ancien_hash != hash => modifies.push(chemin.clone()),
            Some(_) => {}
            None => ajoutes.push(chemin.clone()),
        }
    }
    for chemin in ancien.keys() {
        if nouveau.contains_key(chemin) {
            continue;
        }
        if est_illisible(chemin, illisibles) {
            inconnus.push(chemin.clone()); // présent dans la référence mais impossible à relire
        } else {
            supprimes.push(chemin.clone());
        }
    }
    (modifies, ajoutes, supprimes, inconnus)
}

/// Affiche l'aide et quitte avec le code 2.
fn usage() -> ! {
    eprintln!("Usage :\n  fim init  <dossier> [baseline]\n  fim check <dossier> [baseline]");
    process::exit(2);
}

/// Chemin absolu de la référence, même si elle n'existe pas encore (on canonicalise son dossier).
fn chemin_baseline(baseline: &Path) -> io::Result<PathBuf> {
    let parent = match baseline.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let nom = baseline
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "nom de référence invalide"))?;
    Ok(fs::canonicalize(parent)?.join(nom))
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        usage();
    }
    let commande = args[1].as_str();
    let baseline = Path::new(args.get(3).map(String::as_str).unwrap_or("fim-baseline.txt"));

    // On travaille sur des chemins absolus pour que les comparaisons soient fiables.
    let racine = match fs::canonicalize(&args[2]) {
        Ok(r) if r.is_dir() => r,
        _ => {
            eprintln!("Erreur : {} n'est pas un dossier", args[2]);
            process::exit(2);
        }
    };
    let baseline_abs = match chemin_baseline(baseline) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Erreur : référence {} inutilisable ({e})", baseline.display());
            process::exit(2);
        }
    };

    let mut scan = Scan::default();
    if let Err(e) = parcourir(&racine, &racine, &baseline_abs, &mut scan) {
        eprintln!("Erreur : {e}");
        process::exit(2);
    }

    match commande {
        "init" => {
            if let Err(e) = sauvegarder(baseline, &scan.empreintes) {
                eprintln!("Erreur d'écriture de la référence : {e}");
                process::exit(2);
            }
            println!("Référence créée : {} fichiers -> {}", scan.empreintes.len(), baseline.display());
            if !scan.illisibles.is_empty() {
                eprintln!("Attention : {} élément(s) illisible(s) absents de la référence", scan.illisibles.len());
                process::exit(1);
            }
        }
        "check" => {
            let ancien = match charger(baseline) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("Impossible de lire la référence {} ({e}). Lance d'abord `fim init`.", baseline.display());
                    process::exit(2);
                }
            };
            let (modifies, ajoutes, supprimes, inconnus) = comparer(&ancien, &scan.empreintes, &scan.illisibles);
            for c in &modifies {
                println!("MODIFIÉ   {c}");
            }
            for c in &ajoutes {
                println!("AJOUTÉ    {c}");
            }
            for c in &supprimes {
                println!("SUPPRIMÉ  {c}");
            }
            for c in &inconnus {
                println!("ILLISIBLE {c}");
            }
            // Tout élément illisible est une anomalie, qu'il figure ou non dans la référence.
            if modifies.is_empty()
                && ajoutes.is_empty()
                && supprimes.is_empty()
                && scan.illisibles.is_empty()
            {
                println!("OK : aucun changement ({} fichiers vérifiés)", scan.empreintes.len());
            } else {
                println!(
                    "\n{} modifié(s), {} ajouté(s), {} supprimé(s), {} illisible(s)",
                    modifies.len(),
                    ajoutes.len(),
                    supprimes.len(),
                    scan.illisibles.len()
                );
                process::exit(1);
            }
        }
        _ => usage(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn emp(paires: &[(&str, &str)]) -> Empreintes {
        paires.iter().map(|(c, h)| (c.to_string(), h.to_string())).collect()
    }

    #[test]
    fn detecte_modifie_ajoute_supprime() {
        let ancien = emp(&[("a", "1"), ("b", "2"), ("c", "3")]);
        let nouveau = emp(&[("a", "1"), ("b", "X"), ("d", "4")]);
        let (m, a, s, i) = comparer(&ancien, &nouveau, &BTreeSet::new());
        assert_eq!((m, a, s, i), (vec!["b".into()], vec!["d".into()], vec!["c".into()], vec![]));
    }

    #[test]
    fn illisible_nest_pas_supprime() {
        let ancien = emp(&[("dossier/x", "1"), ("autre", "2")]);
        let nouveau = emp(&[]);
        let illisibles: BTreeSet<String> = ["dossier".to_string()].into();
        let (_, _, s, i) = comparer(&ancien, &nouveau, &illisibles);
        assert_eq!(s, vec!["autre".to_string()]);
        assert_eq!(i, vec!["dossier/x".to_string()]);
    }

    #[test]
    fn echappement_aller_retour() {
        let chemin = "bizarre\nnom\\avec\rtout";
        assert_eq!(desechapper(&echapper(chemin)), chemin);
        assert!(!echapper(chemin).contains('\n'));
    }
}
