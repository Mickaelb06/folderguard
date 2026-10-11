//! Honeypot : faux service réseau qui journalise les tentatives de connexion.
//!
//! Usage :
//!   honeypot [port] [service] [journal]
//!     port     port d'écoute (défaut : 2323)
//!     service  `telnet` (faux écran de connexion) ou `ssh` (fausse bannière) (défaut : telnet)
//!     journal  fichier de journal, une ligne JSON par événement (défaut : honeypot.log)
//!
//! Le honeypot ne donne JAMAIS accès à rien : il affiche un écran, note ce que le visiteur
//! envoie, puis ferme la connexion. Aucune commande n'est exécutée.

use std::io::{BufRead, BufReader, Read, Write}; // lecture/écriture sur le réseau et les fichiers
use std::fs::OpenOptions; // pour ouvrir le journal en mode "ajout"
use std::net::{TcpListener, TcpStream}; // serveur TCP et connexion d'un visiteur
use std::process; // pour quitter avec un code de sortie précis
use std::sync::atomic::{AtomicUsize, Ordering}; // compteur partagé entre les threads
use std::sync::{Arc, Mutex}; // Arc = partage entre threads ; Mutex = un seul écrivain à la fois
use std::thread; // un thread par visiteur
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Nombre maximum de visiteurs traités en même temps (évite de saturer la machine).
const MAX_CONNEXIONS: usize = 50;
/// Délai maximum d'attente d'une réponse du visiteur (évite les connexions qui traînent).
const DELAI: Duration = Duration::from_secs(20);
/// Nombre maximum d'octets lus pour une ligne (évite qu'un visiteur nous envoie un flot de données).
const MAX_LIGNE: u64 = 256;
/// Nombre d'essais de connexion proposés avant de fermer.
const ESSAIS: usize = 3;

#[derive(Clone, Copy, PartialEq)]
enum Service {
    Telnet,
    Ssh,
}

impl Service {
    fn nom(self) -> &'static str {
        match self {
            Service::Telnet => "telnet",
            Service::Ssh => "ssh",
        }
    }
}

/// Le journal : un fichier partagé, protégé par un Mutex pour que deux visiteurs n'écrivent pas en même temps.
struct Journal {
    fichier: Mutex<std::fs::File>,
}

impl Journal {
    /// Écrit une ligne JSON : {"ts":"...","ip":"...","port":2323,"service":"telnet","evenement":"...", ...champs}
    fn ecrire(&self, ip: &str, port: u16, service: Service, evenement: &str, champs: &[(&str, &str)]) {
        let mut ligne = format!(
            "{{\"ts\":\"{}\",\"ip\":\"{}\",\"port\":{},\"service\":\"{}\",\"evenement\":\"{}\"",
            horodatage(maintenant()),
            echapper_json(ip),
            port,
            service.nom(),
            echapper_json(evenement)
        );
        for (cle, valeur) in champs {
            ligne.push_str(&format!(",\"{}\":\"{}\"", echapper_json(cle), echapper_json(valeur)));
        }
        ligne.push_str("}\n");
        print!("{ligne}"); // on affiche aussi à l'écran pour voir en direct
        if let Ok(mut f) = self.fichier.lock() {
            let _ = f.write_all(ligne.as_bytes()); // si l'écriture échoue, on continue de servir
            let _ = f.flush();
        }
    }
}

/// Secondes écoulées depuis le 1er janvier 1970 (UTC).
fn maintenant() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Convertit un nombre de secondes depuis 1970 en date ISO 8601 UTC (ex. "2026-10-11T14:05:09Z").
/// Algorithme "civil from days" (calendrier grégorien) : évite d'ajouter une bibliothèque de dates.
fn horodatage(secondes: i64) -> String {
    let jours = secondes.div_euclid(86_400);
    let reste = secondes.rem_euclid(86_400);
    let z = jours + 719_468;
    let ere = z.div_euclid(146_097);
    let jour_ere = z.rem_euclid(146_097);
    let annee_ere = (jour_ere - jour_ere / 1_460 + jour_ere / 36_524 - jour_ere / 146_096) / 365;
    let jour_annee = jour_ere - (365 * annee_ere + annee_ere / 4 - annee_ere / 100);
    let mp = (5 * jour_annee + 2) / 153;
    let jour = jour_annee - (153 * mp + 2) / 5 + 1;
    let mois = if mp < 10 { mp + 3 } else { mp - 9 };
    let annee = annee_ere + ere * 400 + if mois <= 2 { 1 } else { 0 };
    format!(
        "{annee:04}-{mois:02}-{jour:02}T{:02}:{:02}:{:02}Z",
        reste / 3_600,
        (reste % 3_600) / 60,
        reste % 60
    )
}

/// Rend un texte sûr pour du JSON : le visiteur contrôle ce texte, il ne doit pas pouvoir casser le journal.
fn echapper_json(texte: &str) -> String {
    let mut sortie = String::new();
    for c in texte.chars() {
        match c {
            '"' => sortie.push_str("\\\""),
            '\\' => sortie.push_str("\\\\"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => sortie.push_str(&format!("\\u{:04x}", c as u32)),
            c => sortie.push(c),
        }
    }
    sortie
}

/// Nettoie ce que le visiteur a tapé : retire les fins de ligne et les octets de négociation Telnet.
fn nettoyer(octets: &[u8]) -> String {
    let texte = String::from_utf8_lossy(octets);
    texte.trim_matches(|c: char| c == '\r' || c == '\n' || c == '\0').chars().take(128).collect()
}

/// Lit une ligne envoyée par le visiteur (au plus MAX_LIGNE octets). `None` = connexion fermée ou délai dépassé.
fn lire_ligne(lecteur: &mut BufReader<TcpStream>) -> Option<String> {
    let mut tampon = Vec::new();
    match lecteur.by_ref().take(MAX_LIGNE).read_until(b'\n', &mut tampon) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(nettoyer(&tampon)),
    }
}

/// Faux écran de connexion : demande un identifiant et un mot de passe, refuse toujours.
fn faux_telnet(flux: &mut TcpStream, lecteur: &mut BufReader<TcpStream>, ip: &str, port: u16, journal: &Journal) {
    let _ = flux.write_all(b"\r\nUbuntu 22.04.3 LTS\r\n");
    for _ in 0..ESSAIS {
        let _ = flux.write_all(b"serveur login: ");
        let Some(identifiant) = lire_ligne(lecteur) else { return };
        let _ = flux.write_all(b"Password: ");
        let Some(mot_de_passe) = lire_ligne(lecteur) else { return };
        journal.ecrire(ip, port, Service::Telnet, "tentative", &[("identifiant", &identifiant), ("mot_de_passe", &mot_de_passe)]);
        let _ = flux.write_all(b"\r\nLogin incorrect\r\n");
    }
}

/// Fausse bannière SSH : annonce un serveur, note les premiers octets reçus, puis ferme.
fn faux_ssh(flux: &mut TcpStream, lecteur: &mut BufReader<TcpStream>, ip: &str, port: u16, journal: &Journal) {
    let _ = flux.write_all(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n");
    let mut tampon = [0u8; 512];
    if let Ok(n) = lecteur.read(&mut tampon) {
        if n > 0 {
            // le client SSH annonce généralement son logiciel dans la première ligne ("SSH-2.0-...")
            journal.ecrire(ip, port, Service::Ssh, "donnees", &[("recu", &nettoyer(&tampon[..n]))]);
        }
    }
}

/// Traite un visiteur du début à la fin.
fn gerer(flux: TcpStream, service: Service, port: u16, journal: &Journal) {
    let ip = flux.peer_addr().map(|a| a.ip().to_string()).unwrap_or_else(|_| "inconnue".to_string());
    let _ = flux.set_read_timeout(Some(DELAI));
    let _ = flux.set_write_timeout(Some(DELAI));
    journal.ecrire(&ip, port, service, "connexion", &[]);

    let Ok(copie) = flux.try_clone() else { return }; // une copie pour lire, l'original pour écrire
    let mut lecteur = BufReader::new(copie);
    let mut flux = flux;
    match service {
        Service::Telnet => faux_telnet(&mut flux, &mut lecteur, &ip, port, journal),
        Service::Ssh => faux_ssh(&mut flux, &mut lecteur, &ip, port, journal),
    }
    journal.ecrire(&ip, port, service, "fermeture", &[]);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let port: u16 = args.get(1).map(|p| p.parse().unwrap_or(0)).unwrap_or(2323);
    let service = match args.get(2).map(String::as_str).unwrap_or("telnet") {
        "telnet" => Service::Telnet,
        "ssh" => Service::Ssh,
        _ => {
            eprintln!("Usage : honeypot [port] [telnet|ssh] [journal]");
            process::exit(2);
        }
    };
    let chemin_journal = args.get(3).map(String::as_str).unwrap_or("honeypot.log");
    if port == 0 {
        eprintln!("Erreur : port invalide. Usage : honeypot [port] [telnet|ssh] [journal]");
        process::exit(2);
    }

    let fichier = match OpenOptions::new().create(true).append(true).open(chemin_journal) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Erreur : impossible d'ouvrir le journal {chemin_journal} ({e})");
            process::exit(2);
        }
    };
    let ecoute = match TcpListener::bind(("0.0.0.0", port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Erreur : impossible d'écouter sur le port {port} ({e})");
            process::exit(2);
        }
    };
    eprintln!("Honeypot {} à l'écoute sur le port {port}. Journal : {chemin_journal}. Ctrl+C pour arrêter.", service.nom());

    let journal = Arc::new(Journal { fichier: Mutex::new(fichier) });
    let actifs = Arc::new(AtomicUsize::new(0)); // nombre de visiteurs en cours

    for connexion in ecoute.incoming() {
        let Ok(flux) = connexion else { continue };
        if actifs.load(Ordering::SeqCst) >= MAX_CONNEXIONS {
            continue; // trop de monde : on coupe sans répondre (le flux est fermé quand il sort de la portée)
        }
        actifs.fetch_add(1, Ordering::SeqCst);
        let (journal, actifs) = (Arc::clone(&journal), Arc::clone(&actifs));
        thread::spawn(move || {
            gerer(flux, service, port, &journal);
            actifs.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_connues() {
        assert_eq!(horodatage(0), "1970-01-01T00:00:00Z");
        assert_eq!(horodatage(951_782_400), "2000-02-29T00:00:00Z"); // année bissextile
        assert_eq!(horodatage(1_700_000_000), "2023-11-14T22:13:20Z");
    }

    #[test]
    fn json_ne_peut_pas_etre_casse() {
        let sale = "admin\"},{\"x\":\"1\n\\";
        let propre = echapper_json(sale);
        assert!(!propre.contains('\n'));
        assert_eq!(propre, "admin\\\"},{\\\"x\\\":\\\"1\\u000a\\\\");
    }

    #[test]
    fn nettoyage_des_saisies() {
        assert_eq!(nettoyer(b"root\r\n"), "root");
        assert_eq!(nettoyer(&vec![b'a'; 500]).len(), 128);
    }
}
