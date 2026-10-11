//! Vrai serveur SSH leurre : il parle le vrai protocole (échange de clés, chiffrement),
//! note chaque identifiant / mot de passe / clé publique proposé, et REFUSE TOUJOURS l'accès.
//! Aucun terminal n'est jamais ouvert : il n'y a rien à exécuter.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use russh::{MethodKind, MethodSet}; // méthodes d'authentification annoncées au client
use russh::keys::ssh_key::{LineEnding, PublicKey}; // format de fichier de clé et clé publique
use russh::keys::{Algorithm, HashAlg, PrivateKey}; // algorithme de clé, empreinte, clé privée
use russh::server::{self, Auth, Handler}; // briques du serveur
use russh::SshId; // texte d'identification du serveur ("SSH-2.0-...")
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore}; // Semaphore = limite de visiteurs simultanés

use crate::{Journal, Service};

/// Identité annoncée : celle d'un OpenSSH ordinaire sur Ubuntu.
const IDENTITE: &str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6";
/// Visiteurs simultanés maximum.
const MAX_CONNEXIONS: usize = 50;
/// Durée maximale d'une session : un leurre n'a aucune raison de garder quelqu'un longtemps.
const DUREE_MAX: Duration = Duration::from_secs(120);

/// Charge la clé du serveur, ou en crée une et la sauvegarde.
/// Elle est conservée entre deux lancements : une clé qui change à chaque fois est un indice de leurre.
fn cle_du_serveur(chemin: &Path) -> Result<PrivateKey, String> {
    if chemin.exists() {
        return PrivateKey::read_openssh_file(chemin).map_err(|e| format!("clé illisible {} ({e})", chemin.display()));
    }
    let cle = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).map_err(|e| format!("création de la clé impossible ({e})"))?;
    cle.write_openssh_file(chemin, LineEnding::LF) // le fichier est créé en lecture seule pour son propriétaire (0600)
        .map_err(|e| format!("écriture de la clé impossible {} ({e})", chemin.display()))?;
    Ok(cle)
}

/// Un visiteur connecté. Détruit à la fin de la connexion (le `Drop` écrit alors "fermeture").
struct Visiteur {
    ip: String,
    port: u16,
    journal: Arc<Journal>,
    _place: OwnedSemaphorePermit, // libère une place quand le visiteur disparaît
}

impl Drop for Visiteur {
    fn drop(&mut self) {
        self.journal.ecrire(&self.ip, self.port, Service::Ssh, "fermeture", &[]);
    }
}

impl Handler for Visiteur {
    type Error = russh::Error;

    /// Mot de passe proposé : on le note et on refuse.
    async fn auth_password(&mut self, utilisateur: &str, mot_de_passe: &str) -> Result<Auth, Self::Error> {
        self.journal.ecrire(
            &self.ip,
            self.port,
            Service::Ssh,
            "tentative",
            &[("identifiant", utilisateur), ("mot_de_passe", mot_de_passe)],
        );
        Ok(Auth::reject())
    }

    /// Clé publique proposée : on note son empreinte et on refuse (le client passera à autre chose).
    async fn auth_publickey_offered(&mut self, utilisateur: &str, cle: &PublicKey) -> Result<Auth, Self::Error> {
        let empreinte = cle.fingerprint(HashAlg::Sha256).to_string();
        self.journal.ecrire(
            &self.ip,
            self.port,
            Service::Ssh,
            "cle_publique",
            &[("identifiant", utilisateur), ("algorithme", &cle.algorithm().to_string()), ("empreinte", &empreinte)],
        );
        Ok(Auth::reject())
    }
}

/// Démarre le serveur et ne s'arrête jamais (sauf erreur de démarrage).
pub async fn lancer(port: u16, journal: Arc<Journal>, chemin_cle: &str) -> Result<(), String> {
    let cle = cle_du_serveur(Path::new(chemin_cle))?;
    let config = Arc::new(server::Config {
        server_id: SshId::Standard(IDENTITE.into()),
        methods: MethodSet::from(&[MethodKind::Password, MethodKind::PublicKey][..]),
        keys: vec![cle],
        auth_rejection_time: Duration::from_secs(2), // petite pause après un refus, comme un vrai serveur
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        max_auth_attempts: 6,
        inactivity_timeout: Some(Duration::from_secs(30)),
        ..Default::default()
    });

    let ecoute = TcpListener::bind(("0.0.0.0", port)).await.map_err(|e| format!("impossible d'écouter sur le port {port} ({e})"))?;
    let places = Arc::new(Semaphore::new(MAX_CONNEXIONS));

    loop {
        let Ok((flux, adresse)) = ecoute.accept().await else { continue };
        let Ok(place) = Arc::clone(&places).try_acquire_owned() else { continue }; // trop de monde : on coupe
        let ip = ip_de(adresse);
        journal.ecrire(&ip, port, Service::Ssh, "connexion", &[]);
        let visiteur = Visiteur { ip, port, journal: Arc::clone(&journal), _place: place };
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            if let Ok(session) = server::run_stream(config, flux, visiteur).await {
                let _ = tokio::time::timeout(DUREE_MAX, session).await; // au-delà, la session est coupée
            }
        });
    }
}

fn ip_de(adresse: SocketAddr) -> String {
    adresse.ip().to_string()
}
