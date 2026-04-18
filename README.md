# Clavix

**Client desktop moderne pour Vaultwarden et Bitwarden.**

Clavix est une alternative au client officiel Bitwarden et à Keyguard,
pensée pour la communauté self-hosted Vaultwarden. L'objectif : offrir
enfin une gestion d'arborescence confortable avec drag & drop, comme
KeePassXC le propose depuis des années.

> **Statut : en cours de développement.** Aucune version utilisable
> n'est encore publiée.

## Où en est Clavix aujourd'hui

Clavix sait déjà, contre une instance Vaultwarden réelle :

- se connecter (email + mot de passe maître, KDF PBKDF2 et Argon2id) ;
- passer un challenge 2FA TOTP ;
- synchroniser le coffre complet (items, folders, collections,
  organisations) ;
- **déchiffrer côté client** les noms de folders et d'items, aussi
  bien pour le coffre personnel (AES-256-CBC + HMAC-SHA256) que pour
  les items d'organisations dont la clé est chiffrée en RSA-OAEP-SHA1
  via la clé privée de l'utilisateur ;
- afficher un récapitulatif du coffre (compteurs + aperçu d'items en
  clair).

Le mot de passe maître ne touche jamais le serveur ni le disque :
seules des valeurs dérivées transitent (master password hash pour
l'authentification, master key pour le déchiffrement local). Toutes
les clés sensibles (`MasterKey`, `SymmetricKey`) s'effacent de la
mémoire à leur destruction via `zeroize`.

Ce qui manque encore pour la release utilisable : recherche, détail
d'item, copie presse-papier, cache local persistant. Voir la roadmap.

---

## Pourquoi ce projet

Le client officiel Bitwarden (Electron) a une UX datée et n'offre pas
de vrai drag & drop d'arbre. Keyguard, l'alternative la plus sérieuse,
est en lecture seule sans abonnement premium et gère mal les
hiérarchies profondes. Clavix vise à combler ce manque pour la
communauté self-hosted.

## Stack technique

- **Framework** — [Tauri 2](https://tauri.app) (Rust + WebView natif)
- **Frontend** — [Svelte 5](https://svelte.dev) + TypeScript + Vite
- **Backend** — Rust (crypto Bitwarden inspirée de [rbw](https://github.com/doy/rbw))
- **Drag & drop** — `svelte-dnd-action`
- **Cache local** — SQLite chiffré (`rusqlite`)
- **Secrets OS** — `keyring-rs` (trousseau système)

> Clavix n'utilise **pas** le SDK officiel Bitwarden (licence ambiguë).
> La crypto est réimplémentée côté projet, sous licence GPL-3.0.

## Roadmap MVP

### Phase 1 — Lecture seule
- [x] Login contre une instance Vaultwarden (URL custom)
- [x] Déverrouillage par mot de passe maître (PBKDF2 + Argon2id)
- [x] 2FA TOTP
- [x] Sync initial : items, folders, collections, organisations
- [x] Déchiffrement des noms (AES-CBC + HMAC, RSA-OAEP)
- [ ] Liste complète avec recherche
- [ ] Détail d'un item, copie clipboard avec effacement auto (30 s)
- [ ] Persistance du refresh token via `keyring-rs`
- [ ] Cache local chiffré (mode offline en lecture)

### Phase 2 — Arborescence
- [ ] Parsing des noms avec `/` pour construire l'arbre
- [ ] TreeView avec expand/collapse
- [ ] Arbre des folders perso **et** des collections d'organisations

### Phase 3 — Drag & drop (killer feature)
- [ ] Drag & drop d'items vers un folder ou une collection
- [ ] Drag & drop de folders entre eux
- [ ] Rename propagé côté serveur, UI optimiste avec rollback

### Hors scope MVP

Création/édition/suppression d'items, génération de mots de passe,
attachments, Sends, passkeys, auto-fill navigateur, YubiKey/FIDO2
(phase 4+), import KeePass (phase 5+).

## Prérequis (développement)

- **Rust** ≥ 1.85 (edition 2024 requise par les dépendances)
- **Node.js** ≥ 20 et **pnpm** ≥ 10

### Ubuntu / Debian

```bash
sudo apt install \
  libwebkit2gtk-4.1-dev \
  libjavascriptcoregtk-4.1-dev \
  libsoup-3.0-dev \
  libxdo-dev \
  libssl-dev \
  librsvg2-dev \
  libayatana-appindicator3-dev \
  build-essential curl wget file
```

### Autres plateformes

Voir la [documentation Tauri](https://tauri.app/start/prerequisites/).

## Lancer l'app en développement

```bash
pnpm install
pnpm tauri dev
```

La première compilation Rust prend quelques minutes (toutes les
dépendances Tauri), les suivantes sont incrémentales grâce au cache
`target/`.

## Structure du dépôt

```
clavix/
├── src-tauri/        Backend Rust (Tauri)
│   └── src/
│       ├── main.rs       Entrée binaire
│       ├── lib.rs        Commandes Tauri exposées à Svelte
│       ├── api.rs        Client HTTP Vaultwarden (prelogin / login / sync)
│       ├── crypto.rs     Dérivation de clés, EncString (AES / RSA)
│       ├── models.rs     Types API et DTO envoyés à l'UI
│       ├── state.rs      AppState (session en mémoire, clés déchiffrées)
│       └── error.rs      Type Error unifié, sérialisé { code, message, data }
├── src/              Frontend SvelteKit (rendu statique, pas de SSR)
│   ├── app.html
│   └── routes/
│       ├── +layout.ts
│       └── +page.svelte  Écran unique pour l'instant (login → sync)
├── .github/workflows/ci.yml   CI (fmt, clippy, cargo audit, svelte-check)
└── CLAUDE.md         Contexte projet pour pair programming
```

À mesure que l'app grossit, `src/routes/+page.svelte` sera découpé en
composants dans `src/lib/components/` et en stores dans
`src/lib/stores/`.

## Sécurité

- Le mot de passe maître et les clés symétriques dérivées
  (`MasterKey`, `SymmetricKey`) dérivent `ZeroizeOnDrop` : leur
  mémoire est écrasée dès qu'ils sortent du scope. En transit,
  le mot de passe passe en `SecretString` (crate `secrecy`) qui
  empêche le `Debug` de le divulguer dans les logs.
- Tout le déchiffrement se fait **côté client** ; le serveur ne voit
  jamais les secrets en clair.
- La vérification HMAC du ciphertext AES-CBC se fait en **temps
  constant** (`hmac::Mac::verify_slice`) avant le déchiffrement.
- **En cours de développement**, le refresh token reste en mémoire
  process — redémarrer l'app exige un relogin. La persistance via
  `keyring-rs` (trousseau OS) et le cache local SQLite chiffré sont
  planifiés pour finir la phase 1.
- Clavix est testé en priorité contre **Vaultwarden**. La
  compatibilité Bitwarden officiel est un bonus, pas une garantie.

Les vulnérabilités doivent être signalées en privé au mainteneur avant
toute divulgation publique.

## Qualité / CI

Chaque push et pull request vers `main` ou `master` déclenche un
workflow GitHub Actions qui vérifie :

- `cargo fmt --check` — style Rust.
- `cargo clippy --all-targets -- -D warnings` — lint strict.
- `cargo audit` — vulnérabilités dans les dépendances.
- `pnpm check` (svelte-check) — typage TypeScript / Svelte.

Les dépendances systèmes Tauri sont installées à chaque run ; le
cache `target/` est géré par `Swatinem/rust-cache`.

## Contribuer

Le projet est encore à ses débuts et l'architecture bouge. Les issues
et suggestions sont bienvenues ; les PR seront ouvertes à partir de la
première release utilisable (phase 1 complète).

## Licence

[GPL-3.0-or-later](https://www.gnu.org/licenses/gpl-3.0.html).

## À propos

Clavix fait partie de **Clavix Labs**, qui regroupera à terme d'autres
outils FOSS orientés self-hosting, souveraineté et RGPD.
