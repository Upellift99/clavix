# Clavix

**Client desktop moderne pour Vaultwarden et Bitwarden.**

Clavix est une alternative au client officiel Bitwarden et à Keyguard,
pensée pour la communauté self-hosted Vaultwarden. L'objectif : offrir
enfin une gestion d'arborescence confortable avec drag & drop, comme
KeePassXC le propose depuis des années.

> **Statut : en cours de développement.** Aucune version utilisable
> n'est encore publiée.

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
- [ ] Login contre une instance Vaultwarden (URL custom)
- [ ] Déverrouillage par mot de passe maître
- [ ] Sync initial : items, folders, collections, organisations
- [ ] Liste plate avec recherche
- [ ] Détail d'un item, copie clipboard avec effacement auto (30 s)
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
│       ├── main.rs
│       ├── crypto.rs     Crypto Bitwarden (à venir)
│       ├── api.rs        Client HTTP Vaultwarden
│       ├── sync.rs       Sync et cache offline
│       ├── models.rs     Types partagés
│       └── commands.rs   Commandes Tauri exposées à Svelte
├── src/              Frontend Svelte
│   ├── routes/
│   └── lib/
│       ├── components/
│       ├── stores/
│       └── api.ts
└── CLAUDE.md         Contexte projet pour pair programming
```

## Sécurité

- Le mot de passe maître n'est jamais conservé en mémoire plus
  longtemps que nécessaire (types qui s'effacent à la destruction via
  `zeroize`).
- Le refresh token est stocké dans le trousseau de l'OS via
  `keyring-rs`, jamais en clair sur disque.
- Le cache local SQLite est chiffré.
- Clavix est testé en priorité contre **Vaultwarden**. La
  compatibilité Bitwarden officiel est un bonus, pas une garantie.

Les vulnérabilités doivent être signalées en privé au mainteneur avant
toute divulgation publique.

## Contribuer

Le projet est encore à ses débuts et l'architecture bouge. Les issues
et suggestions sont bienvenues ; les PR seront ouvertes à partir de la
première release utilisable (phase 1 complète).

## Licence

[GPL-3.0-or-later](https://www.gnu.org/licenses/gpl-3.0.html).

## À propos

Clavix fait partie de **Clavix Labs**, qui regroupera à terme d'autres
outils FOSS orientés self-hosting, souveraineté et RGPD.
