# Raccourcis pour reproduire les vérifs CI en local avant de pusher.
# Tout est indépendant : tu peux appeler un target isolé, ou `check` /
# `check-full` pour enchaîner.

.PHONY: check check-full fmt clippy test-rust check-js test-js test-e2e \
        build-tauri docker-up docker-down

# --- Rust ---

fmt:
	cd src-tauri && cargo fmt --all -- --check

fmt-fix:
	cd src-tauri && cargo fmt --all

clippy:
	cd src-tauri && cargo clippy --all-targets -- -D warnings

test-rust:
	cd src-tauri && cargo test --lib

# --- Frontend ---

check-js:
	pnpm check

test-js:
	pnpm test

# --- E2E (plus lent : build Tauri + docker Vaultwarden + xvfb/WebDriver) ---

build-tauri:
	pnpm tauri build --debug --no-bundle

test-e2e: build-tauri
	pnpm test:e2e

docker-up:
	docker compose -f tests/e2e/docker-compose.yml up -d

docker-down:
	docker compose -f tests/e2e/docker-compose.yml down --volumes

# --- Agrégats ---

# Boucle rapide pendant le dev : fmt + clippy + test Rust + svelte-check + vitest.
# ~20 s sur cache chaud. Pas d'E2E ici.
check: fmt clippy test-rust check-js test-js

# Tout ce que la CI enforce, E2E compris. À lancer avant un push qui touche
# à l'UI ou aux flows côté Rust exposés en command.
check-full: check test-e2e
