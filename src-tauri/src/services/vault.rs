use std::collections::HashMap;

use rayon::prelude::*;

use crate::crypto::{decrypt_name, SymmetricKey};
use crate::models::{
    CipherSummary, CipherType, CollectionSummary, FolderSummary, OrganizationSummary, SyncResponse,
    SyncSummary, TypeCounts,
};

pub fn build_sync_summary(
    response: &SyncResponse,
    user_key: &SymmetricKey,
    org_keys: &HashMap<String, SymmetricKey>,
) -> SyncSummary {
    let mut type_counts = TypeCounts::default();
    for c in &response.ciphers {
        match c.kind {
            CipherType::Login => type_counts.login += 1,
            CipherType::SecureNote => type_counts.secure_note += 1,
            CipherType::Card => type_counts.card += 1,
            CipherType::Identity => type_counts.identity += 1,
            CipherType::SshKey => type_counts.ssh_key += 1,
        }
    }

    let folders: Vec<FolderSummary> = response
        .folders
        .par_iter()
        .map(|f| FolderSummary {
            id: f.id.clone(),
            name: decrypt_or_placeholder(&f.name, user_key),
        })
        .collect();

    let ciphers: Vec<CipherSummary> = response
        .ciphers
        .par_iter()
        .map(|c| {
            let key = c
                .organization_id
                .as_ref()
                .and_then(|id| org_keys.get(id))
                .unwrap_or(user_key);
            let primary_uri = c
                .login
                .as_ref()
                .and_then(|l| l.uris.as_ref())
                .and_then(|uris| uris.iter().find_map(|u| u.uri.as_deref()))
                .and_then(|s| decrypt_name(s, key).ok());

            let username = c
                .login
                .as_ref()
                .and_then(|l| l.username.as_deref())
                .and_then(|s| decrypt_name(s, key).ok());

            CipherSummary {
                id: c.id.clone(),
                kind: c.kind as u8,
                name: decrypt_or_placeholder(&c.name, key),
                folder_id: c.folder_id.clone(),
                organization_id: c.organization_id.clone(),
                collection_ids: c.collection_ids.clone(),
                favorite: c.favorite,
                primary_uri,
                username,
                revision_date: c.revision_date.clone(),
                deleted_date: c.deleted_date.clone(),
            }
        })
        .collect();

    let organizations: Vec<OrganizationSummary> = response
        .profile
        .organizations
        .iter()
        .map(|o| OrganizationSummary {
            id: o.id.clone(),
            name: o.name.clone(),
        })
        .collect();

    let collections: Vec<CollectionSummary> = response
        .collections
        .par_iter()
        .map(|c| {
            let key = org_keys.get(&c.organization_id).unwrap_or(user_key);
            CollectionSummary {
                id: c.id.clone(),
                organization_id: c.organization_id.clone(),
                name: decrypt_or_placeholder(&c.name, key),
            }
        })
        .collect();

    SyncSummary {
        email: response.profile.email.clone(),
        name: response.profile.name.clone(),
        item_count: response.ciphers.len(),
        folder_count: response.folders.len(),
        collection_count: response.collections.len(),
        organization_count: response.profile.organizations.len(),
        type_counts,
        folders,
        organizations,
        collections,
        ciphers,
    }
}

pub fn decrypt_or_placeholder(encrypted: &str, key: &SymmetricKey) -> String {
    match decrypt_name(encrypted, key) {
        Ok(name) => name,
        Err(e) => {
            eprintln!("[clavix] decrypt failed: {e}");
            "[decrypt failed]".to_string()
        }
    }
}

/// Validates and computes the new base path for a folder move operation.
/// Returns the trimmed source path, optional trimmed parent, and the resulting
/// new base path.
pub fn compute_new_folder_base(
    source_path: &str,
    target_parent_path: Option<&str>,
) -> Result<(String, Option<String>, String), String> {
    let source = source_path.trim().trim_matches('/').to_string();
    if source.is_empty() {
        return Err("empty source path".into());
    }

    let target_parent = target_parent_path
        .map(|p| p.trim().trim_matches('/').to_string())
        .filter(|p| !p.is_empty());

    if let Some(parent) = target_parent.as_deref() {
        if parent == source || parent.starts_with(&format!("{source}/")) {
            return Err("cannot move a folder into itself or one of its descendants".into());
        }
    }

    let last_segment = source
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "source path has no final segment".to_string())?
        .to_string();

    let new_base = match target_parent.as_deref() {
        Some(parent) => format!("{parent}/{last_segment}"),
        None => last_segment.clone(),
    };

    Ok((source, target_parent, new_base))
}

/// Computes the new name for a folder when its prefix is being moved.
/// Returns `None` if the folder is unrelated to the move.
pub fn rename_folder_under_move(
    current_name: &str,
    source_path: &str,
    new_base: &str,
) -> Option<String> {
    if current_name == source_path {
        Some(new_base.to_string())
    } else if current_name.starts_with(&format!("{source_path}/")) {
        let suffix = &current_name[source_path.len() + 1..];
        Some(format!("{new_base}/{suffix}"))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{encrypt_string, SymmetricKey};
    use crate::models::{
        Cipher, CipherLogin, CipherLoginUri, CipherType, Collection, Folder, Organization, Profile,
        SyncResponse,
    };

    fn user_key() -> SymmetricKey {
        let mut bytes = [0u8; 64];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(11);
        }
        SymmetricKey::from_bytes(&bytes).unwrap()
    }

    fn org_key() -> SymmetricKey {
        let mut bytes = [0u8; 64];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(13).wrapping_add(47);
        }
        SymmetricKey::from_bytes(&bytes).unwrap()
    }

    fn make_folder(id: &str, name: &str, key: &SymmetricKey) -> Folder {
        Folder {
            id: id.into(),
            name: encrypt_string(name, key).unwrap(),
            revision_date: None,
        }
    }

    fn make_login_cipher(
        id: &str,
        name: &str,
        username: Option<&str>,
        uri: Option<&str>,
        key: &SymmetricKey,
        organization_id: Option<&str>,
    ) -> Cipher {
        Cipher {
            id: id.into(),
            kind: CipherType::Login,
            name: encrypt_string(name, key).unwrap(),
            notes: None,
            organization_id: organization_id.map(str::to_string),
            folder_id: None,
            collection_ids: vec![],
            revision_date: None,
            deleted_date: None,
            favorite: false,
            login: Some(CipherLogin {
                username: username.map(|u| encrypt_string(u, key).unwrap()),
                password: None,
                totp: None,
                uris: uri.map(|u| {
                    vec![CipherLoginUri {
                        uri: Some(encrypt_string(u, key).unwrap()),
                    }]
                }),
            }),
            card: None,
            identity: None,
            ssh_key: None,
        }
    }

    fn make_cipher_of_type(
        id: &str,
        kind: CipherType,
        key: &SymmetricKey,
        organization_id: Option<&str>,
    ) -> Cipher {
        Cipher {
            id: id.into(),
            kind,
            name: encrypt_string("n", key).unwrap(),
            notes: None,
            organization_id: organization_id.map(str::to_string),
            folder_id: None,
            collection_ids: vec![],
            revision_date: None,
            deleted_date: None,
            favorite: false,
            login: None,
            card: None,
            identity: None,
            ssh_key: None,
        }
    }

    fn response_with(
        folders: Vec<Folder>,
        collections: Vec<Collection>,
        ciphers: Vec<Cipher>,
        organizations: Vec<Organization>,
    ) -> SyncResponse {
        SyncResponse {
            profile: Profile {
                id: "user-id".into(),
                email: "u@e.com".into(),
                name: Some("Utilisateur".into()),
                organizations,
            },
            folders,
            collections,
            ciphers,
        }
    }

    #[test]
    fn sync_summary_counts_match_response_lengths() {
        let uk = user_key();
        let resp = response_with(
            vec![make_folder("f1", "Work", &uk)],
            vec![],
            vec![
                make_cipher_of_type("c1", CipherType::Login, &uk, None),
                make_cipher_of_type("c2", CipherType::Login, &uk, None),
                make_cipher_of_type("c3", CipherType::SecureNote, &uk, None),
            ],
            vec![],
        );

        let s = build_sync_summary(&resp, &uk, &HashMap::new());
        assert_eq!(s.item_count, 3);
        assert_eq!(s.folder_count, 1);
        assert_eq!(s.collection_count, 0);
        assert_eq!(s.organization_count, 0);
        assert_eq!(s.type_counts.login, 2);
        assert_eq!(s.type_counts.secure_note, 1);
        assert_eq!(s.type_counts.card, 0);
    }

    #[test]
    fn sync_summary_type_counts_cover_every_variant() {
        let uk = user_key();
        let resp = response_with(
            vec![],
            vec![],
            vec![
                make_cipher_of_type("1", CipherType::Login, &uk, None),
                make_cipher_of_type("2", CipherType::SecureNote, &uk, None),
                make_cipher_of_type("3", CipherType::Card, &uk, None),
                make_cipher_of_type("4", CipherType::Identity, &uk, None),
                make_cipher_of_type("5", CipherType::SshKey, &uk, None),
            ],
            vec![],
        );

        let s = build_sync_summary(&resp, &uk, &HashMap::new());
        assert_eq!(s.type_counts.login, 1);
        assert_eq!(s.type_counts.secure_note, 1);
        assert_eq!(s.type_counts.card, 1);
        assert_eq!(s.type_counts.identity, 1);
        assert_eq!(s.type_counts.ssh_key, 1);
    }

    #[test]
    fn sync_summary_decrypts_folder_names_with_user_key() {
        let uk = user_key();
        let resp = response_with(
            vec![
                make_folder("f1", "Work", &uk),
                make_folder("f2", "Personal/Notes", &uk),
            ],
            vec![],
            vec![],
            vec![],
        );

        let s = build_sync_summary(&resp, &uk, &HashMap::new());
        assert_eq!(s.folders[0].name, "Work");
        assert_eq!(s.folders[1].name, "Personal/Notes");
    }

    #[test]
    fn sync_summary_picks_org_key_for_org_cipher() {
        // Decisive invariant: an org cipher must be decrypted with the
        // matching org_keys entry, not the user_key. A bug here would
        // either show '[decrypt failed]' to org members or (worse) tie
        // item retrieval to the user key only.
        let uk = user_key();
        let mut org_keys = HashMap::new();
        org_keys.insert("org-1".to_string(), org_key());

        let resp = response_with(
            vec![],
            vec![],
            vec![make_login_cipher(
                "c1",
                "Org item",
                Some("alice"),
                Some("https://example.com"),
                &org_key(),
                Some("org-1"),
            )],
            vec![],
        );

        let s = build_sync_summary(&resp, &uk, &org_keys);
        assert_eq!(s.ciphers[0].name, "Org item");
        assert_eq!(s.ciphers[0].username.as_deref(), Some("alice"));
        assert_eq!(s.ciphers[0].primary_uri.as_deref(), Some("https://example.com"));
        assert_eq!(s.ciphers[0].organization_id.as_deref(), Some("org-1"));
    }

    #[test]
    fn sync_summary_falls_back_to_placeholder_when_org_key_missing() {
        // If the org_keys map doesn't have the cipher's org id, we fall
        // back to user_key — which will fail to decrypt — and emit a
        // placeholder name. Must not panic and must not silently swap the
        // cipher's organization_id.
        let uk = user_key();

        // Build cipher encrypted under org_key, but pass an empty org_keys
        // map so the summary falls back to user_key.
        let resp = response_with(
            vec![],
            vec![],
            vec![make_login_cipher(
                "c1",
                "Org item",
                None,
                None,
                &org_key(),
                Some("org-1"),
            )],
            vec![],
        );

        let s = build_sync_summary(&resp, &uk, &HashMap::new());
        assert_eq!(s.ciphers[0].name, "[decrypt failed]");
        assert_eq!(s.ciphers[0].organization_id.as_deref(), Some("org-1"));
    }

    #[test]
    fn sync_summary_decrypts_collection_names_with_org_key() {
        let uk = user_key();
        let mut org_keys = HashMap::new();
        org_keys.insert("org-1".to_string(), org_key());

        let resp = response_with(
            vec![],
            vec![Collection {
                id: "coll-1".into(),
                organization_id: "org-1".into(),
                name: encrypt_string("Shared", &org_key()).unwrap(),
                external_id: None,
                read_only: false,
                hide_passwords: false,
            }],
            vec![],
            vec![],
        );

        let s = build_sync_summary(&resp, &uk, &org_keys);
        assert_eq!(s.collections[0].name, "Shared");
        assert_eq!(s.collections[0].organization_id, "org-1");
    }

    #[test]
    fn sync_summary_preserves_favorite_folder_and_collection_links() {
        let uk = user_key();
        let mut c = make_login_cipher("c1", "Item", None, None, &uk, None);
        c.favorite = true;
        c.folder_id = Some("f1".into());
        c.collection_ids = vec!["coll-1".into()];
        c.deleted_date = Some("2026-01-01T00:00:00Z".into());
        c.revision_date = Some("2026-01-02T00:00:00Z".into());

        let resp = response_with(vec![], vec![], vec![c], vec![]);
        let s = build_sync_summary(&resp, &uk, &HashMap::new());
        let cs = &s.ciphers[0];
        assert!(cs.favorite);
        assert_eq!(cs.folder_id.as_deref(), Some("f1"));
        assert_eq!(cs.collection_ids, vec!["coll-1".to_string()]);
        assert_eq!(cs.deleted_date.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_eq!(cs.revision_date.as_deref(), Some("2026-01-02T00:00:00Z"));
    }

    #[test]
    fn sync_summary_primary_uri_is_first_non_none() {
        let uk = user_key();
        let mut c = make_login_cipher("c1", "Item", None, None, &uk, None);
        c.login = Some(CipherLogin {
            username: None,
            password: None,
            totp: None,
            uris: Some(vec![
                CipherLoginUri { uri: None },
                CipherLoginUri {
                    uri: Some(encrypt_string("https://second.example", &uk).unwrap()),
                },
                CipherLoginUri {
                    uri: Some(encrypt_string("https://third.example", &uk).unwrap()),
                },
            ]),
        });

        let resp = response_with(vec![], vec![], vec![c], vec![]);
        let s = build_sync_summary(&resp, &uk, &HashMap::new());
        assert_eq!(
            s.ciphers[0].primary_uri.as_deref(),
            Some("https://second.example")
        );
    }

    #[test]
    fn sync_summary_passes_through_profile_fields() {
        let uk = user_key();
        let resp = response_with(
            vec![],
            vec![],
            vec![],
            vec![Organization {
                id: "org-1".into(),
                name: "Acme".into(),
                key: None,
            }],
        );
        let s = build_sync_summary(&resp, &uk, &HashMap::new());
        assert_eq!(s.email, "u@e.com");
        assert_eq!(s.name.as_deref(), Some("Utilisateur"));
        assert_eq!(s.organization_count, 1);
        assert_eq!(s.organizations[0].id, "org-1");
        assert_eq!(s.organizations[0].name, "Acme");
    }

    #[test]
    fn compute_new_folder_base_root_target() {
        let (src, parent, base) = compute_new_folder_base("/work/projects/", None).unwrap();
        assert_eq!(src, "work/projects");
        assert_eq!(parent, None);
        assert_eq!(base, "projects");
    }

    #[test]
    fn compute_new_folder_base_with_parent() {
        let (src, parent, base) =
            compute_new_folder_base("work/projects", Some("personal")).unwrap();
        assert_eq!(src, "work/projects");
        assert_eq!(parent.as_deref(), Some("personal"));
        assert_eq!(base, "personal/projects");
    }

    #[test]
    fn compute_new_folder_base_rejects_into_self() {
        assert!(compute_new_folder_base("work", Some("work")).is_err());
    }

    #[test]
    fn compute_new_folder_base_rejects_into_descendant() {
        assert!(compute_new_folder_base("work", Some("work/sub")).is_err());
    }

    #[test]
    fn compute_new_folder_base_rejects_empty_source() {
        assert!(compute_new_folder_base("/", None).is_err());
        assert!(compute_new_folder_base("", None).is_err());
    }

    #[test]
    fn rename_folder_renames_exact_match() {
        assert_eq!(
            rename_folder_under_move("work/projects", "work/projects", "personal/projects"),
            Some("personal/projects".to_string())
        );
    }

    #[test]
    fn rename_folder_renames_descendants() {
        assert_eq!(
            rename_folder_under_move("work/projects/site", "work/projects", "personal/projects"),
            Some("personal/projects/site".to_string())
        );
    }

    #[test]
    fn rename_folder_skips_unrelated() {
        assert_eq!(
            rename_folder_under_move("home/notes", "work/projects", "personal/projects"),
            None
        );
        assert_eq!(
            rename_folder_under_move("work/projection", "work/projects", "personal/projects"),
            None
        );
    }
}
