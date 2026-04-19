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
