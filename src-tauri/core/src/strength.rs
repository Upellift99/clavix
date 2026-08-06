//! Password strength scoring, on top of zxcvbn.
//!
//! This module exists so there is exactly **one** verdict in the app.
//! The vault-wide audit (`crate::audit`) and the per-field indicator in
//! the editor both come through here, so the editor can never say
//! "strong" about a password the audit lists as weak — a contradiction
//! that two scoring engines (one in Rust, one in the webview) would
//! have produced sooner or later.
//!
//! zxcvbn is the right tool for a *human-chosen* password: it estimates
//! guessability against dictionaries, keyboard walks, dates and l33t
//! substitutions. It is the wrong tool for a generated one — on a
//! CSPRNG draw over a known alphabet it saturates at score 4 from about
//! twelve characters and stops discriminating. The generator therefore
//! computes exact entropy in the renderer instead (`src/lib/strength.ts`)
//! and never calls in here.
//!
//! Known limitation, surfaced in the UI rather than hidden: the
//! dictionaries are English-centric, so a French passphrase scores
//! higher than it deserves.

use serde::Serialize;
use ts_rs::TS;

/// Highest zxcvbn score still considered weak. The audit's "weak"
/// section and the indicator's red/amber bands both read this, so the
/// two can't drift apart.
pub const WEAK_SCORE_MAX: u8 = 2;

/// Longest input we will score. zxcvbn itself only looks at the first
/// 100 characters, but the cap belongs at our boundary too: without it
/// a compromised renderer could hand us an arbitrarily large string to
/// allocate and copy across IPC.
pub const MAX_SCORED_LEN: usize = 256;

#[derive(Debug, Clone, Serialize, TS)]
#[ts(export)]
#[serde(rename_all = "camelCase")]
pub struct PasswordStrength {
    /// zxcvbn score, 0 (very weak) to 4 (very strong).
    pub score: u8,
    /// Order of magnitude of the estimated guess count. Always finite —
    /// see the clamp in `score` for why that isn't automatic.
    pub guesses_log10: f64,
    /// Stable slug for the headline problem, or `None` when zxcvbn has
    /// nothing to say (it only produces feedback at score <= 2).
    ///
    /// A slug rather than prose: the crate's `Display` impl emits
    /// English, which would land untranslated in a French UI. zxcvbn's
    /// improvement *suggestions* are deliberately not carried — a
    /// compact inline meter has no room to render them, and shipping a
    /// field nothing displays is dead weight. Adding them later is a
    /// purely additive change.
    pub warning: Option<String>,
}

/// Score `password`, letting zxcvbn penalise anything that echoes
/// `user_inputs` (item name, username, domain). Passing those matters:
/// without them "github2024" saved on the GitHub item scores as an
/// ordinary word-plus-year rather than as the giveaway it is.
pub fn score(password: &str, user_inputs: &[&str]) -> PasswordStrength {
    let truncated: String = password.chars().take(MAX_SCORED_LEN).collect();
    let entropy = zxcvbn::zxcvbn(&truncated, user_inputs);

    // zxcvbn returns -inf for the empty password, and serde_json turns
    // any non-finite float into `null` — which would arrive in the
    // webview as `null` under a `number` binding and poison every
    // arithmetic use downstream. Clamp to 0 instead: "zero guesses
    // needed" is both finite and true.
    let guesses_log10 = if entropy.guesses_log10().is_finite() {
        entropy.guesses_log10()
    } else {
        0.0
    };

    PasswordStrength {
        score: entropy.score() as u8,
        guesses_log10,
        warning: entropy
            .feedback()
            .and_then(|f| f.warning())
            .map(|w| warning_slug(w).to_string()),
    }
}

/// Map zxcvbn's warning to a stable slug the renderer translates.
///
/// The crate's `Display` impl emits English prose, which would land
/// untranslated in a French UI. The slugs are written out by hand
/// rather than derived from the variant names so that a rename
/// upstream is a compile error here instead of a silently changed
/// i18n key.
fn warning_slug(warning: zxcvbn::feedback::Warning) -> &'static str {
    use zxcvbn::feedback::Warning as W;
    match warning {
        W::StraightRowsOfKeysAreEasyToGuess => "straight-rows-of-keys",
        W::ShortKeyboardPatternsAreEasyToGuess => "short-keyboard-pattern",
        W::RepeatsLikeAaaAreEasyToGuess => "repeats-like-aaa",
        W::RepeatsLikeAbcAbcAreOnlySlightlyHarderToGuess => "repeats-like-abcabc",
        W::ThisIsATop10Password => "top-10-password",
        W::ThisIsATop100Password => "top-100-password",
        W::ThisIsACommonPassword => "common-password",
        W::ThisIsSimilarToACommonlyUsedPassword => "similar-to-common-password",
        W::SequencesLikeAbcAreEasyToGuess => "sequences-like-abc",
        W::RecentYearsAreEasyToGuess => "recent-years",
        W::AWordByItselfIsEasyToGuess => "word-by-itself",
        W::DatesAreOftenEasyToGuess => "dates",
        W::NamesAndSurnamesByThemselvesAreEasyToGuess => "names-by-themselves",
        W::CommonNamesAndSurnamesAreEasyToGuess => "common-names",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trivial_password_scores_weak() {
        let s = score("password", &[]);
        assert!(
            s.score <= WEAK_SCORE_MAX,
            "\"password\" should be weak: got {s:?}"
        );
        assert_eq!(s.warning.as_deref(), Some("top-10-password"));
    }

    #[test]
    fn generated_password_scores_strong() {
        let s = score("8J!kQr2#Lm^9zXvP$4wT", &[]);
        assert!(
            s.score > WEAK_SCORE_MAX,
            "a random 20-char password should not be weak: got {s:?}"
        );
    }

    #[test]
    fn empty_password_yields_finite_guesses() {
        // zxcvbn returns -inf here; serde_json would emit `null` for it
        // and break the `number` binding on the other side of the IPC.
        let s = score("", &[]);
        assert!(
            s.guesses_log10.is_finite(),
            "guessesLog10 must stay finite so it survives JSON: got {}",
            s.guesses_log10
        );
        assert_eq!(s.score, 0);
    }

    #[test]
    fn user_inputs_penalise_a_password_echoing_the_item() {
        let blind = score("github2024", &[]);
        let informed = score("github2024", &["GitHub", "octocat"]);
        assert!(
            informed.score <= blind.score,
            "knowing the item name must not make the password look stronger: \
             blind={} informed={}",
            blind.score,
            informed.score
        );
    }

    #[test]
    fn overlong_input_is_truncated_not_rejected() {
        let s = score(&"a".repeat(MAX_SCORED_LEN * 4), &[]);
        assert!(s.guesses_log10.is_finite());
    }
}
