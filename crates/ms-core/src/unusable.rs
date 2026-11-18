//! What to tell the user about keys another program stored in morsec's keychain entries: the
//! keychain lets only the program that stored an item read or delete it, so only the user can
//! remove one (vault-foreign-items). Shared by msd and the CLI, which never touches values.

use crate::KeyName;

/// Keychain service of every morsec item. The account is the key name.
pub const KEYCHAIN_SERVICE: &str = "cc.morsec.vault";

/// The command the user runs to remove a key another program stored. It names the login
/// keychain, the one msd reads, so a keychain earlier in the search list can't catch it. macOS
/// asks for the login password, because the item belongs to another program. Key names are
/// `[a-z0-9-/]` and never start with `-` ([`KeyName`]), so the command needs no quoting.
pub fn removal_command(name: &KeyName) -> String {
    format!(
        "security delete-generic-password -s {KEYCHAIN_SERVICE} -a {name} \
         ~/Library/Keychains/login.keychain-db"
    )
}

/// One line telling the user what to do about one unusable key.
pub fn unusable_hint(name: &KeyName) -> String {
    format!(
        "{name} was stored by another program (usually another morsec build, such as a dev build), \
         and the keychain lets only that program use it. Remove it with: {} (macOS asks for your \
         login password), then add it again: ms add {name}",
        removal_command(name)
    )
}

/// How many unusable keys [`unusable_alert`] names before it summarises the rest.
pub const UNUSABLE_NAMED: usize = 5;

/// One alert for every unusable key: the names (at most [`UNUSABLE_NAMED`]) and the fix. `None`
/// when there are none.
pub fn unusable_alert(names: &[KeyName]) -> Option<String> {
    match names {
        [] => None,
        [one] => Some(unusable_hint(one)),
        many => {
            let shown: Vec<&str> = many
                .iter()
                .take(UNUSABLE_NAMED)
                .map(KeyName::as_str)
                .collect();
            let more = many.len().saturating_sub(UNUSABLE_NAMED);
            let rest = if more > 0 {
                format!(" and {more} more")
            } else {
                String::new()
            };
            Some(format!(
                "{} keys were stored by another program (usually another morsec build, such as a \
                 dev build), and the keychain lets only that program use them: {}{rest}. Remove \
                 each with: {} (macOS asks for your login password), then add it again: ms add \
                 <name>. If you never used another build, something else wrote into morsec's \
                 keychain entries",
                many.len(),
                shown.join(", "),
                removal_command(&KeyName::new("name").expect("valid"))
                    .replace(" -a name ", " -a <name> "),
            ))
        }
    }
}
