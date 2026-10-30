//! T4-T5: what the deployment-facing commands (`login`, `logout`, `targets`,
//! `model`, `data`) share: `--json` output with a schema version, the
//! confirmation a writing command needs, and shell completion scripts.
//!
//! **JSON.** With `--json` a command prints one JSON object on standard
//! output, `{"schema_version": 1, "kind": "<command>", ...}`; anything meant
//! for a person (a sign-in code) goes to standard error. A new field may be
//! added within a version; a field is never renamed or removed without
//! raising `schema_version`.
//!
//! **Confirmation.** A command that writes to a deployment (`model import`,
//! `data import`) runs only with `--yes`; on a target marked production
//! (`attome login --production`) it also needs `--confirm-target <name>`,
//! naming that target, so a command copied from a staging session cannot
//! write to production by accident.
//!
//! **Completions.** `attome completions powershell|bash|zsh` prints a
//! completion script for the subcommands and their flags.

use serde_json::{Map, Value};

/// The `schema_version` of every `--json` output.
pub const SCHEMA_VERSION: u32 = 1;

/// Removes `flag` from `args`; whether it was there. Pure.
pub fn take_flag(args: &mut Vec<String>, flag: &str) -> bool {
    let before = args.len();
    args.retain(|a| a != flag);
    args.len() != before
}

/// Removes `flag <value>` from `args`; the value, if the flag was there. Pure.
pub fn take_value(args: &mut Vec<String>, flag: &str) -> Result<Option<String>, String> {
    let Some(at) = args.iter().position(|a| a == flag) else {
        return Ok(None);
    };
    if at + 1 >= args.len() {
        return Err(format!("{flag} needs a value"));
    }
    let value = args.remove(at + 1);
    args.remove(at);
    Ok(Some(value))
}

/// `{"schema_version": 1, "kind": kind, ...fields}`. Pure.
pub fn envelope(kind: &str, fields: Value) -> Value {
    let mut out = Map::new();
    out.insert("schema_version".into(), Value::from(SCHEMA_VERSION));
    out.insert("kind".into(), Value::from(kind));
    if let Value::Object(fields) = fields {
        for (key, value) in fields {
            out.entry(key).or_insert(value);
        }
    }
    Value::Object(out)
}

/// Whether a writing command may run: `--yes`, and on a production target
/// `--confirm-target` naming it. `target` is the target's name and whether
/// it is production; `None` when the command names a URL instead. Pure.
pub fn confirm(
    what: &str,
    yes: bool,
    confirm_target: Option<&str>,
    target: Option<(&str, bool)>,
) -> Result<(), String> {
    if !yes {
        return Err(format!(
            "{what} writes to the deployment; run it again with --yes"
        ));
    }
    if let Some((name, true)) = target
        && confirm_target != Some(name)
    {
        return Err(format!(
            "`{name}` is a production target; add --confirm-target {name} to {what} there"
        ));
    }
    Ok(())
}

/// The subcommands and their flags, for completion.
const COMMANDS: &[(&str, &[&str])] = &[
    ("login", &["--target", "--url", "--production", "--json"]),
    ("logout", &["--target", "--json"]),
    ("targets", &["--json"]),
    (
        "model",
        &[
            "export",
            "import",
            "--out",
            "--dir",
            "--target",
            "--url",
            "--api-key",
            "--yes",
            "--confirm-target",
            "--json",
        ],
    ),
    (
        "data",
        &[
            "query",
            "export",
            "import",
            "--where",
            "--fields",
            "--limit",
            "--format",
            "--out",
            "--file",
            "--target",
            "--url",
            "--api-key",
            "--yes",
            "--confirm-target",
            "--json",
        ],
    ),
    (
        "package",
        &[
            "keygen",
            "build",
            "publish",
            "install",
            "--out",
            "--key",
            "--to",
            "--from",
            "--trust",
            "--trust-file",
            "--target",
            "--url",
            "--yes",
            "--confirm-target",
            "--json",
        ],
    ),
    (
        "flags",
        &[
            "list",
            "get",
            "set",
            "off-now",
            "on",
            "off",
            "--description",
            "--target",
            "--url",
            "--yes",
            "--confirm-target",
            "--json",
        ],
    ),
    ("init", &["--database-url", "--out", "--port", "--force"]),
    ("serve", &[]),
    ("worker", &[]),
    ("migrate", &[]),
    ("doctor", &[]),
    ("preflight", &[]),
    ("healthcheck", &[]),
    ("backup", &["now", "drill"]),
    ("restore", &["--yes"]),
    ("scratch", &["create", "--mode", "--percent"]),
    ("service", &["install", "uninstall", "--dir", "--dry-run"]),
    ("completions", &["powershell", "bash", "zsh"]),
];

/// The completion script for `shell`.
pub fn completions(shell: &str) -> Result<String, String> {
    let names: Vec<&str> = COMMANDS.iter().map(|(name, _)| *name).collect();
    match shell {
        "bash" => {
            let mut cases = String::new();
            for (name, flags) in COMMANDS {
                cases.push_str(&format!("    {name}) words=\"{}\" ;;\n", flags.join(" ")));
            }
            Ok(format!(
                "# attome bash completion: source <(attome completions bash)\n_attome() {{\n  local cur=\"${{COMP_WORDS[COMP_CWORD]}}\" words\n  if [ \"$COMP_CWORD\" -eq 1 ]; then\n    words=\"{}\"\n  else\n    case \"${{COMP_WORDS[1]}}\" in\n{cases}    *) words=\"\" ;;\n    esac\n  fi\n  COMPREPLY=($(compgen -W \"$words\" -- \"$cur\"))\n}}\ncomplete -F _attome attome\n",
                names.join(" ")
            ))
        }
        "zsh" => {
            let mut cases = String::new();
            for (name, flags) in COMMANDS {
                cases.push_str(&format!("    {name}) compadd -- {} ;;\n", flags.join(" ")));
            }
            Ok(format!(
                "#compdef attome\n# attome zsh completion: attome completions zsh > \"${{fpath[1]}}/_attome\"\n_attome() {{\n  if (( CURRENT == 2 )); then\n    compadd -- {}\n    return\n  fi\n  case \"${{words[2]}}\" in\n{cases}  esac\n}}\n_attome \"$@\"\n",
                names.join(" ")
            ))
        }
        "powershell" => {
            let mut table = String::new();
            for (name, flags) in COMMANDS {
                let quoted: Vec<String> = flags.iter().map(|f| format!("'{f}'")).collect();
                table.push_str(&format!("    '{name}' = @({})\n", quoted.join(", ")));
            }
            let quoted: Vec<String> = names.iter().map(|n| format!("'{n}'")).collect();
            Ok(format!(
                "# attome PowerShell completion: attome completions powershell | Out-String | Invoke-Expression\n$attomeFlags = @{{\n{table}}}\nRegister-ArgumentCompleter -Native -CommandName attome -ScriptBlock {{\n  param($wordToComplete, $commandAst, $cursorPosition)\n  $words = $commandAst.CommandElements | ForEach-Object {{ $_.ToString() }}\n  if ($words.Count -le 2 -and -not $wordToComplete.StartsWith('-')) {{ $candidates = @({}) }}\n  else {{ $candidates = $attomeFlags[$words[1]] }}\n  $candidates | Where-Object {{ $_ -like \"$wordToComplete*\" }} | ForEach-Object {{\n    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)\n  }}\n}}\n",
                quoted.join(", ")
            ))
        }
        other => Err(format!(
            "completions are for powershell, bash or zsh, not `{other}`"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|a| (*a).to_owned()).collect()
    }

    #[test]
    fn flags_are_taken_out_of_the_arguments() {
        let mut a = args(&["import", "--yes", "--dir", "m", "--confirm-target", "prod"]);
        assert!(take_flag(&mut a, "--yes"));
        assert!(!take_flag(&mut a, "--json"));
        assert_eq!(
            take_value(&mut a, "--confirm-target"),
            Ok(Some("prod".into()))
        );
        assert_eq!(a, args(&["import", "--dir", "m"]));
        assert!(take_value(&mut args(&["--confirm-target"]), "--confirm-target").is_err());
    }

    #[test]
    fn json_output_carries_its_schema_version() {
        let out = envelope(
            "targets",
            serde_json::json!({ "default": "prod", "kind": "ignored" }),
        );
        assert_eq!(out["schema_version"], 1);
        assert_eq!(out["kind"], "targets");
        assert_eq!(out["default"], "prod");
    }

    #[test]
    fn writing_needs_yes_and_production_needs_its_name() {
        assert!(confirm("model import", false, None, None).is_err());
        assert!(confirm("model import", true, None, None).is_ok());
        assert!(confirm("model import", true, None, Some(("staging", false))).is_ok());
        assert!(confirm("model import", true, None, Some(("prod", true))).is_err());
        assert!(confirm("model import", true, Some("staging"), Some(("prod", true))).is_err());
        assert!(confirm("model import", true, Some("prod"), Some(("prod", true))).is_ok());
    }

    #[test]
    fn completions_name_every_command() {
        for shell in ["bash", "zsh", "powershell"] {
            let script = completions(shell).unwrap_or_default();
            for (name, _) in COMMANDS {
                assert!(script.contains(name), "{shell} lacks {name}");
            }
            assert!(script.contains("--confirm-target"), "{shell}");
        }
        assert!(completions("fish").is_err());
    }
}
