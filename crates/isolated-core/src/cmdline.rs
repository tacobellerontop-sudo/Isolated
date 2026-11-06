//! Windows command-line building and target classification. Pure functions
//! so they can be tested on any platform.

/// Quotes one argument following the rules `CommandLineToArgvW` and the MSVC
/// runtime use to split a command line.
pub fn quote_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '\n', '\u{b}', '"']) {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
    out
}

/// Joins a program and its arguments into one command line.
pub fn join(program: &str, args: &[String]) -> String {
    let mut s = quote_arg(program);
    for a in args {
        s.push(' ');
        s.push_str(&quote_arg(a));
    }
    s
}

/// What kind of file a launch target is, by extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    Executable,
    Shortcut,
    BatchScript,
    PowerShellScript,
    Installer,
    Unsupported,
}

pub fn classify(path: &str) -> TargetKind {
    let ext = path
        .rsplit(['\\', '/'])
        .next()
        .and_then(|name| name.rsplit_once('.'))
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "exe" | "com" | "scr" => TargetKind::Executable,
        "lnk" => TargetKind::Shortcut,
        "bat" | "cmd" => TargetKind::BatchScript,
        "ps1" => TargetKind::PowerShellScript,
        "msi" | "msix" | "appx" | "msixbundle" | "appxbundle" => TargetKind::Installer,
        _ => TargetKind::Unsupported,
    }
}

/// Command line that runs a batch file through `cmd.exe`. Uses `/s` with an
/// outer pair of quotes so paths with spaces and quotes survive.
pub fn batch_command_line(cmd_exe: &str, script: &str, args: &[String]) -> String {
    let mut inner = quote_arg_always(script);
    for a in args {
        inner.push(' ');
        inner.push_str(&quote_arg(a));
    }
    format!("{} /d /s /c \"{}\"", quote_arg(cmd_exe), inner)
}

fn quote_arg_always(a: &str) -> String {
    let q = quote_arg(a);
    if q.starts_with('"') {
        q
    } else {
        format!("\"{q}\"")
    }
}

/// Splits a command-line argument string the way programs usually do.
pub fn split(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    let mut have = false;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let mut n = 1;
                while chars.peek() == Some(&'\\') {
                    chars.next();
                    n += 1;
                }
                if chars.peek() == Some(&'"') {
                    cur.extend(std::iter::repeat_n('\\', n / 2));
                    if n % 2 == 1 {
                        chars.next();
                        cur.push('"');
                    }
                } else {
                    cur.extend(std::iter::repeat_n('\\', n));
                }
                have = true;
            }
            '"' => {
                in_q = !in_q;
                have = true;
            }
            ' ' | '\t' if !in_q => {
                if have {
                    out.push(std::mem::take(&mut cur));
                    have = false;
                }
            }
            _ => {
                cur.push(c);
                have = true;
            }
        }
    }
    if have {
        out.push(cur);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(quote_arg("simple"), "simple");
        assert_eq!(quote_arg(""), "\"\"");
        assert_eq!(quote_arg("a b"), "\"a b\"");
        assert_eq!(quote_arg(r#"say "hi""#), r#""say \"hi\"""#);
        assert_eq!(quote_arg(r"C:\dir with space\"), r#""C:\dir with space\\""#);
        assert_eq!(quote_arg(r"C:\no\space"), r"C:\no\space");
        assert_eq!(
            join(r"C:\Program Files\x.exe", &["-a".into(), "b c".into()]),
            r#""C:\Program Files\x.exe" -a "b c""#
        );
    }

    #[test]
    fn kinds() {
        assert_eq!(classify(r"C:\a\B.EXE"), TargetKind::Executable);
        assert_eq!(classify(r"C:\a\x.lnk"), TargetKind::Shortcut);
        assert_eq!(classify(r"C:\a.b\run.cmd"), TargetKind::BatchScript);
        assert_eq!(classify(r"C:\a\s.ps1"), TargetKind::PowerShellScript);
        assert_eq!(classify(r"C:\a\setup.msi"), TargetKind::Installer);
        assert_eq!(classify(r"C:\a.exe\noext"), TargetKind::Unsupported);
    }

    #[test]
    fn batch() {
        assert_eq!(
            batch_command_line(r"C:\Windows\System32\cmd.exe", r"C:\my dir\go.bat", &["x".into()]),
            r#"C:\Windows\System32\cmd.exe /d /s /c ""C:\my dir\go.bat" x""#
        );
    }
}
