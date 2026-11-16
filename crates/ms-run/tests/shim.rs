//! The `ms-shim` binary: pass-through without a ref, no loops through shim directories, and
//! fail closed when the daemon is down.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

fn shim() -> &'static str {
    env!("CARGO_BIN_EXE_ms-shim")
}

fn place_shim(dir: &Path, name: &str) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::copy(shim(), dir.join(name)).unwrap();
}

fn script(dir: &Path, name: &str, body: &str) {
    std::fs::create_dir_all(dir).unwrap();
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

// protects=D6: without a ref the shim execs the next real binary of its name on PATH with the
// same arguments, environment and exit code; two shim directories (even one listed twice) don't
// loop; fails_when=the real tool doesn't run, args/exit code change, or the shim recurses;
// no_claim=forwarding (e2e run_mode_through_shims)
#[test]
fn passes_through_without_looping() {
    let d = tempfile::tempdir().unwrap();
    let (a, b, real) = (
        d.path().join("a"),
        d.path().join("b"),
        d.path().join("real"),
    );
    place_shim(&a, "tool");
    place_shim(&b, "tool");
    script(&real, "tool", "echo \"real:$*:$KEEP\"; exit 5");
    let path = std::env::join_paths([&a, &b, &a, &real, Path::new("/usr/bin"), Path::new("/bin")])
        .unwrap();
    let out = Command::new(a.join("tool"))
        .args(["x y", "--z"])
        .env_clear()
        .env("PATH", &path)
        .env("KEEP", "kept")
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "real:x y --z:kept\n");
    assert_eq!(out.status.code(), Some(5));

    // Only shims on PATH: "not found", not an endless exec chain.
    let only = std::env::join_paths([&a, &b, &a]).unwrap();
    let out = Command::new(a.join("tool"))
        .env_clear()
        .env("PATH", &only)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(127));
    assert!(String::from_utf8_lossy(&out.stderr).contains("command not found"));
}

// protects=D6 fail closed: with a ref present and msd unreachable, the shim refuses (69) and does
// not run the real tool; called as ms-shim it explains itself (64); fails_when=the tool runs or
// the exit is 0; no_claim=-
#[test]
fn ref_without_daemon_fails_closed() {
    let d = tempfile::tempdir().unwrap();
    let (a, real) = (d.path().join("a"), d.path().join("real"));
    place_shim(&a, "tool");
    let ran = d.path().join("ran");
    script(&real, "tool", &format!("touch '{}'", ran.display()));
    let path = std::env::join_paths([&a, &real]).unwrap();
    for (args, env) in [
        (vec!["--token=ms://svc/prod"], None),
        (vec![], Some(("TOKEN", "ms://svc/prod"))),
    ] {
        let mut cmd = Command::new(a.join("tool"));
        cmd.args(&args)
            .env_clear()
            .env("PATH", &path)
            .env("MORSEC_SOCKET", d.path().join("no.sock"));
        if let Some((k, v)) = env {
            cmd.env(k, v);
        }
        let out = cmd.output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(69),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(String::from_utf8_lossy(&out.stderr).contains("daemon not running"));
        assert!(!ran.exists(), "the real tool ran with a raw ref");
    }
    let out = Command::new(shim()).output().unwrap();
    assert_eq!(out.status.code(), Some(64));
}

// protects=launchagent-opt-path: a shim that is a symlink into a Homebrew-style prefix
// (shims/tool -> <prefix>/opt/morsec/bin/ms-shim, opt/morsec -> ../Cellar/morsec/<ver>) still
// passes through to the real tool without looping, still fails closed with a ref and no msd, and
// keeps working after the opt link moves to a new version and the old keg is deleted;
// fails_when=the symlinked shim recurses, runs the tool with a ref, or breaks on upgrade;
// no_claim=brew itself (a fake prefix, brew never runs)
#[test]
fn symlinked_through_opt_survives_upgrade() {
    let d = tempfile::tempdir().unwrap();
    let prefix = std::fs::canonicalize(d.path()).unwrap();
    let keg = |v: &str| prefix.join("Cellar/morsec").join(v).join("bin");
    place_shim(&keg("1.0.0"), "ms-shim");
    std::fs::create_dir_all(prefix.join("opt")).unwrap();
    std::os::unix::fs::symlink("../Cellar/morsec/1.0.0", prefix.join("opt/morsec")).unwrap();
    let shims = prefix.join("shims");
    std::fs::create_dir_all(&shims).unwrap();
    std::os::unix::fs::symlink(prefix.join("opt/morsec/bin/ms-shim"), shims.join("tool")).unwrap();
    let real = prefix.join("real");
    script(&real, "tool", "echo \"real:$*\"; exit 3");
    let ran = prefix.join("ran");
    script(&real, "guarded", &format!("touch '{}'", ran.display()));
    std::os::unix::fs::symlink(prefix.join("opt/morsec/bin/ms-shim"), shims.join("guarded"))
        .unwrap();
    // The shim directory twice, and the keg's bin too: still no loop.
    let path = std::env::join_paths([&shims, &keg("1.0.0"), &shims, &real]).unwrap();
    let run = |args: &[&str]| {
        // Through PATH lookup, as an agent's shell does: argv[0] is the bare name.
        Command::new("/bin/sh")
            .arg("-c")
            .arg("\"$@\"")
            .arg("sh")
            .args(args)
            .env_clear()
            .env("PATH", &path)
            .env("MORSEC_SOCKET", prefix.join("no.sock"))
            .output()
            .unwrap()
    };
    let out = run(&["tool", "a b"]);
    assert_eq!(String::from_utf8_lossy(&out.stdout), "real:a b\n");
    assert_eq!(out.status.code(), Some(3));
    let out = run(&["guarded", "--token=ms://svc/prod"]);
    assert_eq!(out.status.code(), Some(69));
    assert!(!ran.exists());

    // brew upgrade: new keg, opt moved, old keg deleted. The same symlinks keep working.
    place_shim(&keg("1.1.0"), "ms-shim");
    std::fs::remove_file(prefix.join("opt/morsec")).unwrap();
    std::os::unix::fs::symlink("../Cellar/morsec/1.1.0", prefix.join("opt/morsec")).unwrap();
    std::fs::remove_dir_all(prefix.join("Cellar/morsec/1.0.0")).unwrap();
    let out = run(&["tool", "after"]);
    assert_eq!(String::from_utf8_lossy(&out.stdout), "real:after\n");
    assert_eq!(out.status.code(), Some(3));
}

// protects=every ms-shim build carries ms_run::SHIM_MARKER, which `ms run --link-shims` uses to
// recognise and replace shims left by an older version; fails_when=the marker is not in the
// binary; no_claim=-
#[test]
fn binary_carries_the_marker() {
    let bytes = std::fs::read(shim()).unwrap();
    let m = ms_run::SHIM_MARKER.as_bytes();
    assert!(bytes.windows(m.len()).any(|w| w == m));
    let out = Command::new(shim()).output().unwrap();
    assert_eq!(out.status.code(), Some(64));
    assert!(String::from_utf8_lossy(&out.stderr).contains(ms_run::SHIM_MARKER));
}
