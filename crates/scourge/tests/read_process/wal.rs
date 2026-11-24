use std::{
    os::unix::fs::{MetadataExt, symlink},
    sync::{
        Arc, Barrier,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use scourge_core::store::checks::{RecordedCheck, Stage};

use super::*;

type FileSnapshot = (u64, u64, Vec<u8>);

pub(super) fn snapshot_family(path: &Path) -> [FileSnapshot; 3] {
    [
        path.to_owned(),
        path.with_file_name("state.sqlite3-wal"),
        path.with_file_name("state.sqlite3-shm"),
    ]
    .map(|name| {
        let metadata = fs::metadata(&name).unwrap();
        (metadata.dev(), metadata.ino(), fs::read(name).unwrap())
    })
}

pub(super) fn damaged_sidecars(fixture: &Fixture) {
    let root = fixture.dir.path().join("sidecar fixture");
    let state = &fixture.state;
    let declaration = fixture.dir.path().join(format!("{SCOPE}.toml"));
    let created = stock_command(fixture.dir.path(), state)
        .args(["init", "--json"])
        .arg(&root)
        .arg("--engagement")
        .arg(declaration)
        .output()
        .unwrap();
    assert!(response(&created, 0).0.ok);
    let path = root.join(".scourge/state.sqlite3");
    let mut writer = Store::open(&path).unwrap();
    seed_lead(&mut writer, SCOPE, "L-first", 1);
    drop(writer);
    let read = || {
        stock_command(&root, state)
            .args(["list", "--json"])
            .output()
            .unwrap()
    };
    assert_eq!(response(&read(), 0).1["leads"][0]["id"], "L-first");

    let wal = path.with_file_name("state.sqlite3-wal");
    let shm = path.with_file_name("state.sqlite3-shm");
    let wal_copy = path.with_file_name("wal-saved");
    let shm_copy = path.with_file_name("shm-saved");
    let baseline = snapshot_family(&path);
    let assert_integrity = || {
        let (view, _) = response(&read(), 6);
        assert_eq!(view.error.unwrap().code, ErrorCode::IntegrityFailure);
    };
    for (remove_wal, remove_shm) in [(true, false), (false, true), (true, true)] {
        if remove_wal {
            fs::rename(&wal, &wal_copy).unwrap();
        }
        if remove_shm {
            fs::rename(&shm, &shm_copy).unwrap();
        }
        assert_integrity();
        if remove_wal {
            assert!(!wal.exists());
            fs::rename(&wal_copy, &wal).unwrap();
        }
        if remove_shm {
            assert!(!shm.exists());
            fs::rename(&shm_copy, &shm).unwrap();
        }
        assert_eq!(snapshot_family(&path), baseline);
    }

    for (failed, backup, bad_bytes) in [
        (&wal, &wal_copy, &baseline[1].2[..8]),
        (
            &wal,
            &wal_copy,
            b"truncated but foreign SQL header; no SQLite magic".as_slice(),
        ),
        (&shm, &shm_copy, b"truncated-shm!".as_slice()),
    ] {
        fs::rename(failed, backup).unwrap();
        fs::write(failed, bad_bytes).unwrap();
        fs::set_permissions(failed, fs::metadata(backup).unwrap().permissions()).unwrap();
        let corrupted = snapshot_family(&path);
        assert_integrity();
        assert_eq!(snapshot_family(&path), corrupted);
        fs::remove_file(failed).unwrap();
        fs::rename(backup, failed).unwrap();
    }

    for (failed, backup) in [(&wal, &wal_copy), (&shm, &shm_copy)] {
        fs::rename(failed, backup).unwrap();
        fs::create_dir(failed).unwrap();
        assert_integrity();
        assert!(failed.is_dir());
        fs::remove_dir(failed).unwrap();
        symlink(backup, failed).unwrap();
        assert_integrity();
        assert_eq!(fs::read_link(failed).unwrap(), *backup);
        fs::remove_file(failed).unwrap();
        fs::rename(backup, failed).unwrap();
    }
    assert_eq!(snapshot_family(&path), baseline);
    assert_eq!(response(&read(), 0).1["leads"][0]["id"], "L-first");
    assert_eq!(snapshot_family(&path), baseline);
}

#[cfg(target_os = "linux")]
pub(super) fn concurrent_doctor(fixture: &Fixture, guarded: impl Fn() -> Command) {
    let path = &fixture.path;
    let mut writer = Store::open(path).unwrap();
    let ready = Arc::new(Barrier::new(2));
    let stop = Arc::new(AtomicBool::new(false));
    std::thread::scope(|scope| {
        let ready_writer = Arc::clone(&ready);
        let stop_writer = Arc::clone(&stop);
        let handle = scope.spawn(move || {
            let engagement = SCOPE.parse().unwrap();
            let mut check = RecordedCheck {
                stage: Stage::DryRun,
                observed_at: "1970-01-01T00:00:01Z".parse().unwrap(),
                code: None,
                native_exit: Some(0),
                wrapper_exit: None,
                run_id: None,
            };
            writer.record_check(&engagement, &check).unwrap();
            ready_writer.wait();
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut updates = 1;
            while !stop_writer.load(Ordering::Relaxed) && Instant::now() < deadline {
                check.observed_at = format!("1970-01-01T00:00:02.{updates:09}Z")
                    .parse()
                    .unwrap();
                writer.record_check(&engagement, &check).unwrap();
                updates += 1;
            }
            updates
        });
        ready.wait();
        let scope_args = [
            "--workspace",
            fixture.root.to_str().unwrap(),
            "--engagement",
            SCOPE,
            "doctor",
            "--json",
        ];
        let mut completed = 0;
        for _ in 0..80 {
            let output = guarded().args(scope_args).output().unwrap();
            match output.status.code() {
                Some(0) => {
                    doctor::stock_populated(&output);
                    completed += 1;
                }
                Some(4) => {
                    assert_eq!(
                        response(&output, 4).0.error.unwrap().code,
                        ErrorCode::ConflictingRun
                    );
                }
                _ => {
                    panic!("ordinary concurrent writer yielded an unexpected response: {output:?}")
                }
            }
        }
        stop.store(true, Ordering::Relaxed);
        assert!(handle.join().unwrap() > 1);
        assert!(completed > 0);
        let before = snapshot_family(path);
        doctor::stock_populated(&guarded().args(scope_args).output().unwrap());
        assert_eq!(snapshot_family(path), before);
    });
}
