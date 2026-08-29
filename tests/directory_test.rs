//! Round trips for directory encryption: archive mode (one .shadow per
//! directory) and recursive mode (one .shadow per file, paths preserved).

mod common;

use std::fs;
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use common::{TEST_PASSWORD, decrypt_files, encrypt_files, encrypt_paths, find_shadow_files};
use tempfile::TempDir;

/// Builds a small tree:
/// photos/
/// ├── a.txt          ("alpha")
/// ├── empty.bin      (empty)
/// ├── empty-dir/
/// └── sub/
///     └── b.txt      ("bravo bravo")
fn build_tree(parent: &Path) -> std::path::PathBuf {
    let root = parent.join("photos");
    fs::create_dir_all(root.join("sub")).unwrap();
    fs::create_dir_all(root.join("empty-dir")).unwrap();
    fs::write(root.join("a.txt"), b"alpha").unwrap();
    fs::write(root.join("empty.bin"), b"").unwrap();
    fs::write(root.join("sub").join("b.txt"), b"bravo bravo").unwrap();
    root
}

fn assert_tree_restored(root: &Path, expect_empty_dir: bool) {
    assert_eq!(fs::read(root.join("a.txt")).unwrap(), b"alpha");
    assert_eq!(fs::read(root.join("empty.bin")).unwrap(), b"");
    assert_eq!(
        fs::read(root.join("sub").join("b.txt")).unwrap(),
        b"bravo bravo"
    );
    assert_eq!(root.join("empty-dir").is_dir(), expect_empty_dir);
}

#[test]
fn test_directory_archive_round_trip() {
    let src_dir = TempDir::new().unwrap();
    let root = build_tree(src_dir.path());

    // Stamp metadata to verify it survives the archive.
    let mtime = UNIX_EPOCH + Duration::new(1_500_000_000, 0);
    fs::File::open(root.join("sub").join("b.txt"))
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root.join("a.txt"), fs::Permissions::from_mode(0o600)).unwrap();
    }

    let enc_dir = TempDir::new().unwrap();
    encrypt_files(&[&root], TEST_PASSWORD, enc_dir.path()).unwrap();

    // The whole tree becomes exactly one .shadow file.
    let shadows = find_shadow_files(enc_dir.path());
    assert_eq!(shadows.len(), 1);

    let out_dir = TempDir::new().unwrap();
    decrypt_files(&[&shadows[0]], TEST_PASSWORD, out_dir.path()).unwrap();

    let restored = out_dir.path().join("photos");
    assert_tree_restored(&restored, true);

    // Per-entry metadata came back.
    assert_eq!(
        fs::metadata(restored.join("sub").join("b.txt"))
            .unwrap()
            .modified()
            .unwrap(),
        mtime
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(restored.join("a.txt"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
    }
}

#[test]
fn test_directory_archive_no_overwrite_without_force() {
    let src_dir = TempDir::new().unwrap();
    let root = build_tree(src_dir.path());

    let enc_dir = TempDir::new().unwrap();
    encrypt_files(&[&root], TEST_PASSWORD, enc_dir.path()).unwrap();
    let shadows = find_shadow_files(enc_dir.path());

    let out_dir = TempDir::new().unwrap();
    decrypt_files(&[&shadows[0]], TEST_PASSWORD, out_dir.path()).unwrap();
    // Extracting again into the same place must fail (root dir exists).
    assert!(decrypt_files(&[&shadows[0]], TEST_PASSWORD, out_dir.path()).is_err());
}

#[test]
fn test_directory_recursive_round_trip() {
    let src_dir = TempDir::new().unwrap();
    let root = build_tree(src_dir.path());

    let enc_dir = TempDir::new().unwrap();
    encrypt_paths(&[&root], TEST_PASSWORD, enc_dir.path(), true).unwrap();

    // One .shadow per file (three files; empty dirs are not represented).
    let shadows = find_shadow_files(enc_dir.path());
    assert_eq!(shadows.len(), 3);

    let out_dir = TempDir::new().unwrap();
    let shadow_refs: Vec<&Path> = shadows.iter().map(|p| p.as_path()).collect();
    decrypt_files(&shadow_refs, TEST_PASSWORD, out_dir.path()).unwrap();

    let restored = out_dir.path().join("photos");
    assert_tree_restored(&restored, false);
}

#[test]
fn test_empty_directory_archive_round_trip() {
    let src_dir = TempDir::new().unwrap();
    let root = src_dir.path().join("hollow");
    fs::create_dir(&root).unwrap();

    let enc_dir = TempDir::new().unwrap();
    encrypt_files(&[&root], TEST_PASSWORD, enc_dir.path()).unwrap();
    let shadows = find_shadow_files(enc_dir.path());
    assert_eq!(shadows.len(), 1);

    let out_dir = TempDir::new().unwrap();
    decrypt_files(&[&shadows[0]], TEST_PASSWORD, out_dir.path()).unwrap();
    assert!(out_dir.path().join("hollow").is_dir());
}

#[test]
fn test_delete_removes_original_file_after_encryption() {
    let temp_dir = TempDir::new().unwrap();
    let input_file = temp_dir.path().join("secret.txt");
    fs::write(&input_file, b"delete me after").unwrap();

    common::encrypt_with_options(&[&input_file], TEST_PASSWORD, temp_dir.path(), false, true)
        .unwrap();

    assert!(!input_file.exists(), "original must be deleted");
    let shadows = find_shadow_files(temp_dir.path());
    assert_eq!(shadows.len(), 1);

    // The encrypted copy still restores the content.
    decrypt_files(&[&shadows[0]], TEST_PASSWORD, temp_dir.path()).unwrap();
    assert_eq!(fs::read(&input_file).unwrap(), b"delete me after");
}

#[test]
fn test_delete_removes_original_directory_after_archiving() {
    let src_dir = TempDir::new().unwrap();
    let root = build_tree(src_dir.path());

    let enc_dir = TempDir::new().unwrap();
    common::encrypt_with_options(&[&root], TEST_PASSWORD, enc_dir.path(), false, true).unwrap();

    assert!(!root.exists(), "original tree must be deleted");

    let shadows = find_shadow_files(enc_dir.path());
    let out_dir = TempDir::new().unwrap();
    decrypt_files(&[&shadows[0]], TEST_PASSWORD, out_dir.path()).unwrap();
    assert_tree_restored(&out_dir.path().join("photos"), true);
}
