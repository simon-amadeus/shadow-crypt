use std::path::PathBuf;

use shadow_crypt_core::profile::SecurityProfile;

use crate::{
    encryption::{
        cli::EncryptionCliArgs,
        file::{EncryptionInputFile, InputKind},
        file_ops::walk_directory,
    },
    errors::{WorkflowError, WorkflowResult},
    ui::display_warning,
};

pub struct ValidEncryptionArgs {
    pub files: Vec<EncryptionInputFile>,
    pub security_profile: SecurityProfile,
    pub output_dir: Option<PathBuf>,
    pub password_file: Option<PathBuf>,
}

pub fn validate_input(input: EncryptionCliArgs) -> WorkflowResult<ValidEncryptionArgs> {
    if input.input_files.is_empty() {
        return Err(WorkflowError::UserInput(
            "No input files provided".to_string(),
        ));
    }

    let mut validated_files: Vec<EncryptionInputFile> = Vec::new();
    for raw in &input.input_files {
        validate_path(PathBuf::from(raw), input.recursive, &mut validated_files)?;
    }

    Ok(ValidEncryptionArgs {
        files: validated_files,
        security_profile: input.profile.into(),
        output_dir: input.output_dir,
        password_file: input.password_file,
    })
}

fn validate_path(
    path: PathBuf,
    recursive: bool,
    out: &mut Vec<EncryptionInputFile>,
) -> WorkflowResult<()> {
    if !path.exists() {
        return Err(WorkflowError::UserInput(format!(
            "Input path does not exist: {}",
            path.display()
        )));
    }

    let name = path_name(&path)?;

    if path.is_dir() {
        if recursive {
            // Expand the directory into individual file items, each storing
            // its path relative to the directory's parent (so decryption
            // recreates the tree including the top directory).
            let (entries, skipped) = walk_directory(&path)?;
            if skipped > 0 {
                display_warning(&format!(
                    "Skipped {} unsupported entr{} (symlinks, special files) in '{}'",
                    skipped,
                    if skipped == 1 { "y" } else { "ies" },
                    path.display()
                ));
            }
            for entry in entries.iter().filter(|e| !e.is_dir) {
                out.push(EncryptionInputFile {
                    path: entry.path.clone(),
                    filename: format!("{name}/{}", entry.rel),
                    size: entry.size,
                    kind: InputKind::File,
                });
            }
        } else {
            out.push(EncryptionInputFile {
                path,
                filename: name,
                size: 0,
                kind: InputKind::Directory,
            });
        }
        return Ok(());
    }

    if !path.is_file() {
        return Err(WorkflowError::UserInput(format!(
            "Input path is not a file or directory: {}",
            path.display()
        )));
    }

    let size: u64 = path
        .metadata()
        .map_err(|_| {
            WorkflowError::UserInput(format!(
                "Unable to read metadata for file: {}",
                path.display()
            ))
        })?
        .len();

    out.push(EncryptionInputFile {
        path,
        filename: name,
        size,
        kind: InputKind::File,
    });
    Ok(())
}

fn path_name(path: &std::path::Path) -> WorkflowResult<String> {
    Ok(path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| {
            WorkflowError::UserInput(format!("Invalid filename for path: {}", path.display()))
        })?
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_validate_input_no_files() {
        let input = EncryptionCliArgs {
            input_files: vec![],
            ..Default::default()
        };
        let result = validate_input(input);
        assert!(result.is_err());
        if let Err(WorkflowError::UserInput(msg)) = result {
            assert_eq!(msg, "No input files provided");
        } else {
            panic!("Expected UserInput error");
        }
    }

    #[test]
    fn test_validate_input_file_does_not_exist() {
        let input = EncryptionCliArgs {
            input_files: vec!["nonexistent_file.txt".to_string()],
            ..Default::default()
        };
        let result = validate_input(input);
        assert!(result.is_err());
        if let Err(WorkflowError::UserInput(msg)) = result {
            assert!(msg.contains("Input path does not exist"));
        } else {
            panic!("Expected UserInput error");
        }
    }

    #[test]
    fn test_validate_input_directory_becomes_archive_item() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dir = temp_dir.path().join("photos");
        std::fs::create_dir(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"a").unwrap();

        let input = EncryptionCliArgs {
            input_files: vec![dir.to_str().unwrap().to_string()],
            ..Default::default()
        };
        let valid = validate_input(input).unwrap();
        assert_eq!(valid.files.len(), 1);
        assert_eq!(valid.files[0].kind, InputKind::Directory);
        assert_eq!(valid.files[0].filename, "photos");
    }

    #[test]
    fn test_validate_input_directory_recursive_expands_files() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dir = temp_dir.path().join("photos");
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(dir.join("a.txt"), b"aaa").unwrap();
        std::fs::write(dir.join("sub").join("b.txt"), b"b").unwrap();

        let input = EncryptionCliArgs {
            input_files: vec![dir.to_str().unwrap().to_string()],
            recursive: true,
            ..Default::default()
        };
        let valid = validate_input(input).unwrap();

        let mut names: Vec<(String, u64)> = valid
            .files
            .iter()
            .map(|f| (f.filename.clone(), f.size))
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec![
                ("photos/a.txt".to_string(), 3),
                ("photos/sub/b.txt".to_string(), 1),
            ]
        );
        assert!(valid.files.iter().all(|f| f.kind == InputKind::File));
    }

    #[test]
    fn test_validate_input_valid_file() {
        let mut temp_file = NamedTempFile::new().unwrap();
        let content = b"Hello, world!";
        temp_file.write_all(content).unwrap();
        let file_path = temp_file.path().to_path_buf();

        let input = EncryptionCliArgs {
            input_files: vec![file_path.to_str().unwrap().to_string()],
            profile: crate::encryption::cli::CliProfile::Test,
            ..Default::default()
        };
        let result = validate_input(input);
        assert!(result.is_ok());
        let valid_args = result.unwrap();
        assert_eq!(valid_args.files.len(), 1);
        assert_eq!(valid_args.security_profile, SecurityProfile::Test);
        let file = &valid_args.files[0];
        assert_eq!(file.path, file_path);
        assert_eq!(
            file.filename,
            file_path.file_name().unwrap().to_str().unwrap()
        );
        assert_eq!(file.size, content.len() as u64);
    }

    #[test]
    fn test_validate_input_multiple_files() {
        let mut temp_file1 = NamedTempFile::new().unwrap();
        temp_file1.write_all(b"File 1").unwrap();
        let path1 = temp_file1.path().to_path_buf();

        let mut temp_file2 = NamedTempFile::new().unwrap();
        temp_file2.write_all(b"File 2 content").unwrap();
        let path2 = temp_file2.path().to_path_buf();

        let input = EncryptionCliArgs {
            input_files: vec![
                path1.to_str().unwrap().to_string(),
                path2.to_str().unwrap().to_string(),
            ],
            ..Default::default()
        };
        let result = validate_input(input);
        assert!(result.is_ok());
        let valid_args = result.unwrap();
        assert_eq!(valid_args.files.len(), 2);
        assert_eq!(valid_args.security_profile, SecurityProfile::Standard);

        // Check first file
        let file1 = &valid_args.files[0];
        assert_eq!(file1.path, path1);
        assert_eq!(file1.filename, path1.file_name().unwrap().to_str().unwrap());
        assert_eq!(file1.size, 6); // "File 1".len()

        // Check second file
        let file2 = &valid_args.files[1];
        assert_eq!(file2.path, path2);
        assert_eq!(file2.filename, path2.file_name().unwrap().to_str().unwrap());
        assert_eq!(file2.size, 14); // "File 2 content".len()
    }
}
