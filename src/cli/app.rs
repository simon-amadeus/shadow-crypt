use crate::cli::commands::{Cli, Commands};
use crate::crypto::{AesHmacEncryptor, Argon2KeyDeriver};
use crate::error::EncryptionError;
use crate::filesystem::StdFileSystem;
use crate::service::{AdvancedFeatures, EncryptionService};
use crate::traits::*;
use clap::Parser;
use std::io::{self, Write};
use std::sync::Arc;

pub struct App {
    service: EncryptionService<Argon2KeyDeriver, AesHmacEncryptor, StdFileSystem>,
    advanced_features: AdvancedFeatures<AesHmacEncryptor, StdFileSystem>,
}

impl App {
    pub fn new() -> Self {
        let key_deriver = Argon2KeyDeriver::new();
        let encryptor = AesHmacEncryptor::new();
        let file_system = StdFileSystem::new();

        let service = EncryptionService::new(key_deriver, encryptor.clone(), file_system.clone());
        let advanced_features = AdvancedFeatures::new(Arc::new(encryptor), Arc::new(file_system));

        Self {
            service,
            advanced_features,
        }
    }

    pub fn run() -> Result<(), EncryptionError> {
        let cli = Cli::parse();
        let app = App::new();
        app.execute_command(cli.command)
    }

    fn execute_command(&self, command: Commands) -> Result<(), EncryptionError> {
        let password = if command.requires_password() {
            if let Some(pwd) = command.get_password() {
                pwd.clone()
            } else {
                self.prompt_password()?
            }
        } else {
            String::new()
        };

        match command {
            Commands::EncryptFile { input, output, .. } => {
                println!("Encrypting file: {} -> {}", input.display(), output.display());
                self.service.encrypt_file(&input, &output, &password)?;
                println!("✅ File encrypted successfully!");
            }

            Commands::DecryptFile { input, output, .. } => {
                println!("Decrypting file: {} -> {}", input.display(), output.display());
                self.service.decrypt_file(&input, &output, &password)?;
                println!("✅ File decrypted successfully!");
            }

            Commands::EncryptDir {
                input,
                output,
                recursive,
                obfuscate_names: _,
                ..
            } => {
                println!("Encrypting directory: {} -> {}", input.display(), output.display());
                self.service.encrypt_directory(&input, &output, &password, recursive)?;
                println!("✅ Directory encrypted successfully!");
            }

            Commands::DecryptDir {
                input,
                output,
                restore_structure,
                ..
            } => {
                println!("Decrypting directory: {} -> {}", input.display(), output.display());
                self.service.decrypt_directory(&input, &output, &password, restore_structure)?;
                println!("✅ Directory decrypted successfully!");
            }

            Commands::List {
                directory,
                detailed,
                ..
            } => {
                println!("Listing encrypted files in: {}", directory.display());
                self.list_files(&directory, &password, detailed)?;
            }

            Commands::Edit { file, editor, .. } => {
                println!("Editing encrypted file: {}", file.display());
                let keys = self.service.key_deriver().derive_session_key(&password)?;
                self.advanced_features.edit_text_file(&file, &keys.key_material, &editor)?;
                println!("✅ File edited successfully!");
            }

            Commands::View {
                file,
                viewer,
                preview,
                ..
            } => {
                println!("Viewing encrypted file: {}", file.display());
                let keys = self.service.key_deriver().derive_session_key(&password)?;

                if let Some(preview_size) = preview {
                    let preview_data = self.advanced_features.get_file_preview(&file, &keys.key_material, preview_size)?;
                    println!("Preview ({} bytes):", preview_data.len());
                    println!("{}", String::from_utf8_lossy(&preview_data));
                } else {
                    self.advanced_features.view_file(&file, &keys.key_material, &viewer)?;
                }
            }
        }

        Ok(())
    }

    fn list_files(&self, directory: &std::path::Path, password: &str, detailed: bool) -> Result<(), EncryptionError> {
        let keys = self.service.key_deriver().derive_session_key(password)?;
        let file_infos = self.advanced_features.list_encrypted_names(directory, &keys.key_material)?;

        if file_infos.is_empty() {
            println!("No encrypted files found in directory.");
            return Ok(());
        }

        println!("Found {} encrypted file(s):", file_infos.len());
        println!();

        for file_info in file_infos {
            if detailed {
                println!("📄 {}", file_info.original_name);
                println!("   Obfuscated: {}", file_info.obfuscated_name);
                println!("   Original path: {}", file_info.original_path.display());
                println!("   Size: {} bytes (encrypted: {} bytes)", file_info.size, file_info.encrypted_size);
                println!("   Modified: {:?}", file_info.modified);
                println!();
            } else {
                println!("📄 {} ({})", file_info.original_name, file_info.obfuscated_name);
            }
        }

        Ok(())
    }

    fn prompt_password(&self) -> Result<String, EncryptionError> {
        print!("Enter password: ");
        io::stdout().flush().map_err(EncryptionError::FileSystemError)?;

        let password = rpassword::read_password()
            .map_err(|e| EncryptionError::FileSystemError(
                std::io::Error::new(std::io::ErrorKind::Other, e)
            ))?;

        if password.is_empty() {
            return Err(EncryptionError::KeyDerivationError(
                "Password cannot be empty".to_string()
            ));
        }

        Ok(password)
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

pub fn print_banner() {
    println!(r#"
╔═══════════════════════════════════════════════════════════════╗
║                     🔐 CRYPTO FILE ENCRYPTOR 🔐               ║
║                                                               ║
║  High-security file encryption with AES-256-CBC + HMAC-SHA256 ║
║  Features: Directory encryption, filename obfuscation,        ║
║           partial decryption, in-place editing                ║
╚═══════════════════════════════════════════════════════════════╝
"#);
}

pub fn print_help() {
    println!("
Basic Usage Examples:

🔐 Encrypt a single file:
   crypto encrypt-file -i document.pdf -o document.pdf.enc

🔓 Decrypt a single file:
   crypto decrypt-file -i document.pdf.enc -o document.pdf

📁 Encrypt a directory:
   crypto encrypt-dir -i /path/to/folder -o /path/to/encrypted

📂 Decrypt a directory:
   crypto decrypt-dir -i /path/to/encrypted -o /path/to/decrypted

📋 List encrypted files:
   crypto list -d /path/to/encrypted --detailed

✏️  Edit encrypted text file:
   crypto edit -f secret.txt.enc -e vim

👀 View encrypted file:
   crypto view -f document.txt.enc --preview 1024

For more help, use: crypto --help
");
}
