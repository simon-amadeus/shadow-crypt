use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "crypto")]
#[command(about = "A high-security file encryption program")]
#[command(version = "1.0")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Encrypt a single file
    EncryptFile {
        /// Input file to encrypt
        #[arg(short, long)]
        input: PathBuf,
        
        /// Output path for encrypted file
        #[arg(short, long)]
        output: PathBuf,
        
        /// Password for encryption
        #[arg(short, long)]
        password: Option<String>,
    },
    
    /// Decrypt a single file
    DecryptFile {
        /// Encrypted file to decrypt
        #[arg(short, long)]
        input: PathBuf,
        
        /// Output path for decrypted file
        #[arg(short, long)]
        output: PathBuf,
        
        /// Password for decryption
        #[arg(short, long)]
        password: Option<String>,
    },
    
    /// Encrypt a directory
    EncryptDir {
        /// Input directory to encrypt
        #[arg(short, long)]
        input: PathBuf,
        
        /// Output directory for encrypted files
        #[arg(short, long)]
        output: PathBuf,
        
        /// Password for encryption
        #[arg(short, long)]
        password: Option<String>,
        
        /// Encrypt recursively
        #[arg(short, long, default_value_t = true)]
        recursive: bool,
        
        /// Use obfuscated filenames
        #[arg(long, default_value_t = true)]
        obfuscate_names: bool,
    },
    
    /// Decrypt a directory
    DecryptDir {
        /// Directory containing encrypted files
        #[arg(short, long)]
        input: PathBuf,
        
        /// Output directory for decrypted files
        #[arg(short, long)]
        output: PathBuf,
        
        /// Password for decryption
        #[arg(short, long)]
        password: Option<String>,
        
        /// Restore original directory structure
        #[arg(long, default_value_t = false)]
        restore_structure: bool,
    },
    
    /// List encrypted files without decrypting
    List {
        /// Directory containing encrypted files
        #[arg(short, long)]
        directory: PathBuf,
        
        /// Password for listing (needed to deobfuscate names)
        #[arg(short, long)]
        password: Option<String>,
        
        /// Show detailed information
        #[arg(long, default_value_t = false)]
        detailed: bool,
    },
    
    /// Edit an encrypted text file
    Edit {
        /// Encrypted file to edit
        #[arg(short, long)]
        file: PathBuf,
        
        /// Password for decryption
        #[arg(short, long)]
        password: Option<String>,
        
        /// Editor command to use
        #[arg(short, long, default_value = "nano")]
        editor: String,
    },
    
    /// View an encrypted file
    View {
        /// Encrypted file to view
        #[arg(short, long)]
        file: PathBuf,
        
        /// Password for decryption
        #[arg(short, long)]
        password: Option<String>,
        
        /// Viewer command to use
        #[arg(long, default_value = "less")]
        viewer: String,
        
        /// Show only preview (first N bytes)
        #[arg(long)]
        preview: Option<usize>,
    },
}

impl Commands {
    pub fn requires_password(&self) -> bool {
        match self {
            Commands::EncryptFile { .. }
            | Commands::DecryptFile { .. }
            | Commands::EncryptDir { .. }
            | Commands::DecryptDir { .. }
            | Commands::List { .. }
            | Commands::Edit { .. }
            | Commands::View { .. } => true,
        }
    }
    
    pub fn get_password(&self) -> Option<&String> {
        match self {
            Commands::EncryptFile { password, .. }
            | Commands::DecryptFile { password, .. }
            | Commands::EncryptDir { password, .. }
            | Commands::DecryptDir { password, .. }
            | Commands::List { password, .. }
            | Commands::Edit { password, .. }
            | Commands::View { password, .. } => password.as_ref(),
        }
    }
}
