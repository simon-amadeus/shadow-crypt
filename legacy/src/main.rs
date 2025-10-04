
fn main() {
    println!("This is a library crate - use the binary tools:");
    println!("  cargo run --bin lock     # File encryption");
    println!("  cargo run --bin unlock   # File decryption");
    println!("  cargo run --bin cryptls  # File listing");
    println!("  cargo run --bin cryptview # File viewing");
    println!("  cargo run --bin cryptedit # File editing");
}
