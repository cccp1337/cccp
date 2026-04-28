use std::fs;

fn main() {
    // Create a file named "rust" with the content "i am rust"
    fs::write("rust.txt", "i am rust").expect("Failed to create file");
    println!("File 'rust.txt' created successfully!");

    // Show a popup saying "hello i am rust"
    show_popup("hello i am rust");
}

#[cfg(target_os = "windows")]
fn show_popup(message: &str) {
    use std::process::Command;
    Command::new("powershell")
        .args([
            "-Command",
            &format!(
                "Add-Type -AssemblyName PresentationFramework; \
                 [System.Windows.MessageBox]::Show('{message}')"
            ),
        ])
        .spawn()
        .expect("Failed to open popup")
        .wait()
        .unwrap();
}

#[cfg(target_os = "macos")]
fn show_popup(message: &str) {
    use std::process::Command;
    Command::new("osascript")
        .args(["-e", &format!("display dialog \"{message}\"")])
        .spawn()
        .expect("Failed to open popup")
        .wait()
        .unwrap();
}

#[cfg(target_os = "linux")]
fn show_popup(message: &str) {
    use std::process::Command;

    // Try zenity first, fall back to xmessage
    let result = Command::new("zenity")
        .args(["--info", "--text", message, "--title", "Rust Says Hi"])
        .spawn();

    match result {
        Ok(mut child) => { child.wait().unwrap(); }
        Err(_) => {
            Command::new("xmessage")
                .arg(message)
                .spawn()
                .expect("Neither zenity nor xmessage found. Install one of them.")
                .wait()
                .unwrap();
        }
    }
}
