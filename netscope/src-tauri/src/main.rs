// Prevents an extra console window from opening in release mode on Windows.
// DO NOT REMOVE.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    netscope_lib::run()
}
