// ES: Evita una consola adicional en modo release de Windows. No eliminar.
// EN: Prevents an extra console window in Windows release mode. Do not remove.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    netscope_lib::run()
}
