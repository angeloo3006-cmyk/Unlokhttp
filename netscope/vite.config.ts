import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

// ES: Configuracion de Vite. / EN: Vite configuration.
export default defineConfig(async () => ({
  plugins: [react()],

  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },

  // ES: Ajustes para desarrollo y compilacion con Tauri. / EN: Settings for Tauri development and builds.
  // ES: Evita que Vite oculte errores de Rust. / EN: Prevent Vite from hiding Rust errors.
  clearScreen: false,
  // ES: Tauri necesita un puerto fijo. / EN: Tauri expects a fixed port.
  server: {
    port: 1420,
    strictPort: true,
    watch: {
      // ES: No observa cambios dentro de src-tauri. / EN: Ignore changes inside src-tauri.
      ignored: ["**/src-tauri/**"],
    },
  },
}));
