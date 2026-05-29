# Netscope

Network monitoring desktop application built with **Tauri v2** + **React** + **TypeScript**.

## Stack

| Layer | Technology |
|-------|-----------|
| Desktop shell | Tauri 2 (Rust) |
| Frontend | React 18 + TypeScript |
| Bundler | Vite 6 |
| Styling | Tailwind CSS v3 + shadcn/ui (new-york / zinc) |
| UI primitives | Radix UI |
| Tables | TanStack Table v8 |
| Charts | Recharts |
| Icons | Lucide React |
| Database | SQLite via rusqlite (bundled) |
| Async runtime | Tokio |

## Getting Started

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (stable)
- [Node.js](https://nodejs.org/) ≥ 20
- Platform build dependencies → https://tauri.app/start/prerequisites/

### Install & run

```bash
npm install
npm run tauri dev
```

### Build

```bash
npm run tauri build
```

## Project Structure

```
netscope/
├── src/                  # React frontend
│   ├── components/
│   │   └── ui/           # shadcn/ui components (add via: npx shadcn add <component>)
│   ├── hooks/
│   ├── lib/
│   │   └── utils.ts      # cn() helper
│   ├── App.tsx
│   ├── main.tsx
│   └── index.css         # Tailwind + CSS variables
├── src-tauri/            # Rust backend
│   ├── src/
│   │   ├── main.rs
│   │   └── lib.rs
│   ├── capabilities/
│   ├── icons/
│   ├── Cargo.toml
│   └── tauri.conf.json
├── components.json        # shadcn/ui config
├── tailwind.config.js
├── postcss.config.js
├── vite.config.ts
└── package.json
```

## Adding shadcn/ui components

```bash
npx shadcn add button
npx shadcn add card
npx shadcn add dialog
# etc.
```
