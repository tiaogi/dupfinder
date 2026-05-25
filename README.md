# dedupf

A high-performance, multi-threaded duplicate file finder written in C with an interactive ncurses TUI.

## 🚀 Features

- ⚡ **Multi-threaded scanning & hashing**
- 🧠 **Smart detection pipeline**:
  - File size pre-filter
  - Quick hash (first + last bytes)
  - Full MD5 hash
  - Byte-by-byte verification (collision-safe)
- 📁 Recursive directory scanning (`-r`)
- 🕶️ Hidden files support (`-H`)
- 🖥️ Interactive terminal UI (ncurses)
- 🗑️ Selective deletion of duplicates
- 🤖 Auto-delete mode (`-d`)
- 🔍 Dry-run mode (`-n`)
- ⚙️ Configurable thread count (`-t`)

---

## 🧠 How it works

 dedupf uses a **4-step detection pipeline** to balance speed and accuracy:

1. File size comparison (instant)
2. Quick hash (first + last 4KB)
3. Full MD5 hash
4. Byte-by-byte comparison (final guarantee)

➡️ This avoids unnecessary disk reads while remaining **100% safe against hash collisions**.

---

## 📦 Usage

```bash
dedupf <folder> [-r] [-d] [-n] [-H] [-t <threads>]
```

### Options

| Option | Description |
| ------ | ----------- |
| `-r` | Scan subdirectories recursively |
| `-d` | Auto-delete duplicates (keeps first file) |
| `-n` | Dry-run (no deletion) |
| `-H` | Include hidden files |
| `-t <n>` | Number of threads (default: CPU count) |
| `-h` | Show help |

---

## 💡 Examples

```bash
# Interactive mode
dedupf ~/Downloads -r

# Preview what would be deleted
dedupf ~/Pictures -r -n

# Fully automatic cleanup
dedupf ~/Music -r -d

# Limit CPU usage
dedupf ~/Videos -r -t 4
```

---

## 🖥️ Interactive UI

- Navigate with `↑ ↓` or `j k`
- `SPACE` to select files
- `ENTER` to delete selected
- `O` to open a file
- `Ctrl+O` to open all
- `Q` to skip group

---

## 🛠️ Build

### Dependencies

- gcc
- OpenSSL (`libssl-dev`)
- ncurses (`libncursesw5-dev`)
- pthreads

### Compile

```bash
gcc dedupf.c -o dedupf -lcrypto -lncursesw -lpthread
```

---

## ⚙️ Performance

- Parallel directory scanning
- Parallel hash computation
- Lazy + precomputed hashing
- Minimal disk I/O thanks to quick-hash filtering

---

## ⚠️ Notes

- MD5 is used for speed, but **never trusted alone**
- Final byte comparison guarantees correctness
- Designed for large datasets and SSD-friendly access patterns

---

## 📄 License

MIT
