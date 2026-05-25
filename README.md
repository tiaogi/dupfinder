# dedupf

A fast interactive duplicate file finder written in C with a ncurses-based TUI.

## Features

- Recursive directory scanning (-r)
- Duplicate detection using file size + MD5 hashing
- Byte-by-byte verification for safety
- Interactive terminal UI (ncurses)
- Selectively delete duplicates
- Dry-run mode (--dry-run)
- Auto-delete mode (-d)

## Usage

```bash
dedupf <folder> [-r] [-d] [--dry-run]
```

### Options

- `-r` : Scan directories recursively
- `-d` : Automatically delete duplicates (keeps first file)
- `--dry-run` : Simulate deletions without modifying files

## Example

```bash
./dedupf ~/Downloads -r
./dedupf ~/Pictures -r --dry-run
./dedupf ~/Music -r -d
```

## Build

### Dependencies

- gcc
- libssl-dev (OpenSSL)
- libncursesw5-dev

### Compile

```bash
gcc dedupf.c -o dedupf -lssl -lcrypto -lncursesw
```

Or use the Makefile:

```bash
make
```

## Makefile

```makefile
CC=gcc
CFLAGS=-Wall -Wextra -O2
LIBS=-lssl -lcrypto -lncursesw

TARGET=dedupf
SRC=dedupf.c

all:
    $(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LIBS)

clean:
    rm -f $(TARGET)
```

## Notes

- Uses MD5 for fast pre-filtering + full byte comparison for safety
- Limits file scan to 1000 files by default (can be increased in source)
- Requires a terminal compatible with ncurses

## License

MIT (or choose your own)
