/*
 * dupfinder.c — Interactive duplicate file finder
 *
 * Usage:
 *   dupfinder <folder> [-r] [-d] [--dry-run]
 *
 *   -r           Scan subdirectories recursively
 *   -d           Auto-delete duplicates (keep first, delete rest)
 *   --dry-run    Simulate deletions without touching any file
 *
 * Dependencies: openssl, ncursesw
 * Compile:
 *   gcc dupfinder.c -o dupfinder -lssl -lcrypto -lncursesw
 */

#include <dirent.h>
#include <locale.h>
#include <ncursesw/ncurses.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* ─── Constants ──────────────────────────────────────────────────── */

#define MAX_FILES 1000
#define PATH_BUF 1024
#define IO_BUF 4096
#define MB (1024.0 * 1024.0)

/* ─── Data types ─────────────────────────────────────────────────── */

typedef struct
{
    char *path;
    size_t size;
    unsigned char hash[MD5_DIGEST_LENGTH];
    int hash_computed;
} FileEntry;

/* ─── Globals ────────────────────────────────────────────────────── */

static FileEntry files[MAX_FILES];
static int file_count = 0;
static int visited[MAX_FILES];
static long long freed_bytes = 0;

/* ─── File utilities ─────────────────────────────────────────────── */

/* Returns 1 if two files have identical byte content, 0 otherwise. */
static int files_are_identical(const char *a, const char *b)
{
    FILE *fa = fopen(a, "rb");
    FILE *fb = fopen(b, "rb");

    if (!fa || !fb)
    {
        if (fa)
            fclose(fa);
        if (fb)
            fclose(fb);
        return 0;
    }

    char ba[IO_BUF], bb[IO_BUF];
    size_t ra, rb;
    int equal = 1;

    do
    {
        ra = fread(ba, 1, sizeof(ba), fa);
        rb = fread(bb, 1, sizeof(bb), fb);
        if (ra != rb || memcmp(ba, bb, ra) != 0)
        {
            equal = 0;
            break;
        }
    } while (ra > 0);

    fclose(fa);
    fclose(fb);
    return equal;
}

/* Computes the MD5 hash of a file into `out`. Returns 1 on success. */
static int compute_md5(const char *path, unsigned char *out)
{
    FILE *file = fopen(path, "rb");
    if (!file)
        return 0;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        fclose(file);
        return 0;
    }

    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);

    unsigned char buf[IO_BUF];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), file)) > 0)
        EVP_DigestUpdate(ctx, buf, n);

    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, out, &len);

    EVP_MD_CTX_free(ctx);
    fclose(file);
    return 1;
}

static int hashes_equal(const unsigned char *h1, const unsigned char *h2)
{
    return memcmp(h1, h2, MD5_DIGEST_LENGTH) == 0;
}

/* ─── Directory scan ─────────────────────────────────────────────── */

static void scan_directory(const char *base, int recursive)
{
    DIR *dir = opendir(base);
    if (!dir)
    {
        perror("opendir");
        return;
    }

    struct dirent *entry;
    char path[PATH_BUF];

    while ((entry = readdir(dir)) != NULL)
    {
        if (file_count >= MAX_FILES)
        {
            fprintf(stderr, "Warning: file limit (%d) reached.\n", MAX_FILES);
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        int needs_sep = base[strlen(base) - 1] != '/';
        snprintf(path, sizeof(path), "%s%s%s", base, needs_sep ? "/" : "", entry->d_name);

        struct stat st;
        if (stat(path, &st) == -1)
            continue;

        if (S_ISDIR(st.st_mode))
        {
            if (recursive)
                scan_directory(path, recursive);
        }
        else if (S_ISREG(st.st_mode))
        {
            /* Pass NULL so realpath() allocates a PATH_MAX-sized buffer
             * internally — avoids the -Wattribute-warning about undersized
             * second-argument buffers.  The returned pointer is already
             * heap-allocated, so we own it directly (no strdup needed). */
            char *resolved = realpath(path, NULL);
            if (resolved)
            {
                files[file_count].path = resolved;
                files[file_count].size = (size_t)st.st_size;
                files[file_count].hash_computed = 0;
                file_count++;
            }
        }
    }

    closedir(dir);
}

/* ─── Deletion ───────────────────────────────────────────────────── */

static void delete_file(const char *path, size_t size, int dry_run)
{
    if (dry_run)
    {
        printf("  [dry-run] would delete: %s\n", path);
        return;
    }
    if (remove(path) == 0)
    {
        printf("  deleted: %s\n", path);
        freed_bytes += (long long)size;
    }
    else
    {
        perror("  remove");
    }
}

/* ─── Sorting ────────────────────────────────────────────────────── */

static int compare_size(const void *a, const void *b)
{
    const FileEntry *fa = (const FileEntry *)a;
    const FileEntry *fb = (const FileEntry *)b;
    return (fa->size > fb->size) - (fa->size < fb->size);
}

/* ─── TUI helpers ────────────────────────────────────────────────── */

/* Truncates a path string to fit within `max_cols`, adding "…" if needed. */
static void print_truncated(int row, int col, const char *path, int max_cols)
{
    int len = (int)strlen(path);
    if (len <= max_cols)
    {
        mvprintw(row, col, "%s", path);
    }
    else
    {
        /* Show the tail of the path so the filename is always visible */
        mvprintw(row, col, "…%s", path + (len - max_cols + 1));
    }
}

static void format_size(char *buf, size_t sz)
{
    if (sz >= (size_t)(1024 * 1024))
        snprintf(buf, 16, "%.1f MB", sz / MB);
    else if (sz >= 1024)
        snprintf(buf, 16, "%.1f KB", sz / 1024.0);
    else
        snprintf(buf, 16, "%zu B", sz);
}

/* ─── Interactive ncurses prompt ─────────────────────────────────── */

/*
 * Presents a group of duplicate files in a full-screen ncurses UI.
 * The user can navigate with ↑/↓, toggle selections with SPACE,
 * confirm deletions with ENTER, or skip the group with Q.
 *
 * Returns 1 if the group was processed, 0 if skipped.
 */
static int prompt_group(char **group, size_t *sizes, int count,
                        int group_index, int total_groups,
                        int auto_delete, int dry_run)
{
    if (auto_delete)
    {
        for (int i = 1; i < count; i++)
            delete_file(group[i], sizes[i], dry_run);
        return 1;
    }

    /* ── ncurses init ── */
    setlocale(LC_ALL, "");
    if (!initscr())
    {
        fprintf(stderr, "ncurses init failed\n");
        return 0;
    }
    noecho();
    cbreak();
    keypad(stdscr, TRUE);
    curs_set(0);

    /* Colours */
    int has_color = has_colors();
    if (has_color)
    {
        start_color();
        use_default_colors();
        init_pair(1, COLOR_CYAN, -1);          /* header */
        init_pair(2, COLOR_GREEN, -1);         /* selected */
        init_pair(3, COLOR_YELLOW, -1);        /* cursor bar */
        init_pair(4, COLOR_RED, -1);           /* danger / size */
        init_pair(5, COLOR_WHITE, -1);         /* normal text */
        init_pair(6, COLOR_BLACK, COLOR_CYAN); /* status bar */
    }

    int selected[MAX_FILES] = {0};
    /* FIFO queue tracking the order in which files were selected.
     * sel_queue[0] is the oldest selection.  sel_head is the count. */
    int sel_queue[MAX_FILES];
    int sel_head = 0;
    int cursor = 0;

    while (1)
    {
        clear();
        int rows, cols;
        getmaxyx(stdscr, rows, cols);

        /* ── Top bar ── */
        if (has_color)
            attron(COLOR_PAIR(6) | A_BOLD);
        for (int c = 0; c < cols; c++)
            mvaddch(0, c, ' ');
        char header[128];
        snprintf(header, sizeof(header),
                 " dupfinder  │  Group %d / %d  │  %d duplicate(s)",
                 group_index, total_groups, count - 1);
        mvprintw(0, 0, "%s", header);
        if (has_color)
            attroff(COLOR_PAIR(6) | A_BOLD);

        /* ── Section label ── */
        if (has_color)
            attron(COLOR_PAIR(1) | A_BOLD);
        mvprintw(2, 2, "DUPLICATE FILES");
        attroff(A_BOLD);
        if (has_color)
            attroff(COLOR_PAIR(1));

        /* ── File list ── */
        for (int i = 0; i < count; i++)
        {
            int row = 4 + i;
            if (row >= rows - 4)
                break; /* guard against tiny terminals */

            int is_cursor = (i == cursor);
            int is_selected = selected[i];

            if (is_cursor)
            {
                if (has_color)
                    attron(COLOR_PAIR(3) | A_REVERSE | A_BOLD);
                else
                    attron(A_REVERSE);
                for (int c = 0; c < cols; c++)
                    mvaddch(row, c, ' ');
            }

            /* Checkbox */
            if (has_color && is_selected)
                attron(COLOR_PAIR(2) | A_BOLD);
            mvprintw(row, 2, "[%c]", is_selected ? 'x' : ' ');
            if (has_color && is_selected)
                attroff(COLOR_PAIR(2) | A_BOLD);

            /* Index */
            mvprintw(row, 6, "%2d.", i + 1);

            /* File size */
            char sz[16];
            format_size(sz, sizes[i]);
            if (has_color)
                attron(COLOR_PAIR(4));
            mvprintw(row, 10, "%-9s", sz);
            if (has_color)
                attroff(COLOR_PAIR(4));

            /* Path (truncated) */
            if (has_color && is_selected)
                attron(COLOR_PAIR(2));
            print_truncated(row, 20, group[i], cols - 22);
            if (has_color && is_selected)
                attroff(COLOR_PAIR(2));

            if (is_cursor)
            {
                if (has_color)
                    attroff(COLOR_PAIR(3) | A_REVERSE | A_BOLD);
                else
                    attroff(A_REVERSE);
            }
        }

        /* ── Hint line ── */
        if (has_color)
            attron(COLOR_PAIR(1));
        mvprintw(rows - 3, 2, "↑ ↓  navigate    SPACE  select    ENTER  delete selected    Q  skip group");
        if (has_color)
            attroff(COLOR_PAIR(1));

        /* ── Bottom status bar ── */
        int n_selected = 0;
        size_t bytes_to_free = 0;
        for (int i = 0; i < count; i++)
        {
            if (selected[i])
            {
                n_selected++;
                bytes_to_free += sizes[i];
            }
        }
        char free_sz[16];
        format_size(free_sz, bytes_to_free);

        if (has_color)
            attron(COLOR_PAIR(6));
        for (int c = 0; c < cols; c++)
            mvaddch(rows - 1, c, ' ');
        char status[128];
        snprintf(status, sizeof(status),
                 "  %d file(s) selected  │  %s will be freed%s",
                 n_selected, free_sz,
                 dry_run ? "  [DRY-RUN MODE]" : "");
        mvprintw(rows - 1, 0, "%s", status);
        if (has_color)
            attroff(COLOR_PAIR(6));

        refresh();

        /* ── Input ── */
        int ch = getch();

        if (ch == 'q' || ch == 'Q')
        {
            endwin();
            return 0;
        }
        else if (ch == KEY_UP || ch == 'k')
        {
            if (cursor > 0)
                cursor--;
        }
        else if (ch == KEY_DOWN || ch == 'j')
        {
            if (cursor < count - 1)
                cursor++;
        }
        else if (ch == ' ')
        {
            if (selected[cursor])
            {
                /* Already selected → deselect and remove from queue */
                selected[cursor] = 0;
                int w = 0;
                for (int i = 0; i < sel_head; i++)
                    if (sel_queue[i] != cursor)
                        sel_queue[w++] = sel_queue[i];
                sel_head = w;
            }
            else
            {
                /* Never allow all files to be selected (must keep at least
                 * one): if adding this one would reach count, evict the
                 * oldest selection first. */
                if (sel_head >= count - 1)
                {
                    selected[sel_queue[0]] = 0;
                    for (int i = 0; i < sel_head - 1; i++)
                        sel_queue[i] = sel_queue[i + 1];
                    sel_head--;
                }
                selected[cursor] = 1;
                sel_queue[sel_head++] = cursor;
            }
        }
        else if (ch == 'n' || ch == 'N')
        {
            /* Deselect all */
            for (int i = 0; i < count; i++)
                selected[i] = 0;
            sel_head = 0;
        }
        else if (ch == '\n' || ch == KEY_ENTER)
        {
            break;
        }
    }

    endwin();

    for (int i = 0; i < count; i++)
        if (selected[i])
            delete_file(group[i], sizes[i], dry_run);

    return 1;
}

/* ─── Entry point ────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Usage: %s <folder> [-r] [-d] [--dry-run]\n\n", argv[0]);
        printf("  -r           Recursive scan\n");
        printf("  -d           Auto-delete duplicates (keep first)\n");
        printf("  --dry-run    Simulate without deleting\n");
        return 1;
    }

    int recursive = 0;
    int auto_delete = 0;
    int dry_run = 0;

    for (int i = 2; i < argc; i++)
    {
        if (strcmp(argv[i], "-r") == 0)
            recursive = 1;
        else if (strcmp(argv[i], "-d") == 0)
            auto_delete = 1;
        else if (strcmp(argv[i], "--dry-run") == 0)
            dry_run = 1;
    }

    setlocale(LC_ALL, "");
    memset(visited, 0, sizeof(visited));

    /* ── Scan & sort ── */
    printf("Scanning %s%s…\n", argv[1], recursive ? " (recursive)" : "");
    scan_directory(argv[1], recursive);
    qsort(files, (size_t)file_count, sizeof(FileEntry), compare_size);
    printf("Found %d file(s). Looking for duplicates…\n\n", file_count);

    /* ── Find & process groups ── */

    /* First pass: count groups so we can show "Group N / total" */
    int total_groups = 0;
    for (int i = 0; i < file_count; i++)
    {
        if (visited[i])
            continue;
        for (int j = i + 1; j < file_count; j++)
        {
            if (files[i].size != files[j].size)
                break;
            if (visited[j])
                continue;

            if (!files[i].hash_computed)
            {
                compute_md5(files[i].path, files[i].hash);
                files[i].hash_computed = 1;
            }
            if (!files[j].hash_computed)
            {
                compute_md5(files[j].path, files[j].hash);
                files[j].hash_computed = 1;
            }

            if (hashes_equal(files[i].hash, files[j].hash) &&
                files_are_identical(files[i].path, files[j].path))
            {
                total_groups++;
                break;
            }
        }
    }

    if (total_groups == 0)
    {
        printf("No duplicates found. You're all clean!\n");
        return 0;
    }

    /* Reset visited for second pass */
    memset(visited, 0, sizeof(visited));

    int group_index = 0;

    for (int i = 0; i < file_count; i++)
    {
        if (visited[i])
            continue;

        char *group[MAX_FILES];
        size_t group_sizes[MAX_FILES];
        int group_count = 0;

        group[group_count] = files[i].path;
        group_sizes[group_count] = files[i].size;
        group_count++;

        for (int j = i + 1; j < file_count; j++)
        {
            if (files[i].size != files[j].size)
                break;
            if (visited[j])
                continue;

            if (!files[i].hash_computed)
            {
                compute_md5(files[i].path, files[i].hash);
                files[i].hash_computed = 1;
            }
            if (!files[j].hash_computed)
            {
                compute_md5(files[j].path, files[j].hash);
                files[j].hash_computed = 1;
            }

            if (!hashes_equal(files[i].hash, files[j].hash))
                continue;

            if (files_are_identical(files[i].path, files[j].path))
            {
                group[group_count] = files[j].path;
                group_sizes[group_count] = files[j].size;
                group_count++;
                visited[j] = 1;
            }
        }

        if (group_count > 1)
        {
            group_index++;
            prompt_group(group, group_sizes, group_count,
                         group_index, total_groups,
                         auto_delete, dry_run);
            visited[i] = 1;
        }
    }

    /* ── Summary ── */
    printf("\n┌─────────────────────────────────┐\n");
    printf("│           Summary               │\n");
    printf("├─────────────────────────────────┤\n");
    printf("│  Groups found   : %-13d │\n", total_groups);
    if (dry_run)
    {
        printf("│  Mode           : DRY-RUN       │\n");
    }
    /* Format size into a string first so the locale decimal separator
     * (e.g. ',' on French systems) doesn't break column alignment. */
    char freed_str[16];
    snprintf(freed_str, sizeof(freed_str), "%.2f MB", freed_bytes / MB);
    for (char *p = freed_str; *p; p++)
        if (*p == ',')
            *p = '.';
    printf("│  Space freed    : %-13s │\n", freed_str);
    printf("└─────────────────────────────────┘\n");

    /* Cleanup file paths */
    for (int i = 0; i < file_count; i++)
        free(files[i].path);

    return 0;
}