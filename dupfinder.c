/*
 * dupfinder.c — Interactive duplicate file finder
 *
 * Usage:
 *   dupfinder <folder> [-r] [-d] [-n] [-h]
 *
 *   -r           Scan subdirectories recursively
 *   -d           Auto-delete duplicates (keep first)
 *   -n           Dry-run (no deletion)
 *   -h           Show help
 *
 * Dependencies: openssl, ncursesw
 * Compile:
 *   gcc dupfinder.c -o dupfinder -lcrypto -lncursesw
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
#include <unistd.h>

/* ─── Data types ─────────────────────────────────────────────────── */

typedef struct
{
    char *path;
    size_t size;
    unsigned char hash[MD5_DIGEST_LENGTH];
    int hash_computed;
} FileEntry;

typedef struct
{
    FileEntry *data;
    size_t size;
    size_t cap;
} FileVec;

/* ─── Function prototypes ───────────────────────────────────────── */

static void vec_init(FileVec *v);
static void vec_free(FileVec *v);
static void vec_push(FileVec *v, FileEntry e);

static void scan_directory(const char *base, int recursive);
static int compare_size(const void *a, const void *b);

static int compute_md5(const char *path, unsigned char *out);
static int hashes_equal(const unsigned char *h1, const unsigned char *h2);
static int files_are_identical(const char *a, const char *b);

static int prompt_group(char **group, size_t *sizes, int count,
                        int group_index, int total_groups,
                        int auto_delete, int dry_run);

static void delete_file(const char *path, size_t size, int dry_run);

static int count_duplicate_groups(void);
static void process_groups(int total_groups, int auto_delete, int dry_run);

static void scan_and_sort(const char *path, int recursive);
static void cleanup(void);
static void print_summary(int total_groups, int dry_run);

static void usage(const char *prog);
static void usage_exit(const char *prog, int code);
static void parse_args(int argc, char *argv[],
                       int *recursive, int *auto_delete, int *dry_run);

/* ─── Constants ──────────────────────────────────────────────────── */

#define PATH_BUF 1024
#define IO_BUF 4096
#define MB (1024.0 * 1024.0)

/* ─── Globals ────────────────────────────────────────────────────── */

static FileVec files = {0};
static int *visited = NULL;
static long long freed_bytes = 0;
extern int optind;

static void vec_init(FileVec *v)
{
    v->cap = 128;
    v->size = 0;
    v->data = malloc(v->cap * sizeof(FileEntry));
    if (!v->data)
    {
        perror("malloc");
        exit(1);
    }
}

/* ─── Dynamic allocation ─────────────────────────────────────────────── */

static void vec_free(FileVec *v)
{
    for (size_t i = 0; i < v->size; i++)
        free(v->data[i].path);
    free(v->data);
}

static void vec_push(FileVec *v, FileEntry e)
{
    if (v->size >= v->cap)
    {
        size_t new_cap = v->cap * 2;

        FileEntry *new_data = realloc(v->data, new_cap * sizeof(FileEntry));
        if (!new_data)
        {
            perror("realloc");
            exit(1);
        }

        v->data = new_data;
        v->cap = new_cap;
    }

    v->data[v->size++] = e;
}

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

static void scan_and_sort(const char *path, int recursive)
{
    printf("Scanning %s%s…\n", path, recursive ? " (recursive)" : "");
    scan_directory(path, recursive);
    qsort(files.data, files.size, sizeof(FileEntry), compare_size);
    printf("Found %zu file(s). Looking for duplicates…\n\n", files.size);
}

static void cleanup(void)
{
    vec_free(&files);
    if (visited)
        free(visited);
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
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        int needs_sep = base[strlen(base) - 1] != '/';
        snprintf(path, sizeof(path), "%s%s%s", base, needs_sep ? "/" : "", entry->d_name);

        struct stat st;
        if (stat(path, &st) == -1)
            continue;

        if (S_ISDIR(st.st_mode) && recursive)
        {
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
                FileEntry e = {0};

                e.path = resolved;
                e.size = (size_t)st.st_size;
                e.hash_computed = 0;

                vec_push(&files, e);
            }
        }
    }

    closedir(dir);
}

/* ─── Groups ───────────────────────────────────────────────────── */

static int count_duplicate_groups(void)
{
    int total = 0;

    for (size_t i = 0; i < files.size; i++)
    {
        if (visited[i])
            continue;

        for (size_t j = i + 1; j < files.size; j++)
        {
            if (files.data[i].size != files.data[j].size)
                break;
            if (visited[j])
                continue;

            if (!files.data[i].hash_computed)
            {
                compute_md5(files.data[i].path, files.data[i].hash);
                files.data[i].hash_computed = 1;
            }
            if (!files.data[j].hash_computed)
            {
                compute_md5(files.data[j].path, files.data[j].hash);
                files.data[j].hash_computed = 1;
            }

            if (hashes_equal(files.data[i].hash, files.data[j].hash) &&
                files_are_identical(files.data[i].path, files.data[j].path))
            {
                total++;
                break;
            }
        }
    }

    return total;
}

static void process_groups(int total_groups, int auto_delete, int dry_run)
{
    memset(visited, 0, files.size * sizeof(int));
    int group_index = 0;

    for (size_t i = 0; i < files.size; i++)
    {
        if (visited[i])
            continue;

        char **group = malloc(files.size * sizeof(*group));
        size_t *group_sizes = malloc(files.size * sizeof(*group_sizes));

        if (!group || !group_sizes)
        {
            perror("malloc");
            free(group);
            free(group_sizes);
            return;
        }

        int count = 0;

        group[count] = files.data[i].path;
        group_sizes[count++] = files.data[i].size;

        for (size_t j = i + 1; j < files.size; j++)
        {
            if (files.data[i].size != files.data[j].size)
                break;
            if (visited[j])
                continue;

            if (!files.data[i].hash_computed)
            {
                compute_md5(files.data[i].path, files.data[i].hash);
                files.data[i].hash_computed = 1;
            }
            if (!files.data[j].hash_computed)
            {
                compute_md5(files.data[j].path, files.data[j].hash);
                files.data[j].hash_computed = 1;
            }

            if (!hashes_equal(files.data[i].hash, files.data[j].hash))
                continue;

            if (files_are_identical(files.data[i].path, files.data[j].path))
            {
                group[count] = files.data[j].path;
                group_sizes[count++] = files.data[j].size;
                visited[j] = 1;
            }
        }

        if (count > 1)
        {
            group_index++;
            prompt_group(group, group_sizes, count,
                         group_index, total_groups,
                         auto_delete, dry_run);
            free(group);
            free(group_sizes);
            visited[i] = 1;
        }
    }
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

static void print_summary(int total_groups, int dry_run)
{
    printf("\n┌─────────────────────────────────┐\n");
    printf("│           Summary               │\n");
    printf("├─────────────────────────────────┤\n");
    printf("│  Groups found   : %-13d │\n", total_groups);

    if (dry_run)
        printf("│  Mode           : DRY-RUN       │\n");

    char freed_str[16];
    snprintf(freed_str, sizeof(freed_str), "%.2f MB", freed_bytes / MB);

    for (char *p = freed_str; *p; p++)
        if (*p == ',')
            *p = '.';

    printf("│  Space freed    : %-13s │\n", freed_str);
    printf("└─────────────────────────────────┘\n");
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

    int *selected = calloc(count, sizeof(int));
    int *sel_queue = malloc(count * sizeof(int));

    if (!selected || !sel_queue)
    {
        perror("malloc");
        return 0;
    }

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
            free(selected);
            free(sel_queue);
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

    free(selected);
    free(sel_queue);

    return 1;
}

/* ─── Argument parsing ───────────────────────────────────────────── */

static const char *prog_name(const char *path)
{
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static void usage(const char *prog)
{
    const char *name = prog_name(prog);

    fprintf(stderr,
            "Usage: %s <folder> [-r] [-d] [-n] [-h]\n\n"
            "Options:\n"
            "  -r    Scan subdirectories recursively\n"
            "  -d    Auto-delete duplicates (keep first)\n"
            "  -n    Dry-run (no deletion)\n"
            "  -h    Show help\n",
            name);
}

static void usage_exit(const char *prog, int code)
{
    usage(prog);
    exit(code);
}

static void parse_args(int argc, char *argv[],
                       int *recursive, int *auto_delete, int *dry_run)
{
    int opt;
    while ((opt = getopt(argc, argv, "rdnh")) != -1)
    {
        switch (opt)
        {
        case 'r':
            *recursive = 1;
            break;
        case 'd':
            *auto_delete = 1;
            break;
        case 'n':
            *dry_run = 1;
            break;
        case 'h':
            usage_exit(argv[0], 0);
            break;
        default:
            usage_exit(argv[0], 1);
        }
    }

    if (optind >= argc)
    {
        usage_exit(argv[0], 1);
    }
}

/* ─── Entry point ────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        usage(argv[0]);
        return 1;
    }

    int recursive = 0;
    int auto_delete = 0;
    int dry_run = 0;

    parse_args(argc, argv, &recursive, &auto_delete, &dry_run);

    setlocale(LC_ALL, "");
    vec_init(&files);

    const char *folder = argv[optind];
    scan_and_sort(folder, recursive);

    visited = calloc(files.size, sizeof(int));
    if (!visited)
    {
        perror("calloc");
        exit(1);
    }

    int total_groups = count_duplicate_groups();

    if (total_groups == 0)
    {
        printf("No duplicates found. You're all clean!\n");
        return 0;
    }

    process_groups(total_groups, auto_delete, dry_run);

    print_summary(total_groups, dry_run);

    cleanup();

    return 0;
}