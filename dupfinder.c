/*
 * dupfinder.c — Interactive duplicate file finder
 *
 * Usage:
 *   dupfinder <folder> [-r] [-d] [-n] [-H] [-h]
 *
 *   -r    Scan subdirectories recursively
 *   -d    Auto-delete duplicates (keep first)
 *   -n    Dry-run (no deletion)
 *   -H    Include hidden files and directories (starting with .)
 *   -h    Show help
 *
 * Build:
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

/* ── Constants ──────────────────────────────────────────────────── */

#define PATH_BUF 1024
#define IO_BUF 4096
#define MB (1024.0 * 1024.0)

/* ── Types ──────────────────────────────────────────────────────── */

typedef struct
{
    char *path;
    size_t size;
    unsigned char hash[MD5_DIGEST_LENGTH];
    int hash_ready;
} FileEntry;

typedef struct
{
    FileEntry *data;
    size_t len;
    size_t cap;
} FileVec;

/* ── Globals ────────────────────────────────────────────────────── */

static FileVec g_files = {0};
static int *g_visited = NULL;
static long long g_freed = 0;
static size_t g_progress = 0;
static size_t g_total = 0;
extern int optind;

/* ── FileVec ────────────────────────────────────────────────────── */

static void vec_init(FileVec *v)
{
    v->cap = 128;
    v->len = 0;
    v->data = malloc(v->cap * sizeof(FileEntry));
    if (!v->data)
    {
        perror("malloc");
        exit(1);
    }
}

static void vec_free(FileVec *v)
{
    for (size_t i = 0; i < v->len; i++)
        free(v->data[i].path);
    free(v->data);
}

static void vec_push(FileVec *v, FileEntry e)
{
    if (v->len >= v->cap)
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
    v->data[v->len++] = e;
}

/* ── File utilities ─────────────────────────────────────────────── */

/* Computes the MD5 digest of a file into `out`. Returns 1 on success. */
static int compute_md5(const char *path, unsigned char *out)
{
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return 0;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        fclose(fp);
        return 0;
    }

    EVP_DigestInit_ex(ctx, EVP_md5(), NULL);

    unsigned char buf[IO_BUF];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0)
        EVP_DigestUpdate(ctx, buf, n);

    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, out, &len);

    EVP_MD_CTX_free(ctx);
    fclose(fp);
    return 1;
}

/* Returns 1 if two files share the same byte content. */
static int files_identical(const char *a, const char *b)
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
    int equal = 1;
    size_t ra, rb;

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

/* Lazily computes the MD5 of entry `e` (once only). */
static void ensure_hash(FileEntry *e)
{
    if (!e->hash_ready)
    {
        compute_md5(e->path, e->hash);
        e->hash_ready = 1;
    }
}

/* Returns 1 if two entries are confirmed duplicates. */
static int entries_match(FileEntry *a, FileEntry *b)
{
    if (a->size != b->size)
        return 0;
    ensure_hash(a);
    ensure_hash(b);
    if (memcmp(a->hash, b->hash, MD5_DIGEST_LENGTH) != 0)
        return 0;
    return files_identical(a->path, b->path);
}

/* ── Directory scan ─────────────────────────────────────────────── */

static void scan_dir(const char *base, int recursive, int include_hidden)
{
    DIR *dir = opendir(base);
    if (!dir)
    {
        perror("opendir");
        return;
    }

    struct dirent *de;
    char path[PATH_BUF];

    while ((de = readdir(dir)) != NULL)
    {
        /* Always skip . and .. */
        if (de->d_name[0] == '.' &&
            (de->d_name[1] == '\0' ||
             (de->d_name[1] == '.' && de->d_name[2] == '\0')))
            continue;

        /* Skip hidden entries unless -H was given */
        if (!include_hidden && de->d_name[0] == '.')
            continue;

        int sep = base[strlen(base) - 1] != '/';
        snprintf(path, sizeof(path), "%s%s%s", base, sep ? "/" : "", de->d_name);

        struct stat st;
        if (stat(path, &st) == -1)
            continue;

        if (S_ISDIR(st.st_mode) && recursive)
        {
            scan_dir(path, recursive, include_hidden);
        }
        else if (S_ISREG(st.st_mode))
        {
            /* realpath() allocates a PATH_MAX buffer — we own the pointer. */
            char *resolved = realpath(path, NULL);
            if (resolved)
                vec_push(&g_files, (FileEntry){.path = resolved, .size = (size_t)st.st_size});
        }
    }

    closedir(dir);
}

static int cmp_size(const void *a, const void *b)
{
    size_t sa = ((const FileEntry *)a)->size;
    size_t sb = ((const FileEntry *)b)->size;
    return (sa > sb) - (sa < sb);
}

static void scan_and_sort(const char *path, int recursive, int include_hidden)
{
    printf("Scanning %s%s%s…\n",
           path,
           recursive ? " (recursive)" : "",
           include_hidden ? " (including hidden)" : "");
    scan_dir(path, recursive, include_hidden);
    qsort(g_files.data, g_files.len, sizeof(FileEntry), cmp_size);
    printf("Found %zu file(s). Looking for duplicates…\n\n", g_files.len);
}

static void print_progress(size_t i, size_t total)
{
    int width = 30;

    float ratio = total ? (float)i / (float)total : 0.0f;
    if (ratio > 1.0f)
        ratio = 1.0f;

    int filled = (int)(ratio * width);

    printf("\r[");
    for (int j = 0; j < width; j++)
        putchar(j < filled ? '#' : '-');

    printf("] %3d%% (%zu/%zu)",
           (int)(ratio * 100),
           i,
           total);

    fflush(stdout);
}

/* ── Deletion ───────────────────────────────────────────────────── */

static void delete_file(const char *path, size_t size, int dry_run)
{
    if (dry_run)
    {
        printf("  [dry-run] would delete: %s\n", path);
        g_freed += (long long)size;
        return;
    }
    if (remove(path) == 0)
    {
        printf("  deleted: %s\n", path);
        g_freed += (long long)size;
    }
    else
    {
        perror("  remove");
    }
}

/* ── TUI helpers ────────────────────────────────────────────────── */

static void format_size(char *buf, size_t sz)
{
    if (sz >= (size_t)(1024 * 1024))
        snprintf(buf, 16, "%.1f MB", sz / MB);
    else if (sz >= 1024)
        snprintf(buf, 16, "%.1f KB", sz / 1024.0);
    else
        snprintf(buf, 16, "%zu B", sz);
}

/* Shows the tail of the path so the filename is always visible. */
static void print_truncated(int row, int col, const char *path, int max_cols)
{
    int len = (int)strlen(path);
    if (len <= max_cols)
        mvprintw(row, col, "%s", path);
    else
        mvprintw(row, col, "…%s", path + (len - max_cols + 1));
}

/* ── ncurses color helpers ──────────────────────────────────────── */

#define CP_HEADER 1 /* cyan   — section labels          */
#define CP_OK 2     /* green  — selected files          */
#define CP_CURSOR 3 /* yellow — cursor row              */
#define CP_DANGER 4 /* red    — file sizes              */
#define CP_STATUS 6 /* black on cyan — top/bottom bars  */

static void init_colors(void)
{
    start_color();
    use_default_colors();
    init_pair(CP_HEADER, COLOR_CYAN, -1);
    init_pair(CP_OK, COLOR_GREEN, -1);
    init_pair(CP_CURSOR, COLOR_YELLOW, -1);
    init_pair(CP_DANGER, COLOR_RED, -1);
    init_pair(CP_STATUS, COLOR_BLACK, COLOR_CYAN);
}

/* ── Interactive prompt ─────────────────────────────────────────── */

/*
 * Displays a group of duplicate files in a full-screen ncurses UI.
 * Navigation: ↑/↓ or j/k · SPACE toggles selection · ENTER confirms · Q skips.
 * At least one file is always kept (selection is capped at count-1).
 */
static int prompt_group(char **paths, size_t *sizes, int count,
                        int group_idx, int total_groups,
                        int auto_delete, int dry_run)
{
    /* In auto mode we silently keep the first file and delete the rest. */
    if (auto_delete)
    {
        for (int i = 1; i < count; i++)
            delete_file(paths[i], sizes[i], dry_run);
        return 1;
    }

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

    int color = has_colors();
    if (color)
        init_colors();

    int *selected = calloc(count, sizeof(int));
    int *sel_queue = malloc(count * sizeof(int));
    if (!selected || !sel_queue)
    {
        perror("malloc");
        endwin();
        return 0;
    }

    int sel_head = 0, cursor = 0;

    for (;;)
    {
        clear();
        int rows, cols;
        getmaxyx(stdscr, rows, cols);

        /* Top status bar */
        if (color)
            attron(COLOR_PAIR(CP_STATUS) | A_BOLD);
        for (int c = 0; c < cols; c++)
            mvaddch(0, c, ' ');
        mvprintw(0, 0, " dupfinder  │  Group %d / %d  │  %d duplicate(s)",
                 group_idx, total_groups, count - 1);
        if (color)
            attroff(COLOR_PAIR(CP_STATUS) | A_BOLD);

        /* Section label */
        if (color)
            attron(COLOR_PAIR(CP_HEADER) | A_BOLD);
        mvprintw(2, 2, "DUPLICATE FILES");
        if (color)
            attroff(COLOR_PAIR(CP_HEADER) | A_BOLD);

        /* File list */
        for (int i = 0; i < count && (4 + i) < rows - 4; i++)
        {
            int row = 4 + i;
            int is_cur = (i == cursor);
            int is_sel = selected[i];

            if (is_cur)
            {
                if (color)
                    attron(COLOR_PAIR(CP_CURSOR) | A_REVERSE | A_BOLD);
                else
                    attron(A_REVERSE);
                for (int c = 0; c < cols; c++)
                    mvaddch(row, c, ' ');
            }

            if (color && is_sel)
                attron(COLOR_PAIR(CP_OK) | A_BOLD);
            mvprintw(row, 2, "[%c]", is_sel ? 'x' : ' ');
            if (color && is_sel)
                attroff(COLOR_PAIR(CP_OK) | A_BOLD);

            mvprintw(row, 6, "%2d.", i + 1);

            char sz[16];
            format_size(sz, sizes[i]);
            if (color)
                attron(COLOR_PAIR(CP_DANGER));
            mvprintw(row, 10, "%-9s", sz);
            if (color)
                attroff(COLOR_PAIR(CP_DANGER));

            if (color && is_sel)
                attron(COLOR_PAIR(CP_OK));
            print_truncated(row, 20, paths[i], cols - 22);
            if (color && is_sel)
                attroff(COLOR_PAIR(CP_OK));

            if (is_cur)
            {
                if (color)
                    attroff(COLOR_PAIR(CP_CURSOR) | A_REVERSE | A_BOLD);
                else
                    attroff(A_REVERSE);
            }
        }

        /* Key hints */
        if (color)
            attron(COLOR_PAIR(CP_HEADER));
        mvprintw(rows - 3, 2,
                 "↑↓/jk  navigate    SPACE  select    ENTER  delete selected    Q  skip");
        if (color)
            attroff(COLOR_PAIR(CP_HEADER));

        /* Bottom status bar */
        int n_sel = 0;
        size_t bytes_freed = 0;
        for (int i = 0; i < count; i++)
            if (selected[i])
            {
                n_sel++;
                bytes_freed += sizes[i];
            }

        char free_sz[16];
        format_size(free_sz, bytes_freed);

        if (color)
            attron(COLOR_PAIR(CP_STATUS));
        for (int c = 0; c < cols; c++)
            mvaddch(rows - 1, c, ' ');
        mvprintw(rows - 1, 0, "  %d file(s) selected  │  %s will be freed%s",
                 n_sel, free_sz, dry_run ? "  [DRY-RUN]" : "");
        if (color)
            attroff(COLOR_PAIR(CP_STATUS));

        refresh();

        /* Input handling */
        int ch = getch();

        if (ch == 'q' || ch == 'Q')
        {
            break;
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
                /* Deselect — remove from queue */
                selected[cursor] = 0;
                int w = 0;
                for (int i = 0; i < sel_head; i++)
                    if (sel_queue[i] != cursor)
                        sel_queue[w++] = sel_queue[i];
                sel_head = w;
            }
            else
            {
                /* Evict oldest if we would select all (must keep one) */
                if (sel_head >= count - 1)
                {
                    selected[sel_queue[0]] = 0;
                    memmove(sel_queue, sel_queue + 1, (--sel_head) * sizeof(int));
                }
                selected[cursor] = 1;
                sel_queue[sel_head++] = cursor;
            }
        }
        else if (ch == 'n' || ch == 'N')
        {
            memset(selected, 0, count * sizeof(int));
            sel_head = 0;
        }
        else if (ch == '\n' || ch == KEY_ENTER)
        {
            endwin();
            for (int i = 0; i < count; i++)
                if (selected[i])
                    delete_file(paths[i], sizes[i], dry_run);
            free(selected);
            free(sel_queue);
            return 1;
        }
    }

    endwin();
    free(selected);
    free(sel_queue);
    return 0;
}

/* ── Group processing (single pass) ────────────────────────────── */

/*
 * Iterates over size-sorted files.  For each unvisited file, gathers all
 * entries with the same size + hash + byte content into a group, then
 * either counts them (dry pass) or interactively handles them (live pass).
 *
 * `on_group` receives (paths, sizes, count, group_index, total, auto_delete,
 * dry_run) and returns 1 if the group was processed, 0 if skipped.
 */
typedef int (*GroupHandler)(char **, size_t *, int, int, int, int, int);

static int iterate_groups(int total, GroupHandler on_group,
                          int auto_delete, int dry_run)
{
    memset(g_visited, 0, g_files.len * sizeof(int));
    int group_idx = 0;

    for (size_t i = 0; i < g_files.len; i++)
    {
        g_progress = i;
        print_progress(i, g_files.len);

        if (g_visited[i])
            continue;

        char **paths = malloc(g_files.len * sizeof(*paths));
        size_t *szs = malloc(g_files.len * sizeof(*szs));
        if (!paths || !szs)
        {
            perror("malloc");
            free(paths);
            free(szs);
            return group_idx;
        }

        int count = 0;
        paths[count] = g_files.data[i].path;
        szs[count++] = g_files.data[i].size;

        for (size_t j = i + 1; j < g_files.len; j++)
        {
            if (g_files.data[j].size != g_files.data[i].size)
                break;
            if (g_visited[j])
                continue;
            if (!entries_match(&g_files.data[i], &g_files.data[j]))
                continue;

            paths[count] = g_files.data[j].path;
            szs[count++] = g_files.data[j].size;
            g_visited[j] = 1;
        }

        if (count > 1)
        {
            group_idx++;
            if (on_group)
                on_group(paths, szs, count, group_idx, total, auto_delete, dry_run);
            g_visited[i] = 1;
        }

        free(paths);
        free(szs);
    }

    print_progress(g_files.len, g_files.len);
    printf("\n");

    return group_idx;
}

static int count_groups(void) { return iterate_groups(0, NULL, 0, 0); }
static void process_groups(int total, int ad, int dr)
{
    g_total = g_files.len;
    g_progress = 0;
    printf("\n");
    iterate_groups(total, prompt_group, ad, dr);
}

/* ── Summary ────────────────────────────────────────────────────── */

static void print_summary(int total_groups, int dry_run)
{
    char freed_str[16];
    snprintf(freed_str, sizeof(freed_str), "%.2f MB", g_freed / MB);

    printf("\n┌─────────────────────────────────┐\n");
    printf("│           Summary               │\n");
    printf("├─────────────────────────────────┤\n");
    printf("│  Groups found   : %-13d │\n", total_groups);
    if (dry_run)
        printf("│  Mode           : DRY-RUN       │\n");
    printf("│  %-15s: %-13s │\n", dry_run ? "Would free" : "Space freed", freed_str);
    printf("└─────────────────────────────────┘\n");
}

/* ── Argument parsing ───────────────────────────────────────────── */

static const char *prog_name(const char *argv0)
{
    const char *p = strrchr(argv0, '/');
    return p ? p + 1 : argv0;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s <folder> [-r] [-d] [-n] [-H] [-h]\n\n"
            "Options:\n"
            "  -r    Scan subdirectories recursively\n"
            "  -d    Auto-delete duplicates (keep first)\n"
            "  -n    Dry-run (no deletion)\n"
            "  -H    Include hidden files and directories (starting with .)\n"
            "  -h    Show help\n",
            prog_name(argv0));
}

static void parse_args(int argc, char *argv[],
                       int *recursive, int *auto_delete, int *dry_run,
                       int *include_hidden)
{
    int opt;
    while ((opt = getopt(argc, argv, "rdnHh")) != -1)
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
        case 'H':
            *include_hidden = 1;
            break;
        case 'h':
            usage(argv[0]);
            exit(0);
        default:
            usage(argv[0]);
            exit(1);
        }
    }
    if (optind >= argc)
    {
        usage(argv[0]);
        exit(1);
    }
}

/* ── Entry point ────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        usage(argv[0]);
        return 1;
    }

    int recursive = 0, auto_delete = 0, dry_run = 0, include_hidden = 0;
    parse_args(argc, argv, &recursive, &auto_delete, &dry_run, &include_hidden);

    setlocale(LC_ALL, "");
    vec_init(&g_files);
    scan_and_sort(argv[optind], recursive, include_hidden);

    g_visited = calloc(g_files.len, sizeof(int));
    if (!g_visited)
    {
        perror("calloc");
        return 1;
    }

    int total = count_groups();
    if (total == 0)
    {
        printf("No duplicates found. You're all clean!\n");
        vec_free(&g_files);
        free(g_visited);
        return 0;
    }

    process_groups(total, auto_delete, dry_run);
    print_summary(total, dry_run);

    vec_free(&g_files);
    free(g_visited);
    return 0;
}