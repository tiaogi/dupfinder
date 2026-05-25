/*
 * dupfinder.c — Interactive duplicate file finder
 *
 * Usage:
 *   dupfinder <folder> [-r] [-d] [-n] [-H] [-t <threads>] [-h]
 *
 *   -r           Scan subdirectories recursively
 *   -d           Auto-delete duplicates (keep first)
 *   -n           Dry-run (no deletion)
 *   -H           Include hidden files and directories (starting with .)
 *   -t <n>       Number of threads (default: number of logical CPUs;
 *                clamped to the system maximum if exceeded)
 *   -h           Show help
 *
 * Build:
 *   gcc dupfinder.c -o dupfinder -lcrypto -lncursesw -lpthread
 */

#define _GNU_SOURCE

#include <dirent.h>
#include <fcntl.h>
#include <locale.h>
#include <ncursesw/ncurses.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/wait.h>
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
    pthread_mutex_t hash_mutex; /* protects lazy hash computation */
} FileEntry;

typedef struct
{
    FileEntry *data;
    size_t len;
    size_t cap;
    pthread_mutex_t mutex; /* protects concurrent push */
} FileVec;

/* ── Scan work-queue ────────────────────────────────────────────── */

/*
 * Each item in the queue is a directory path to scan.
 * Threads pop items, scan them and push any sub-directories they find
 * back into the queue (when recursive mode is on).
 */
typedef struct DirItem
{
    char *path;
    struct DirItem *next;
} DirItem;

typedef struct
{
    DirItem *head;
    DirItem *tail;
    size_t size;
    int idle;  /* threads currently waiting */
    int total; /* total thread count        */
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int shutdown;
} DirQueue;

typedef struct
{
    DirQueue *q;
    int recursive;
    int include_hidden;
} ScanArgs;

/* ── Hash work-queue ────────────────────────────────────────────── */

/*
 * One task = compute MD5 of a single FileEntry (if not already done).
 */
typedef struct
{
    FileEntry **entries;
    size_t count;
    size_t next; /* index of next entry to process */
    pthread_mutex_t mutex;
    pthread_cond_t done_cond;
    size_t finished;
} HashQueue;

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
    pthread_mutex_init(&v->mutex, NULL);
}

static void vec_free(FileVec *v)
{
    for (size_t i = 0; i < v->len; i++)
    {
        free(v->data[i].path);
        pthread_mutex_destroy(&v->data[i].hash_mutex);
    }
    free(v->data);
    pthread_mutex_destroy(&v->mutex);
}

static void vec_push(FileVec *v, FileEntry e)
{
    pthread_mutex_lock(&v->mutex);
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
    e.hash_ready = 0;
    pthread_mutex_init(&e.hash_mutex, NULL);
    v->data[v->len++] = e;
    pthread_mutex_unlock(&v->mutex);
}

/* ── File utilities ─────────────────────────────────────────────── */

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

/* Thread-safe lazy MD5 computation. */
static void ensure_hash(FileEntry *e)
{
    pthread_mutex_lock(&e->hash_mutex);
    if (!e->hash_ready)
    {
        compute_md5(e->path, e->hash);
        e->hash_ready = 1;
    }
    pthread_mutex_unlock(&e->hash_mutex);
}

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

/* ── Dir-queue helpers ──────────────────────────────────────────── */

static void dirq_init(DirQueue *q, int total_threads)
{
    q->head = NULL;
    q->tail = NULL;
    q->size = 0;
    q->idle = 0;
    q->total = total_threads;
    q->shutdown = 0;
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->cond, NULL);
}

static void dirq_destroy(DirQueue *q)
{
    /* drain any leftover items */
    DirItem *it = q->head;
    while (it)
    {
        DirItem *nx = it->next;
        free(it->path);
        free(it);
        it = nx;
    }
    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->cond);
}

/* Push a directory path into the queue (takes ownership of `path`). */
static void dirq_push(DirQueue *q, char *path)
{
    DirItem *item = malloc(sizeof(DirItem));
    if (!item)
    {
        free(path);
        return;
    }
    item->path = path;
    item->next = NULL;

    pthread_mutex_lock(&q->mutex);
    if (q->tail)
        q->tail->next = item;
    else
        q->head = item;
    q->tail = item;
    q->size++;
    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->mutex);
}

/*
 * Pop a path from the queue.
 * Returns NULL only when there is no more work AND all threads are idle
 * (i.e. the entire scan is finished).
 */
static char *dirq_pop(DirQueue *q)
{
    pthread_mutex_lock(&q->mutex);
    q->idle++;

    while (!q->shutdown)
    {
        if (q->head)
        {
            /* work available */
            DirItem *item = q->head;
            q->head = item->next;
            if (!q->head)
                q->tail = NULL;
            q->size--;
            q->idle--;
            pthread_mutex_unlock(&q->mutex);
            char *p = item->path;
            free(item);
            return p;
        }

        /* No work: are all threads idle? */
        if (q->idle == q->total)
        {
            /* Broadcast so everyone wakes and exits */
            q->shutdown = 1;
            pthread_cond_broadcast(&q->cond);
            pthread_mutex_unlock(&q->mutex);
            return NULL;
        }

        pthread_cond_wait(&q->cond, &q->mutex);
    }

    q->idle--;
    pthread_mutex_unlock(&q->mutex);
    return NULL;
}

/* ── Scan thread ────────────────────────────────────────────────── */

static void scan_dir_into_queue(const char *base, DirQueue *q,
                                int recursive, int include_hidden)
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
        if (de->d_name[0] == '.' &&
            (de->d_name[1] == '\0' ||
             (de->d_name[1] == '.' && de->d_name[2] == '\0')))
            continue;

        if (!include_hidden && de->d_name[0] == '.')
            continue;

        int sep = base[strlen(base) - 1] != '/';
        snprintf(path, sizeof(path), "%s%s%s", base, sep ? "/" : "", de->d_name);

        struct stat st;
        if (stat(path, &st) == -1)
            continue;

        if (S_ISDIR(st.st_mode) && recursive)
        {
            char *copy = strdup(path);
            if (copy)
                dirq_push(q, copy);
        }
        else if (S_ISREG(st.st_mode))
        {
            char *resolved = realpath(path, NULL);
            if (resolved)
                vec_push(&g_files, (FileEntry){
                                       .path = resolved,
                                       .size = (size_t)st.st_size,
                                       .hash_ready = 0});
        }
    }

    closedir(dir);
}

static void *scan_thread(void *arg)
{
    ScanArgs *sa = (ScanArgs *)arg;
    char *path;

    while ((path = dirq_pop(sa->q)) != NULL)
    {
        scan_dir_into_queue(path, sa->q, sa->recursive, sa->include_hidden);
        free(path);
    }

    return NULL;
}

/* ── Hash thread pool ───────────────────────────────────────────── */

static void *hash_thread(void *arg)
{
    HashQueue *hq = (HashQueue *)arg;

    for (;;)
    {
        pthread_mutex_lock(&hq->mutex);
        size_t idx = hq->next;
        if (idx >= hq->count)
        {
            pthread_mutex_unlock(&hq->mutex);
            break;
        }
        hq->next++;
        pthread_mutex_unlock(&hq->mutex);

        ensure_hash(hq->entries[idx]);

        pthread_mutex_lock(&hq->mutex);
        hq->finished++;
        if (hq->finished == hq->count)
            pthread_cond_broadcast(&hq->done_cond);
        pthread_mutex_unlock(&hq->mutex);
    }

    return NULL;
}

/*
 * Pre-compute MD5 for all files in a size-group using the thread pool.
 * This avoids doing it lazily (and serially) inside entries_match().
 */
static void parallel_hash(FileEntry **entries, int count, int n_threads)
{
    if (count <= 0)
        return;

    HashQueue hq = {
        .entries = entries,
        .count = (size_t)count,
        .next = 0,
        .finished = 0};
    pthread_mutex_init(&hq.mutex, NULL);
    pthread_cond_init(&hq.done_cond, NULL);

    int actual = n_threads < count ? n_threads : count;
    pthread_t *tids = malloc(actual * sizeof(pthread_t));
    if (!tids)
    {
        perror("malloc");
        return;
    }

    for (int i = 0; i < actual; i++)
        pthread_create(&tids[i], NULL, hash_thread, &hq);

    pthread_mutex_lock(&hq.mutex);
    while (hq.finished < hq.count)
        pthread_cond_wait(&hq.done_cond, &hq.mutex);
    pthread_mutex_unlock(&hq.mutex);

    for (int i = 0; i < actual; i++)
        pthread_join(tids[i], NULL);

    free(tids);
    pthread_mutex_destroy(&hq.mutex);
    pthread_cond_destroy(&hq.done_cond);
}

/* ── Directory scan entry-point ─────────────────────────────────── */

static int cmp_size(const void *a, const void *b)
{
    size_t sa = ((const FileEntry *)a)->size;
    size_t sb = ((const FileEntry *)b)->size;
    return (sa > sb) - (sa < sb);
}

static void scan_and_sort(const char *root, int recursive,
                          int include_hidden, int n_threads)
{
    printf("Scanning %s%s%s… (%d thread%s)\n",
           root,
           recursive ? " (recursive)" : "",
           include_hidden ? " (including hidden)" : "",
           n_threads,
           n_threads > 1 ? "s" : "");

    DirQueue q;
    dirq_init(&q, n_threads);

    /* Seed the queue with the root directory */
    char *root_copy = strdup(root);
    if (!root_copy)
    {
        perror("strdup");
        exit(1);
    }
    dirq_push(&q, root_copy);

    ScanArgs sa = {.q = &q, .recursive = recursive, .include_hidden = include_hidden};

    pthread_t *tids = malloc(n_threads * sizeof(pthread_t));
    if (!tids)
    {
        perror("malloc");
        exit(1);
    }

    for (int i = 0; i < n_threads; i++)
        pthread_create(&tids[i], NULL, scan_thread, &sa);

    for (int i = 0; i < n_threads; i++)
        pthread_join(tids[i], NULL);

    free(tids);
    dirq_destroy(&q);

    qsort(g_files.data, g_files.len, sizeof(FileEntry), cmp_size);
    printf("Found %zu file(s). Looking for duplicates…\n\n", g_files.len);
}

/* ── Progress bar ───────────────────────────────────────────────── */

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
    printf("] %3d%% (%zu/%zu)", (int)(ratio * 100), i, total);
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
        perror("  remove");
}

/* ── File opener ────────────────────────────────────────────────── */

static void open_file(const char *path)
{
    pid_t pid = fork();
    if (pid < 0)
        return;

    if (pid == 0)
    {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0)
        {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        setsid();
        execlp("xdg-open", "xdg-open", path, NULL);
        _exit(1);
    }

    waitpid(pid, NULL, WNOHANG);
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

static void print_truncated(int row, int col, const char *path, int max_cols)
{
    int len = (int)strlen(path);
    if (len <= max_cols)
        mvprintw(row, col, "%s", path);
    else
        mvprintw(row, col, "…%s", path + (len - max_cols + 1));
}

/* ── ncurses colors ─────────────────────────────────────────────── */

#define CP_HEADER 1
#define CP_OK 2
#define CP_CURSOR 3
#define CP_DANGER 4
#define CP_STATUS 6

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

static int prompt_group(char **paths, size_t *sizes, int count,
                        int group_idx, int total_groups,
                        int auto_delete, int dry_run)
{
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

        if (color)
            attron(COLOR_PAIR(CP_STATUS) | A_BOLD);
        for (int c = 0; c < cols; c++)
            mvaddch(0, c, ' ');
        mvprintw(0, 0, " dupfinder  │  Group %d / %d  │  %d duplicate(s)",
                 group_idx, total_groups, count - 1);
        if (color)
            attroff(COLOR_PAIR(CP_STATUS) | A_BOLD);

        if (color)
            attron(COLOR_PAIR(CP_HEADER) | A_BOLD);
        mvprintw(2, 2, "DUPLICATE FILES");
        if (color)
            attroff(COLOR_PAIR(CP_HEADER) | A_BOLD);

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

        if (color)
            attron(COLOR_PAIR(CP_HEADER));
        mvprintw(rows - 3, 2,
                 "↑↓/jk  navigate    SPACE  select    O  open    ^O  open all    ENTER  delete selected    Q  skip");
        if (color)
            attroff(COLOR_PAIR(CP_HEADER));

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

        int ch = getch();

        if (ch == 'q' || ch == 'Q')
            break;
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
                selected[cursor] = 0;
                int w = 0;
                for (int i = 0; i < sel_head; i++)
                    if (sel_queue[i] != cursor)
                        sel_queue[w++] = sel_queue[i];
                sel_head = w;
            }
            else
            {
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
        else if (ch == ('o' & 0x1f))
        {
            for (int i = 0; i < count; i++)
                open_file(paths[i]);
        }
        else if (ch == 'o' || ch == 'O')
            open_file(paths[cursor]);
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

/* ── Group processing ───────────────────────────────────────────── */

typedef int (*GroupHandler)(char **, size_t *, int, int, int, int, int);

static int iterate_groups(int total, GroupHandler on_group,
                          int auto_delete, int dry_run, int n_threads)
{
    memset(g_visited, 0, g_files.len * sizeof(int));
    int group_idx = 0;

    /* We work on slices of consecutive same-size files.
     * For each slice we pre-hash all entries in parallel, then do the
     * pairwise comparison (still serial — avoids false sharing on g_visited). */

    size_t i = 0;
    while (i < g_files.len)
    {
        g_progress = i;
        print_progress(i, g_files.len);

        /* Find the end of the current size-group */
        size_t j = i + 1;
        while (j < g_files.len &&
               g_files.data[j].size == g_files.data[i].size)
            j++;

        /* If more than one file shares this size, pre-hash them all in parallel */
        if (j - i > 1)
        {
            int slice_len = (int)(j - i);
            FileEntry **slice = malloc(slice_len * sizeof(FileEntry *));
            if (slice)
            {
                for (int k = 0; k < slice_len; k++)
                    slice[k] = &g_files.data[i + k];
                parallel_hash(slice, slice_len, n_threads);
                free(slice);
            }
        }

        /* Now do serial pairwise matching within the slice */
        for (size_t ii = i; ii < j; ii++)
        {
            if (g_visited[ii])
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
            paths[count] = g_files.data[ii].path;
            szs[count++] = g_files.data[ii].size;

            for (size_t jj = ii + 1; jj < j; jj++)
            {
                if (g_visited[jj])
                    continue;
                if (!entries_match(&g_files.data[ii], &g_files.data[jj]))
                    continue;
                paths[count] = g_files.data[jj].path;
                szs[count++] = g_files.data[jj].size;
                g_visited[jj] = 1;
            }

            if (count > 1)
            {
                group_idx++;
                if (on_group)
                    on_group(paths, szs, count, group_idx, total, auto_delete, dry_run);
                g_visited[ii] = 1;
            }

            free(paths);
            free(szs);
        }

        i = j;
    }

    print_progress(g_files.len, g_files.len);
    printf("\n");

    return group_idx;
}

static int count_groups(int nt) { return iterate_groups(0, NULL, 0, 0, nt); }
static void process_groups(int total, int ad, int dr, int nt)
{
    g_total = g_files.len;
    g_progress = 0;
    printf("\n");
    iterate_groups(total, prompt_group, ad, dr, nt);
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
    printf("│  %-15s: %-13s │\n",
           dry_run ? "Would free" : "Space freed", freed_str);
    printf("└─────────────────────────────────┘\n");
}

/* ── Thread count helper ────────────────────────────────────────── */

/*
 * Returns the number of threads to use:
 *   - default (requested == 0): all logical CPUs
 *   - explicit: clamped to [1, nprocs]
 */
static int resolve_threads(int requested)
{
    int nprocs = get_nprocs(); /* <sys/sysinfo.h> */
    if (nprocs < 1)
        nprocs = 1;

    if (requested <= 0)
        return nprocs;

    if (requested > nprocs)
    {
        fprintf(stderr,
                "Warning: requested %d threads but system has only %d logical CPU(s). "
                "Clamping to %d.\n",
                requested, nprocs, nprocs);
        return nprocs;
    }

    return requested;
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
            "Usage: %s <folder> [-r] [-d] [-n] [-H] [-t <threads>] [-h]\n\n"
            "Options:\n"
            "  -r           Scan subdirectories recursively\n"
            "  -d           Auto-delete duplicates (keep first)\n"
            "  -n           Dry-run (no deletion)\n"
            "  -H           Include hidden files and directories (starting with .)\n"
            "  -t <n>       Number of threads (default: logical CPU count;\n"
            "               clamped to system maximum if exceeded)\n"
            "  -h           Show help\n",
            prog_name(argv0));
}

static void parse_args(int argc, char *argv[],
                       int *recursive, int *auto_delete, int *dry_run,
                       int *include_hidden, int *n_threads)
{
    int opt;
    while ((opt = getopt(argc, argv, "rdnHt:h")) != -1)
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
        case 't':
            *n_threads = atoi(optarg);
            if (*n_threads < 1)
            {
                fprintf(stderr, "Error: -t requires a positive integer.\n");
                usage(argv[0]);
                exit(1);
            }
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
    int requested_threads = 0; /* 0 = use all CPUs */

    parse_args(argc, argv, &recursive, &auto_delete, &dry_run,
               &include_hidden, &requested_threads);

    int n_threads = resolve_threads(requested_threads);

    setlocale(LC_ALL, "");
    vec_init(&g_files);
    scan_and_sort(argv[optind], recursive, include_hidden, n_threads);

    g_visited = calloc(g_files.len, sizeof(int));
    if (!g_visited)
    {
        perror("calloc");
        return 1;
    }

    int total = count_groups(n_threads);
    if (total == 0)
    {
        printf("No duplicates found. You're all clean!\n");
        vec_free(&g_files);
        free(g_visited);
        return 0;
    }

    process_groups(total, auto_delete, dry_run, n_threads);
    print_summary(total, dry_run);

    vec_free(&g_files);
    free(g_visited);
    return 0;
}