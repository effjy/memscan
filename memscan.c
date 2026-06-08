#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>

#define DEFAULT_DUMP_LEN 256
#define CHUNK_SIZE 65536

struct magic_pattern {
    const char *name;
    uint8_t bytes[64];
    size_t len;
};

struct magic_pattern default_patterns[] = {
    {"PNG Image", {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, 8},
    {"PDF Document", {0x25, 0x50, 0x44, 0x46}, 4}, // "%PDF"
    {"ZIP Archive", {0x50, 0x4B, 0x03, 0x04}, 4}, // "PK\x03\x04"
    {"ELF Binary", {0x7F, 0x45, 0x4C, 0x46}, 4}, // "\x7fELF"
    {"JPEG Image", {0xFF, 0xD8, 0xFF}, 3}
};
#define NUM_DEFAULT_PATTERNS (sizeof(default_patterns)/sizeof(default_patterns[0]))

// Scan settings structure
struct scan_config {
    int target_pid;
    bool scan_defaults;
    size_t dump_len;
    bool ascii_only;
    bool writable_only;
    bool case_insensitive;
    unsigned long restrict_start;
    unsigned long restrict_end;
    bool has_range;
    long max_matches;
    long match_count;
    FILE *out_file;
};

// Function declarations
size_t parse_magic(const char *input, uint8_t *buffer, size_t max_len);
ssize_t read_memory(int mem_fd, unsigned long addr, uint8_t *buf, size_t size);
void dump_recovered_data(FILE *out, const uint8_t *data, size_t len, bool ascii_only);
void scan_region(int mem_fd, unsigned long start, unsigned long end, const char *perms, const char *pathname,
                 const struct magic_pattern *patterns, size_t num_patterns, struct scan_config *config);
void print_usage(const char *prog_name);
void *memmem_case(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len);

// Test string to scan for self-contained verification
volatile const char self_test_string[] = "MEMSCAN_SELFTEST_STRING_9999_SECRET_DATA_xyz_12345!";

int main(int argc, char *argv[]) {
    char pid_str[64] = "";
    struct scan_config config;
    memset(&config, 0, sizeof(config));
    config.target_pid = -1;
    config.dump_len = DEFAULT_DUMP_LEN;
    config.ascii_only = true;
    config.max_matches = -1; // unlimited
    config.out_file = stdout;

    struct magic_pattern custom_pattern;
    memset(&custom_pattern, 0, sizeof(custom_pattern));
    custom_pattern.name = "Custom Pattern";
    bool custom_specified = false;

    int opt;
    while ((opt = getopt(argc, argv, "p:m:l:xr:n:o:wshicv")) != -1) {
        switch (opt) {
            case 'v':
                printf("memscan version 1.0.5\n");
                return 0;
            case 'p':
                strncpy(pid_str, optarg, sizeof(pid_str) - 1);
                break;
            case 'm':
                custom_pattern.len = parse_magic(optarg, custom_pattern.bytes, sizeof(custom_pattern.bytes));
                if (custom_pattern.len == 0) {
                    fprintf(stderr, "Error parsing magic string '%s'\n", optarg);
                    return 1;
                }
                custom_specified = true;
                break;
            case 'l': {
                char *l_end = NULL;
                errno = 0;
                long l_val = strtol(optarg, &l_end, 10);
                if (errno != 0 || l_end == optarg || *l_end != '\0' || l_val <= 0) {
                    fprintf(stderr, "Error: Dump length must be a positive integer.\n");
                    return 1;
                }
                config.dump_len = (size_t)l_val;
                break;
            }
            case 'x':
                config.ascii_only = false; // hex dump mode
                break;
            case 'w':
                config.writable_only = true;
                break;
            case 'i':
            case 'c': // compatibility flag for case-insensitivity
                config.case_insensitive = true;
                break;
            case 'r': {
                unsigned long r_start = 0, r_end = 0;
                if (sscanf(optarg, "0x%lx-0x%lx", &r_start, &r_end) == 2 ||
                    sscanf(optarg, "%lx-%lx", &r_start, &r_end) == 2) {
                    config.restrict_start = r_start;
                    config.restrict_end = r_end;
                    config.has_range = true;
                } else {
                    fprintf(stderr, "Error: Invalid range format. Use <start>-<end> in hex (e.g. 0x1000-0x2000).\n");
                    return 1;
                }
                break;
            }
            case 'n':
                config.max_matches = strtol(optarg, NULL, 10);
                if (config.max_matches <= 0) {
                    fprintf(stderr, "Error: Max match count must be greater than 0.\n");
                    return 1;
                }
                break;
            case 'o':
                config.out_file = fopen(optarg, "w");
                if (!config.out_file) {
                    perror("Error opening output file for writing");
                    return 1;
                }
                break;
            case 's':
                config.scan_defaults = true;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (pid_str[0] == '\0') {
        fprintf(stderr, "Error: PID (-p) is required. Use a positive integer or 'self'.\n");
        print_usage(argv[0]);
        if (config.out_file && config.out_file != stdout) fclose(config.out_file);
        return 1;
    }

    if (strcmp(pid_str, "self") == 0) {
        config.target_pid = getpid();
    } else {
        char *pid_end = NULL;
        errno = 0;
        long pid_val = strtol(pid_str, &pid_end, 10);
        if (errno != 0 || pid_end == pid_str || *pid_end != '\0' ||
            pid_val <= 0 || pid_val > INT_MAX) {
            fprintf(stderr, "Error: Invalid PID '%s' specified.\n", pid_str);
            if (config.out_file && config.out_file != stdout) fclose(config.out_file);
            return 1;
        }
        config.target_pid = (int)pid_val;
    }

    if (config.target_pid <= 0) {
        fprintf(stderr, "Error: Invalid PID '%s' specified.\n", pid_str);
        if (config.out_file && config.out_file != stdout) fclose(config.out_file);
        return 1;
    }

    if (kill(config.target_pid, 0) < 0) {
        if (errno == ESRCH) {
            fprintf(stderr, "Error: Process with PID %d does not exist.\n", config.target_pid);
        } else if (errno == EPERM) {
            fprintf(stderr, "Error: Process with PID %d exists, but you do not have permission to access it.\n", config.target_pid);
        } else {
            perror("Error checking PID");
        }
        if (config.out_file && config.out_file != stdout) fclose(config.out_file);
        return 1;
    }

    struct magic_pattern *active_patterns = NULL;
    size_t num_patterns = 0;

    if (custom_specified) {
        active_patterns = &custom_pattern;
        num_patterns = 1;
    } else {
        if (!config.scan_defaults) {
            fprintf(config.out_file, "No custom pattern (-m) specified. Defaulting to scan for common file signatures (-s).\n");
        }
        active_patterns = default_patterns;
        num_patterns = NUM_DEFAULT_PATTERNS;
    }

    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", config.target_pid);
    FILE *maps = fopen(maps_path, "r");
    if (!maps) {
        perror("Failed to open process maps file. Are you sure the PID is correct?");
        if (config.out_file && config.out_file != stdout) fclose(config.out_file);
        return 1;
    }

    char mem_path[256];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", config.target_pid);
    int mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd < 0) {
        perror("Failed to open process memory. Try running with 'sudo' or check ptrace permissions.");
        fclose(maps);
        if (config.out_file && config.out_file != stdout) fclose(config.out_file);
        return 1;
    }

    fprintf(config.out_file, "Starting memory scan for PID %d...\n", config.target_pid);
    if (custom_specified) {
        fprintf(config.out_file, "Searching for custom pattern: ");
        for (size_t i = 0; i < custom_pattern.len; i++) {
            if (isprint(custom_pattern.bytes[i])) {
                fputc(custom_pattern.bytes[i], config.out_file);
            } else {
                fprintf(config.out_file, "\\x%02x", custom_pattern.bytes[i]);
            }
        }
        fprintf(config.out_file, " (%zu bytes)\n", custom_pattern.len);
    } else {
        fprintf(config.out_file, "Searching for default patterns:\n");
        for (size_t i = 0; i < num_patterns; i++) {
            fprintf(config.out_file, "  - %s\n", default_patterns[i].name);
        }
    }
    fprintf(config.out_file, "Dump format: %s (%zu bytes)\n", config.ascii_only ? "ASCII Plain Text" : "Hex+ASCII Dump", config.dump_len);
    if (config.writable_only) {
        fprintf(config.out_file, "Filter: Writable regions only\n");
    }
    if (config.case_insensitive) {
        fprintf(config.out_file, "Filter: Case-insensitive search\n");
    }
    if (config.has_range) {
        fprintf(config.out_file, "Filter: Restricting scan to address range 0x%lx-0x%lx\n", config.restrict_start, config.restrict_end);
    }
    if (config.max_matches > 0) {
        fprintf(config.out_file, "Filter: Limit output to %ld match(es)\n", config.max_matches);
    }
    fprintf(config.out_file, "========================================================================\n\n");

    char line[512];
    while (fgets(line, sizeof(line), maps)) {
        if (config.max_matches > 0 && config.match_count >= config.max_matches) {
            break;
        }

        unsigned long start = 0, end = 0;
        char perms[5] = {0};
        unsigned long offset = 0;
        char pathname[256] = {0};

        int n = sscanf(line, "%lx-%lx %4s %lx %*s %*s %255[^\n]", &start, &end, perms, &offset, pathname);
        if (n < 4) {
            continue;
        }

        // Strip leading whitespace from pathname
        char *p = pathname;
        while (*p && isspace((unsigned char)*p)) {
            p++;
        }
        memmove(pathname, p, strlen(p) + 1);

        // Filter: only scan regions that are readable ('r')
        if (perms[0] != 'r') {
            continue;
        }

        // Filter: if writable_only is active, check 'w' permission
        if (config.writable_only && perms[1] != 'w') {
            continue;
        }

        // Filter: check address range restriction if specified
        if (config.has_range) {
            // Check if map intersects with target range
            if (end <= config.restrict_start || start >= config.restrict_end) {
                continue;
            }
            // Clip scanning coordinates to restrict range
            if (start < config.restrict_start) start = config.restrict_start;
            if (end > config.restrict_end) end = config.restrict_end;
        }

        // Avoid scanning special device files or Vsdb/Vvar maps, but keep anonymous/heap/stack
        if (strcmp(pathname, "[vvar]") == 0 || strcmp(pathname, "[vdso]") == 0) {
            continue;
        }

        scan_region(mem_fd, start, end, perms, pathname, active_patterns, num_patterns, &config);
    }

    fprintf(config.out_file, "Memory scan completed. Found %ld match(es).\n", config.match_count);
    close(mem_fd);
    fclose(maps);
    if (config.out_file && config.out_file != stdout) {
        fclose(config.out_file);
    }
    return 0;
}

size_t parse_magic(const char *input, uint8_t *buffer, size_t max_len) {
    size_t out_len = 0;
    size_t in_len = strlen(input);

    if (in_len >= 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')) {
        const char *hex = input + 2;
        size_t hex_len = strlen(hex);
        for (size_t i = 0; i + 1 < hex_len && out_len < max_len; i += 2) {
            unsigned int val;
            if (sscanf(hex + i, "%2x", &val) == 1) {
                buffer[out_len++] = (uint8_t)val;
            } else {
                fprintf(stderr, "Error: Invalid hex character in magic string near '%s'\n", hex + i);
                return 0;
            }
        }
        return out_len;
    }

    for (size_t i = 0; i < in_len && out_len < max_len; i++) {
        if (input[i] == '\\') {
            if (i + 1 >= in_len) {
                buffer[out_len++] = '\\';
                break;
            }
            i++;
            switch (input[i]) {
                case 'n':  buffer[out_len++] = '\n'; break;
                case 'r':  buffer[out_len++] = '\r'; break;
                case 't':  buffer[out_len++] = '\t'; break;
                case '\\': buffer[out_len++] = '\\'; break;
                case 'x': case 'X': {
                    if (i + 2 < in_len) {
                        unsigned int val;
                        char hex_buf[3] = { input[i+1], input[i+2], '\0' };
                        if (sscanf(hex_buf, "%x", &val) == 1) {
                            buffer[out_len++] = (uint8_t)val;
                            i += 2;
                        } else {
                            fprintf(stderr, "Warning: Invalid hex escape sequence '\\x%s', treating as literal.\n", hex_buf);
                            buffer[out_len++] = 'x';
                        }
                    } else {
                        fprintf(stderr, "Warning: Incomplete hex escape sequence, treating as literal.\n");
                        buffer[out_len++] = 'x';
                    }
                    break;
                }
                default:
                    buffer[out_len++] = input[i];
                    break;
            }
        } else {
            buffer[out_len++] = input[i];
        }
    }
    return out_len;
}

ssize_t read_memory(int mem_fd, unsigned long addr, uint8_t *buf, size_t size) {
    // Attempt standard pread64
    ssize_t bytes_read = pread64(mem_fd, buf, size, (off64_t)addr);
    if (bytes_read > 0) {
        return bytes_read;
    }

    // Fall back to reading page by page if large read failed. Track the highest
    // offset that contained real data so we report an accurate byte count rather
    // than counting zero-filled holes as valid.
    size_t total_read = 0;
    size_t last_valid_end = 0;
    size_t page_size = 4096;
    for (size_t offset = 0; offset < size; offset += page_size) {
        size_t to_read = (size - offset < page_size) ? (size - offset) : page_size;
        ssize_t r = pread64(mem_fd, buf + offset, to_read, (off64_t)(addr + offset));
        if (r > 0) {
            total_read += r;
            last_valid_end = offset + (size_t)r;
            if ((size_t)r < to_read) {
                memset(buf + offset + r, 0, to_read - r);
            }
        } else {
            memset(buf + offset, 0, to_read);
        }
    }
    return total_read > 0 ? (ssize_t)last_valid_end : -1;
}

void dump_recovered_data(FILE *out, const uint8_t *data, size_t len, bool ascii_only) {
    if (ascii_only) {
        for (size_t i = 0; i < len; i++) {
            uint8_t c = data[i];
            if (isprint(c) || c == '\n' || c == '\r' || c == '\t') {
                fputc(c, out);
            } else {
                fputc('.', out);
            }
        }
        fprintf(out, "\n");
    } else {
        for (size_t i = 0; i < len; i += 16) {
            fprintf(out, "  %04zx: ", i);
            for (size_t j = 0; j < 16; j++) {
                if (i + j < len) {
                    fprintf(out, "%02x ", data[i + j]);
                } else {
                    fprintf(out, "   ");
                }
            }
            fprintf(out, " |");
            for (size_t j = 0; j < 16; j++) {
                if (i + j < len) {
                    uint8_t c = data[i + j];
                    if (isprint(c)) {
                        fputc(c, out);
                    } else {
                        fputc('.', out);
                    }
                } else {
                    fputc(' ', out);
                }
            }
            fprintf(out, "|\n");
        }
    }
}

// Custom case-insensitive memmem implementation
void *memmem_case(const void *haystack, size_t haystack_len, const void *needle, size_t needle_len) {
    if (needle_len == 0) return (void *)haystack;
    if (haystack_len < needle_len) return NULL;

    const uint8_t *h = (const uint8_t *)haystack;
    const uint8_t *n = (const uint8_t *)needle;

    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        bool match = true;
        for (size_t j = 0; j < needle_len; j++) {
            if (tolower(h[i + j]) != tolower(n[j])) {
                match = false;
                break;
            }
        }
        if (match) {
            return (void *)(h + i);
        }
    }
    return NULL;
}

void scan_region(int mem_fd, unsigned long start, unsigned long end, const char *perms, const char *pathname,
                 const struct magic_pattern *patterns, size_t num_patterns, struct scan_config *config) {
    size_t max_magic_len = 0;
    for (size_t i = 0; i < num_patterns; i++) {
        if (patterns[i].len > max_magic_len) {
            max_magic_len = patterns[i].len;
        }
    }
    if (max_magic_len == 0) return;

    size_t overlap_len = max_magic_len > 1 ? max_magic_len - 1 : 0;
    uint8_t *prev_overlap = overlap_len ? malloc(overlap_len) : NULL;
    bool has_prev = false;

    unsigned long addr = start;
    while (addr < end) {
        if (config->max_matches > 0 && config->match_count >= config->max_matches) {
            break;
        }

        size_t to_read = CHUNK_SIZE;
        if (addr + to_read > end) {
            to_read = end - addr;
        }

        size_t scan_size = to_read + (has_prev ? overlap_len : 0);
        uint8_t *scan_buf = malloc(scan_size);
        if (!scan_buf) {
            fprintf(stderr, "Out of memory allocating scan buffer\n");
            break;
        }

        size_t read_offset = 0;
        if (has_prev && prev_overlap) {
            memcpy(scan_buf, prev_overlap, overlap_len);
            read_offset = overlap_len;
        }

        ssize_t r = read_memory(mem_fd, addr, scan_buf + read_offset, to_read);
        if (r <= 0) {
            free(scan_buf);
            addr += to_read;
            has_prev = false;
            continue;
        }

        // read_memory may return fewer bytes than requested (short reads happen
        // at page/region boundaries in /proc/pid/mem). Only scan/carry the bytes
        // actually read; the rest of scan_buf is uninitialized heap.
        size_t valid_read = (size_t)r;
        scan_size = read_offset + valid_read;

        // Actual scanning
        for (size_t p_idx = 0; p_idx < num_patterns; p_idx++) {
            if (config->max_matches > 0 && config->match_count >= config->max_matches) {
                break;
            }

            const struct magic_pattern *pat = &patterns[p_idx];
            uint8_t *curr = scan_buf;
            size_t remaining = scan_size;

            while (remaining >= pat->len) {
                uint8_t *match = NULL;
                if (config->case_insensitive) {
                    match = memmem_case(curr, remaining, pat->bytes, pat->len);
                } else {
                    match = memmem(curr, remaining, pat->bytes, pat->len);
                }

                if (!match) {
                    break;
                }

                size_t match_offset = match - scan_buf;
                // Exclude matches that end at or before the overlap boundary (which were fully processed in previous chunk)
                if (!has_prev || (match_offset + pat->len > read_offset)) {
                    unsigned long match_addr = addr + match_offset - read_offset;
                    
                    size_t actual_dump_len = config->dump_len;
                    if (match_addr + actual_dump_len > end) {
                        actual_dump_len = end - match_addr;
                    }

                    uint8_t *dump_buf = malloc(actual_dump_len);
                    if (dump_buf) {
                        ssize_t dump_r = read_memory(mem_fd, match_addr, dump_buf, actual_dump_len);
                        if (dump_r > 0) {
                            config->match_count++;
                            
                            fprintf(config->out_file, "[MATCH #%ld] Address: 0x%lx | Region: %s (%s) | Offset: +0x%lx | Pattern: %s\n",
                                   config->match_count,
                                   match_addr,
                                   pathname[0] ? pathname : "anonymous",
                                   perms,
                                   match_addr - start,
                                   pat->name);
                            fprintf(config->out_file, "--- Recovered Data (%zu bytes) ---\n", (size_t)dump_r);
                            dump_recovered_data(config->out_file, dump_buf, dump_r, config->ascii_only);
                            fprintf(config->out_file, "----------------------------------\n\n");
                            
                            if (config->max_matches > 0 && config->match_count >= config->max_matches) {
                                free(dump_buf);
                                break;
                            }
                        }
                        free(dump_buf);
                    }
                }

                size_t consumed = (match - curr) + 1;
                curr += consumed;
                remaining -= consumed;
            }
        }

        if (overlap_len > 0) {
            if (valid_read >= overlap_len) {
                memcpy(prev_overlap, scan_buf + scan_size - overlap_len, overlap_len);
                has_prev = true;
            } else {
                has_prev = false;
            }
        }

        free(scan_buf);
        addr += to_read;
    }

    if (prev_overlap) free(prev_overlap);
}

void print_usage(const char *prog_name) {
    printf("memscan version 1.0.5\n");
    printf("Usage: %s -p <pid> [options]\n", prog_name);
    printf("Options:\n");
    printf("  -p <pid>      PID of the target process to scan (required). Use a number or 'self' to scan this process.\n");
    printf("  -m <magic>    Custom magic number or string pattern to look for.\n");
    printf("                Can be text or hex prefix starting with '0x' or containing '\\xHH' escapes.\n");
    printf("  -l <len>      Length of the text to dump after discovering the pattern (default: %d)\n", DEFAULT_DUMP_LEN);
    printf("  -x            Output in Hex+ASCII dump format (default is plain text ASCII)\n");
    printf("  -s            Scan for common file magic headers (PNG, PDF, ZIP, ELF, JPEG)\n");
    printf("  -w            Writable memory regions only (excludes read-only segments)\n");
    printf("  -i, -c        Case-insensitive string comparison for custom text searches\n");
    printf("  -r <rng>      Restrict scanning to address range (e.g. -r 0x7fff0000-0x7fff2000)\n");
    printf("  -n <count>    Limit results to the first <count> matches\n");
    printf("  -o <file>     Write scan output results to <file> instead of stdout\n");
    printf("  -v            Show program version version\n");
    printf("  -h            Show this help information\n");
}
