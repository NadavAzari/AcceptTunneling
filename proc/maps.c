#include "proc/maps.h"

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>

/* Parses one line from /proc/pid/maps into its start address, file offset,
 * and pathname.  Returns 1 on success, 0 if the line could not be parsed.
 *
 * Uses uintptr_t + SCNxPTR so address fields are read correctly on both
 * 32-bit (4-byte uintptr_t) and 64-bit (8-byte uintptr_t) builds. */
static int maps_parse_line(const char  *line,
                            uintptr_t   *out_start,
                            uintptr_t   *out_offset,
                            char         out_path[PATH_MAX])
{
    uintptr_t start, end, offset;
    char      perms[8];
    out_path[0] = '\0';

    int r = sscanf(line,
                   "%" SCNxPTR "-%" SCNxPTR " %7s %" SCNxPTR " %*s %*s %s",
                   &start, &end, perms, &offset, out_path);
    if (r < 4)
        return 0;

    *out_start  = start;
    *out_offset = offset;
    return 1;
}

uint64_t proc_load_base(pid_t pid, const char *exe_path)
{
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

    FILE *fp = fopen(maps_path, "r");
    if (!fp)
        return 0;

    char     line[512];
    uint64_t base = 0;

    while (fgets(line, sizeof(line), fp)) {
        uintptr_t start, offset;
        char      pathname[PATH_MAX];

        if (!maps_parse_line(line, &start, &offset, pathname))
            continue;

        if (offset == 0 && strcmp(pathname, exe_path) == 0) {
            base = (uint64_t)start;
            break;
        }
    }
    fclose(fp);
    return base;
}
