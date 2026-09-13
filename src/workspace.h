#ifndef RMP_WORKSPACE_H
#define RMP_WORKSPACE_H

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RMP_WORK_DIR_ENV "RMP_WORK_DIR"
#define RMP_LEGACY_WORK_DIR "/data/local/tmp"
#define RMP_SESSION_WORK_DIR_PREFIX "/data/local/tmp/"
#define RMP_SESSION_ID_LENGTH 32U
#define RMP_WORK_DIR_CONFIG "/apex/com.android.virt/bin/.rmp-work-dir"

static inline int rmp_is_valid_session_work_dir(const char *path) {
  const size_t prefix_len = strlen(RMP_SESSION_WORK_DIR_PREFIX);
  if (!path || strncmp(path, RMP_SESSION_WORK_DIR_PREFIX, prefix_len) != 0) {
    return 0;
  }

  const char *id = path + prefix_len;
  if (strlen(id) != RMP_SESSION_ID_LENGTH) {
    return 0;
  }
  for (size_t i = 0; i < RMP_SESSION_ID_LENGTH; i++) {
    if (!isdigit((unsigned char)id[i]) &&
        !(id[i] >= 'a' && id[i] <= 'f')) {
      return 0;
    }
  }
  return 1;
}

static inline int rmp_copy_valid_work_dir(char *out, size_t out_len,
                                          const char *value) {
  if (!out || out_len == 0 || !rmp_is_valid_session_work_dir(value)) {
    return 0;
  }
  int written = snprintf(out, out_len, "%s", value);
  return written > 0 && (size_t)written < out_len;
}

static inline int rmp_read_configured_work_dir(char *out, size_t out_len) {
  FILE *config = fopen(RMP_WORK_DIR_CONFIG, "re");
  if (!config) {
    return 0;
  }

  char value[128];
  char *read = fgets(value, sizeof(value), config);
  fclose(config);
  if (!read) {
    return 0;
  }
  value[strcspn(value, "\r\n")] = '\0';
  return rmp_copy_valid_work_dir(out, out_len, value);
}

static inline int rmp_resolve_work_dir(char *out, size_t out_len) {
  const char *environment = getenv(RMP_WORK_DIR_ENV);
  if (environment && environment[0]) {
    return rmp_copy_valid_work_dir(out, out_len, environment);
  }
  if (rmp_read_configured_work_dir(out, out_len)) {
    return 1;
  }

  int written = snprintf(out, out_len, "%s", RMP_LEGACY_WORK_DIR);
  return written > 0 && (size_t)written < out_len;
}

static inline int rmp_work_path(char *out, size_t out_len,
                                const char *leaf) {
  if (!leaf || !leaf[0] || strchr(leaf, '/')) {
    return 0;
  }

  char work_dir[128];
  if (!rmp_resolve_work_dir(work_dir, sizeof(work_dir))) {
    return 0;
  }
  int written = snprintf(out, out_len, "%s/%s", work_dir, leaf);
  return written > 0 && (size_t)written < out_len;
}

#endif
