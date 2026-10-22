/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * Minimal ARM64 bootstrap linked directly into a caller-provided kernel text
 * cave. All xfg_ext_* and xfg_* absolute symbols are supplied by the offline
 * injector. Relative branches/ADRP references remain valid after KASLR. The
 * appended capsule is read through the linear map, not through the kernel image
 * mapping, because it lives beyond the link-time _end.
 */

/*
 * capsule_phys = __pa_symbol(_text) + capsule_image_offset
 * capsule_virt = (capsule_phys - memstart_addr) | PAGE_OFFSET
 */
.macro xfg_capsule_virt dst, tmp
    adrp \dst, xfg_image_base
    add \dst, \dst, :lo12:xfg_image_base
    adrp \tmp, xfg_ext_kimage_voffset
    add \tmp, \tmp, :lo12:xfg_ext_kimage_voffset
    ldr \tmp, [\tmp]
    sub \dst, \dst, \tmp
    ldr \tmp, =xfg_capsule_image_offset
    add \dst, \dst, \tmp
    adrp \tmp, xfg_ext_memstart_addr
    add \tmp, \tmp, :lo12:xfg_ext_memstart_addr
    ldr \tmp, [\tmp]
    sub \dst, \dst, \tmp
    ldr \tmp, =xfg_page_offset
    orr \dst, \dst, \tmp
.endm

    .section .text.xfg_bootstrap, "ax"
    .balign 16
    .global xfg_bootstrap
    .type xfg_bootstrap, %function
xfg_bootstrap:
    /* BTI c, encoded as HINT on CPUs without BTI. */
    .inst 0xd503245f
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!

    /* Preserve the original kernel_init() call first. */
    bl xfg_ext_async_synchronize_full

    xfg_capsule_virt x23, x8

    /* Reject a missing/truncated/wrong capsule before touching its module. */
    ldr x8, [x23, #0]
    ldr x9, =xfg_capsule_magic
    cmp x8, x9
    b.ne .Lbootstrap_out
    ldr w8, [x23, #8]
    ldr w9, =xfg_capsule_version
    cmp w8, w9
    b.ne .Lbootstrap_out
    ldr w8, [x23, #12]
    ldr w9, =xfg_capsule_header_size
    cmp w8, w9
    b.ne .Lbootstrap_out
    ldr x8, [x23, #16]
    ldr x9, =xfg_capsule_size
    cmp x8, x9
    b.ne .Lbootstrap_out
    ldr x8, [x23, #24]
    ldr x9, =xfg_module_capsule_offset
    cmp x8, x9
    b.ne .Lbootstrap_out
    ldr x8, [x23, #32]
    ldr x9, =xfg_module_size
    cmp x8, x9
    b.ne .Lbootstrap_out
    ldr x8, [x23, #40]
    ldr x9, =xfg_fixup_capsule_offset
    cmp x8, x9
    b.ne .Lbootstrap_out
    ldr x8, [x23, #48]
    ldr x9, =xfg_fixup_count
    cmp x8, x9
    b.ne .Lbootstrap_out
    ldr x8, [x23, #96]
    ldr x9, =xfg_args_capsule_offset
    cmp x8, x9
    b.ne .Lbootstrap_out
    ldr x8, [x23, #104]
    ldr x9, =xfg_args_size
    cmp x8, x9
    b.ne .Lbootstrap_out

    /* load_module() owns and vfree()s this temporary copy. */
    ldr x0, =xfg_module_size
    bl xfg_ext_vmalloc
    cbz x0, .Lbootstrap_out
    // x19: vmalloc-ed xfg module
    mov x19, x0

    ldr x8, =xfg_module_capsule_offset
    add x1, x23, x8
    ldr x2, =xfg_module_size
    bl xfg_ext_memcpy

    /* Apply compact { Elf64_Sym file offset, kernel image offset } fixups. */
    ldr x8, =xfg_fixup_capsule_offset
    add x20, x23, x8
    ldr x21, =xfg_fixup_count
    adrp x22, xfg_image_base
    add x22, x22, :lo12:xfg_image_base
    cbz x21, .Lfixups_done
.Lfixup_loop:
    ldr w8, [x20]
    ldr x9, [x20, #8]
    add x10, x19, x8
    mov w11, #0xfff1              /* SHN_ABS */
    strh w11, [x10, #6]           /* Elf64_Sym.st_shndx */
    add x9, x22, x9
    str x9, [x10, #8]             /* Elf64_Sym.st_value */
    add x20, x20, #16
    subs x21, x21, #1
    b.ne .Lfixup_loop
.Lfixups_done:

    /* Oversized, zeroed target_load_info storage; only hdr/len are seeded. */
    ldr x20, =xfg_load_info_size
    sub sp, sp, x20
    mov x21, sp
    mov x8, x20
.Lzero_load_info:
    stp xzr, xzr, [x21], #16
    subs x8, x8, #16
    b.ne .Lzero_load_info

    ldr x9, =xfg_load_info_hdr_offset
    str x19, [sp, x9]
    ldr x8, =xfg_module_size
    ldr x9, =xfg_load_info_len_offset
    str x8, [sp, x9]
    mov x0, sp
    /* NUL-terminated module params, see xfg_strndup_user_adapter */
    ldr x8, =xfg_args_capsule_offset
    add x1, x23, x8
    mov x2, xzr
    bl xfg_ext_load_module
    add sp, sp, x20
    b .Lbootstrap_out

.Lbootstrap_out:
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    ldp x29, x30, [sp], #16
    ret
    .size xfg_bootstrap, . - xfg_bootstrap

/*
 * This replaces the arm64_memblock_init() call that reserves
 * [kernel_start, _end). x0 remains the physical kernel start; extending x1
 * makes the same reservation cover the appended capsule, then the original
 * memblock_reserve() returns directly to arm64_memblock_init().
 */
    .balign 16
    .global xfg_memblock_reserve_wrapper
    .type xfg_memblock_reserve_wrapper, %function
xfg_memblock_reserve_wrapper:
    .inst 0xd503245f              /* BTI c */
    ldr x8, =xfg_reserve_extension
    add x1, x1, x8
    b xfg_ext_memblock_reserve
    .size xfg_memblock_reserve_wrapper, . - xfg_memblock_reserve_wrapper

/*
 * load_module() calls strndup_user(uargs, ...). The pre-exec PID 1 has no
 * usable userspace mapping, so the injector redirects that one call here.
 * Only the exact capsule params address is duplicated from kernel memory;
 * normal future module loads (always user pointers) tail-call the original
 * target unchanged.
 */
    .balign 16
    .global xfg_strndup_user_adapter
    .type xfg_strndup_user_adapter, %function
xfg_strndup_user_adapter:
    .inst 0xd503245f              /* BTI c */
    xfg_capsule_virt x9, x10
    ldr x10, =xfg_args_capsule_offset
    add x9, x9, x10
    cmp x0, x9
    b.eq .Lduplicate_kernel_args
    b xfg_ext_strndup_user
.Lduplicate_kernel_args:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    ldr w1, =xfg_gfp_kernel
    bl xfg_ext_kstrdup
    cbnz x0, .Lduplicate_kernel_args_done
    mov x0, #-12                   /* ERR_PTR(-ENOMEM) */
.Lduplicate_kernel_args_done:
    ldp x29, x30, [sp], #16
    ret
    .size xfg_strndup_user_adapter, . - xfg_strndup_user_adapter

    .ltorg
