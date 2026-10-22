/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Embed the preinit runner. It is only needed until xfg_preinit_init() copies
 * it into shmem, so keep it in an init section that is freed after load.
 */
	.section .init.rodata, "a"
	.balign 16
	.global xfg_preinit_runner_start
xfg_preinit_runner_start:
	.incbin XFG_PREINIT_RUNNER_BIN
	.global xfg_preinit_runner_end
xfg_preinit_runner_end:
