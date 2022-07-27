/*
 * fuseMedia eBPF program
 *
 * Copyright (C) 2021 Google
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <bpf_helpers.h>

#include <stdint.h>

#define __KERNEL__
#include <fuse_kernel.h>

#define bpf_printk(fmt, ...)                                       \
    ({                                                             \
        char ____fmt[] = fmt;                                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })

DEFINE_BPF_PROG("fuse/media", AID_ROOT, AID_MEDIA_RW, fuse_media)
(struct fuse_bpf_args* fa) {
    switch (fa->opcode) {
        case FUSE_LOOKUP | FUSE_PREFILTER: {
            const char* name = fa->in_args[0].value;

            bpf_printk("LOOKUP: %lx %s", fa->nodeid, name);
            return FUSE_BPF_BACKING;
        }

        default:
            if (fa->opcode & FUSE_PREFILTER)
                bpf_printk("Prefilter *** UNKNOWN *** opcode: %d", fa->opcode & FUSE_OPCODE_FILTER);
            else if (fa->opcode & FUSE_POSTFILTER)
                bpf_printk("Postfilter *** UNKNOWN *** opcode: %d",
                           fa->opcode & FUSE_OPCODE_FILTER);
            else
                bpf_printk("*** UNKNOWN *** opcode: %d", fa->opcode);
            return FUSE_BPF_BACKING;
    }
}

LICENSE("GPL");
