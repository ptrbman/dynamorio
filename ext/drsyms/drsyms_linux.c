/* **********************************************************
 * Copyright (c) 2011-2012 Google, Inc.  All rights reserved.
 * **********************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * 
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 * 
 * * Neither the name of VMware, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL VMWARE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/* DRSyms DynamoRIO Extension */

/* Symbol lookup for Linux
 *
 * For symbol and address lookup and enumeration we use a combination of libelf
 * and libdwarf.  All symbol and address lookup is dealt with by parsing the
 * .symtab section, which points to symbols in the .strtab section.  To get line
 * number information, we have to go the extra mile and use libdwarf to dig
 * through the .debug_line section, which was added in DWARF2.  We don't support
 * STABS or any other form of line number debug information.
 *
 * FIXME i#545: Provide an API to demangle the symbol names returned by
 * drsym_lookup_address.
 */

#include "dr_api.h"
#include "drsyms.h"
#include "drsyms_private.h"
#include "hashtable.h"

/* Guards our internal state and libdwarf's modifications of mod->dbg. */
static void *symbol_lock;

/* Hashtable for mapping module paths to dbg_module_t*. */
#define MODTABLE_HASH_BITS 8
static hashtable_t modtable;

/* Sideline server support */
static int shmid;

#define IS_SIDELINE (shmid != 0)

/******************************************************************************
 * Linux lookup layer
 */

static void *
lookup_or_load(const char *modpath)
{
    void *mod = hashtable_lookup(&modtable, (void*)modpath);
    if (mod == NULL) {
        mod = drsym_unix_load(modpath);
        if (mod != NULL) {
            hashtable_add(&modtable, (void*)modpath, mod);
        }
    }
    return mod;
}

static drsym_error_t
drsym_enumerate_symbols_local(const char *modpath, drsym_enumerate_cb callback,
                              void *data, uint flags)
{
    void *mod;
    drsym_error_t r;

    if (modpath == NULL || callback == NULL)
        return DRSYM_ERROR_INVALID_PARAMETER;

    dr_mutex_lock(symbol_lock);
    mod = lookup_or_load(modpath);
    if (mod == NULL) {
        dr_mutex_unlock(symbol_lock);
        return DRSYM_ERROR_LOAD_FAILED;
    }

    r = drsym_unix_enumerate_symbols(mod, callback, data, flags);

    dr_mutex_unlock(symbol_lock);
    return r;
}

static drsym_error_t
drsym_lookup_symbol_local(const char *modpath, const char *symbol,
                          size_t *modoffs OUT, uint flags)
{
    void *mod;
    drsym_error_t r;

    if (modpath == NULL || symbol == NULL || modoffs == NULL)
        return DRSYM_ERROR_INVALID_PARAMETER;

    dr_mutex_lock(symbol_lock);
    mod = lookup_or_load(modpath);
    if (mod == NULL) {
        dr_mutex_unlock(symbol_lock);
        return DRSYM_ERROR_LOAD_FAILED;
    }

    r = drsym_unix_lookup_symbol(mod, symbol, modoffs, flags);

    dr_mutex_unlock(symbol_lock);
    return r;
}

static drsym_error_t
drsym_lookup_address_local(const char *modpath, size_t modoffs,
                           drsym_info_t *out INOUT, uint flags)
{
    void *mod;
    drsym_error_t r;

    if (modpath == NULL || out == NULL)
        return DRSYM_ERROR_INVALID_PARAMETER;
    /* If we add fields in the future we would dispatch on out->struct_size */
    if (out->struct_size != sizeof(*out))
        return DRSYM_ERROR_INVALID_SIZE;

    dr_mutex_lock(symbol_lock);
    mod = lookup_or_load(modpath);
    if (mod == NULL) {
        dr_mutex_unlock(symbol_lock);
        return DRSYM_ERROR_LOAD_FAILED;
    }

    r = drsym_unix_lookup_address(mod, modoffs, out, flags);

    dr_mutex_unlock(symbol_lock);
    return r;
}


/******************************************************************************
 * Exports.
 */

DR_EXPORT
drsym_error_t
drsym_init(int shmid_in)
{
    shmid = shmid_in;

    symbol_lock = dr_mutex_create();

    drsym_unix_init();

    if (IS_SIDELINE) {
        /* FIXME NYI i#446: establish connection with sideline server via shared
         * memory specified by shmid
         */
    } else {
        hashtable_init_ex(&modtable, MODTABLE_HASH_BITS, HASH_STRING,
                          true/*strdup*/, false/*!synch: using symbol_lock*/,
                          (generic_func_t)drsym_unix_unload, NULL, NULL);
    }
    return DRSYM_SUCCESS;
}

DR_EXPORT
drsym_error_t
drsym_exit(void)
{
    drsym_error_t res = DRSYM_SUCCESS;
    drsym_unix_exit();
    if (IS_SIDELINE) {
        /* FIXME NYI i#446 */
    }
    hashtable_delete(&modtable);
    dr_mutex_destroy(symbol_lock);
    return res;
}

DR_EXPORT
drsym_error_t
drsym_lookup_address(const char *modpath, size_t modoffs, drsym_info_t *out INOUT,
                     uint flags)
{
    if (IS_SIDELINE) {
        return DRSYM_ERROR_NOT_IMPLEMENTED;
    } else {
        return drsym_lookup_address_local(modpath, modoffs, out, flags);
    }
}

DR_EXPORT
drsym_error_t
drsym_lookup_symbol(const char *modpath, const char *symbol, size_t *modoffs OUT,
                    uint flags)
{
    if (IS_SIDELINE) {
        return DRSYM_ERROR_NOT_IMPLEMENTED;
    } else {
        return drsym_lookup_symbol_local(modpath, symbol, modoffs, flags);
    }
}

DR_EXPORT
drsym_error_t
drsym_enumerate_symbols(const char *modpath, drsym_enumerate_cb callback, void *data,
                        uint flags)
{
    if (IS_SIDELINE) {
        return DRSYM_ERROR_NOT_IMPLEMENTED;
    } else {
        return drsym_enumerate_symbols_local(modpath, callback, data, flags);
    }
}

DR_EXPORT
drsym_error_t
drsym_get_func_type(const char *modpath, size_t modoffs, char *buf,
                    size_t buf_sz, drsym_func_type_t **func_type OUT)
{
    return DRSYM_ERROR_NOT_IMPLEMENTED;
}

DR_EXPORT
size_t
drsym_demangle_symbol(char *dst OUT, size_t dst_sz, const char *mangled,
                      uint flags)
{
    return drsym_unix_demangle_symbol(dst, dst_sz, mangled, flags);
}

DR_EXPORT
drsym_error_t
drsym_get_module_debug_kind(const char *modpath, drsym_debug_kind_t *kind OUT)
{
    if (IS_SIDELINE) {
        return DRSYM_ERROR_NOT_IMPLEMENTED;
    } else {
        void *mod;
        drsym_error_t r;

        if (modpath == NULL || kind == NULL)
            return DRSYM_ERROR_INVALID_PARAMETER;

        dr_mutex_lock(symbol_lock);
        mod = lookup_or_load(modpath);
        r = drsym_unix_get_module_debug_kind(mod, kind);
        dr_mutex_unlock(symbol_lock);
        return r;
    }
}
