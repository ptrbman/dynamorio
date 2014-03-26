/* **********************************************************
 * Copyright (c) 2011-2014 Google, Inc.  All rights reserved.
 * Copyright (c) 2008-2010 VMware, Inc.  All rights reserved.
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

/* compile with make VMAP=1 for a vmap version (makefile defaults to VMSAFE version) */

#include "configure.h"

#ifdef WINDOWS
# define WIN32_LEAN_AND_MEAN
# include <windows.h>
# include <io.h>
# include "config.h"
# include "share.h"
#endif

#ifdef UNIX
# include <errno.h>
# include <fcntl.h>
# include <unistd.h>
# include <sys/stat.h>
# include <sys/mman.h>
# include <sys/wait.h>
#endif

#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <assert.h>
#include "globals_shared.h"
#include "dr_config.h" /* MUST be before share.h (it sets HOT_PATCHING_INTERFACE) */
#include "dr_inject.h"

typedef enum _action_t {
    action_none,
    action_nudge,
    action_register,
    action_unregister,
    action_list,
} action_t;

static bool verbose;
static bool quiet;
static bool DR_dll_not_needed =
#ifdef STATIC_LIBRARY
    true
#else
    false
#endif
    ;
static bool nocheck;

#define die() exit(1)

/* up to caller to call die() if necessary */
#define error(msg, ...) do { \
    fprintf(stderr, "ERROR: " msg "\n", ##__VA_ARGS__);    \
    fflush(stderr); \
} while (0)

#define warn(msg, ...) do { \
    if (!quiet) { \
        fprintf(stderr, "WARNING: " msg "\n", ##__VA_ARGS__); \
        fflush(stderr); \
    } \
} while (0)

#define info(msg, ...) do { \
    if (verbose) { \
        fprintf(stderr, "INFO: " msg "\n", ##__VA_ARGS__); \
        fflush(stderr); \
    } \
} while (0)

#ifdef DRCONFIG
# define TOOLNAME "drconfig"
#elif defined(DRRUN)
# define TOOLNAME "drrun"
#elif defined(DRINJECT)
# define TOOLNAME "drinject"
#endif

const char *usage_str =
#ifdef DRCONFIG
    "usage: "TOOLNAME" [options]\n"
#elif defined(DRRUN) || defined (DRINJECT)
    "usage: "TOOLNAME" [options] <app and args to run>\n"
    "usage: "TOOLNAME" [options] -- <app and args to run>\n"
# if defined(DRRUN)
    "   or: "TOOLNAME" [options] [DR options] -- <app and args to run>\n"
    "   or: "TOOLNAME" [options] [DR options] -c <client> [client options]"
    " -- <app and args to run>\n"
    "   or: "TOOLNAME" [options] [DR options] -t <tool> [tool options]"
    " -- <app and args to run>\n"
# endif
    "\n"
#endif
    "       -v                 Display version information\n"
    "       -verbose           Display additional information\n"
    "       -quiet             Do not display warnings\n"
    "       -nocheck           Do not fail due to invalid DynamoRIO installation or app\n"
#ifdef DRCONFIG
    "       -reg <process>     Register <process> to run under DR\n"
    "       -unreg <process>   Unregister <process> from running under DR\n"
    "       -isreg <process>   Display whether <process> is registered and if so its\n"
    "                          configuration\n"
    "       -list_registered   Display all registered processes and their configuration\n"
#endif
    "       -root <root>       DR root directory\n"
#if defined(DRCONFIG) || defined(DRRUN)
# if defined(MF_API) && defined(PROBE_API)
    "       -mode <mode>       DR mode (code, probe, or security)\n"
# elif defined(PROBE_API)
    "       -mode <mode>       DR mode (code or probe)\n"
# elif defined(MF_API)
    "       -mode <mode>       DR mode (code or security)\n"
# else
    /* No mode argument, is always code. */
# endif
#endif
#ifdef DRCONFIG
    /* FIXME i#840: Syswide NYI on Linux. */
# ifdef WINDOWS
    "       -syswide_on        Set up systemwide injection so that registered\n"
    "                          applications will run under DR however they are\n"
    "                          launched.  Otherwise, drinject must be used to\n"
    "                          launch a target configured application under DR.\n"
    "                          This option requires administrative privileges.\n"
    "       -syswide_off       Disable systemwide injection.\n"
    "                          This option requires administrative privileges.\n"
# endif
    "       -global            Use global configuration files instead of local\n"
    "                          user-private configuration files.  The global\n"
    "                          config dir must be set up ahead of time.\n"
    "                          This option may require administrative privileges.\n"
    "                          If a local file already exists it will take precedence.\n"
    "       -norun             Create a configuration that excludes the application\n"
    "                          from running under DR control.  Useful for following\n"
    "                          all child processes except a handful (blacklist).\n"
#endif
    "       -debug             Use the DR debug library\n"
    "       -32                Target 32-bit or WOW64 applications\n"
    "       -64                Target 64-bit (non-WOW64) applications\n"
#if defined(DRCONFIG) || defined(DRRUN)
    "\n"
    "       -ops \"<options>\"   Additional DR control options.  When specifying\n"
    "                          multiple options, enclose the entire list of\n"
    "                          options in quotes, or repeat the -ops.\n"
    "                          Alternatively, if the application is separated\n"
    "                          by \"--\", the -ops may be omitted and DR options\n"
    "                          specified prior to \"--\" without quotes.\n"
    "\n"
    "        -c <path> <options>*\n"
    "                           Registers one client to run alongside DR.  Assigns\n"
    "                           the client an id of 0.  All remaining arguments\n"
    "                           until the -- arg before the app are interpreted as\n"
    "                           client options.  Must come after all drrun and DR\n"
    "                           ops.  Incompatible with -client.  Requires using --\n"
    "                           to separate the app executable.\n"
    "\n"
    "       -client <path> <ID> \"<options>\"\n"
    "                          Use -c instead, unless you need to set the client ID.\n"
    "                          Registers one or more clients to run alongside DR.\n"
    "                          This option is only valid when registering a\n"
    "                          process.  The -client option takes three arguments:\n"
    "                          the full path to a client library, a unique 8-digit\n"
    "                          hex ID, and an optional list of client options\n"
    "                          (use \"\" to specify no options).  Multiple clients\n"
    "                          can be installed via multiple -client options.  In\n"
    "                          this case, clients specified first on the command\n"
    "                          line have higher priority.  Neither the path nor\n"
    "                          the options may contain semicolon characters.\n"
    "                          This option must precede any options to DynamoRIO.\n"
#endif
#ifdef DRCONFIG
    "\n"
    "       Note that nudging 64-bit processes is not yet supported.\n"
    "       -nudge <process> <client ID> <argument>\n"
    "                          Nudge the client with ID <client ID> in all running\n"
    "                          processes with name <process>, and pass <argument>\n"
    "                          to the nudge callback.  <client ID> must be the\n"
    "                          8-digit hex ID of the target client.  <argument>\n"
    "                          should be a hex literal (0, 1, 3f etc.).\n"
    "       -nudge_pid <process_id> <client ID> <argument>\n"
    "                          Nudge the client with ID <client ID> in the process with\n"
    "                          id <process_id>, and pass <argument> to the nudge\n"
    "                          callback.  <client ID> must be the 8-digit hex ID\n"
    "                          of the target client.  <argument> should be a hex\n"
    "                          literal (0, 1, 3f etc.).\n"
    "       -nudge_all <client ID> <argument>\n"
    "                          Nudge the client with ID <client ID> in all running\n"
    "                          processes and pass <argument> to the nudge callback.\n"
    "                          <client ID> must be the 8-digit hex ID of the target\n"
    "                          client.  <argument> should be a hex literal\n"
    "                          (0, 1, 3f etc.)\n"
    "       -nudge_timeout <ms> Max time (in milliseconds) to wait for a nudge to\n"
    "                          finish before continuing.  The default is an infinite\n"
    "                          wait.  A value of 0 means don't wait for nudges to\n"
    "                          complete."
#else
    "       -no_wait           Return immediately: do not wait for application exit.\n"
    "       -s <seconds>       Kill the application if it runs longer than the\n"
    "                          specified number of seconds.\n"
    "       -m <minutes>       Kill the application if it runs longer than the\n"
    "                          specified number of minutes.\n"
    "       -h <hours>         Kill the application if it runs longer than the\n"
    "                          specified number of hours.\n"
# ifdef UNIX
    "       -killpg            Create a new process group for the app.  If the app\n"
    "                          times out, kill the entire process group.  This forces\n"
    "                          the child to be a new process with a new pid, rather\n"
    "                          than reusing the parent's pid.\n"
# endif
    "       -stats             Print /usr/bin/time-style elapsed time and memory used.\n"
    "       -mem               Print memory usage statistics.\n"
    "       -pidfile <file>    Print the pid of the child process to the given file.\n"
    "       -no_inject         Run the application natively.\n"
# ifdef UNIX  /* FIXME i#725: Windows attach NYI */
    "       -early             Whether to use early injection.\n"
    "       -attach <pid>      Attach to the process with the given pid.  Pass 0\n"
    "                          for pid to launch and inject into a new process.\n"
    "       -logdir <dir>      Logfiles will be stored in this directory.\n"
# endif
    "       -use_dll <dll>     Inject given dll instead of configured DR dll.\n"
    "       -force             Inject regardless of configuration.\n"
    "       -exit0             Return a 0 exit code instead of the app's exit code.\n"
    "\n"
    "       <app and args>     Application command line to execute under DR.\n"
#endif
    ;

#define usage(msg, ...) do {                                    \
    fprintf(stderr, "\n");                                      \
    fprintf(stderr, "ERROR: " msg "\n\n", ##__VA_ARGS__);       \
    fprintf(stderr, "%s\n", usage_str);                         \
    die();                                                      \
} while (0)

#ifdef UNIX
/* Minimal Windows compatibility layer.
 */

# define _snprintf snprintf

/* Semi-compatibility with the Windows CRT _access function.
 */
static int
_access(const char *fname, int mode)
{
    int r;
    struct stat st;
    if (mode != 0) {
        error("_access called with non-zero mode");
        die();
    }
    r = stat(fname, &st);
    return (r == 0 ? 0 : -1);
}

# ifndef DRCONFIG
/* Implements a normal path search for fname on the paths in env_var.  Assumes
 * full_path is at least MAXIMUM_PATH bytes long.  Resolves symlinks, which is
 * needed to get the right config filename (i#1062).
 */
static int
_searchenv(const char *fname, const char *env_var, char *full_path)
{
    const char *paths = getenv(env_var);
    const char *cur;
    const char *next;
    const char *end;
    char tmp[MAXIMUM_PATH];

    /* Windows searches the current directory first. */
    /* XXX: realpath resolves symlinks, which we may not want. */
    if (realpath(fname, full_path) && _access(full_path, 0) == 0)
        return 0;

    cur = paths;
    end = strchr(paths, '\0');
    while (cur < end) {
        next = strchr(cur, ':');
        next = (next == NULL ? end : next);
        snprintf(tmp, BUFFER_SIZE_ELEMENTS(tmp),
                 "%.*s/%s", (int)(next - cur), cur, fname);
        NULL_TERMINATE_BUFFER(tmp);
        /* realpath checks for existence too. */
        if (realpath(tmp, full_path) != NULL && _access(full_path, 0) == 0)
            return 0;
        cur = next + 1;
    }
    full_path[0] = '\0';
    return -1;
}

static int
GetLastError(void)
{
    return errno;
}
# endif

/* Simply concatenates the cwd with the given relative path.  Previously we
 * called realpath, but this requires the path to exist and expands symlinks,
 * which is inconsistent with Windows GetFullPathName().
 */
static void
GetFullPathName(const char *rel, size_t abs_len, char *abs, char **ext)
{
    size_t len = 0;
    assert(ext == NULL && "invalid param");
    if (rel[0] != '/') {
        char *err = getcwd(abs, abs_len);
        if (err != NULL) {
            len = strlen(abs);
            /* Append a slash if it doesn't have a trailing slash. */
            if (abs[len-1] != '/' && len < abs_len) {
                abs[len++] = '/';
                abs[len] = '\0';
            }
            /* Omit any leading ./. */
            if (rel[0] == '.' && rel[0] == '/') {
                rel += 2;
            }
        }
    }
    strncpy(abs + len, rel, abs_len - len);
    abs[abs_len-1] = '\0';
}

#endif /* UNIX */

/* Unregister a process */
bool unregister_proc(const char *process, process_id_t pid,
                     bool global, dr_platform_t dr_platform)
{
    dr_config_status_t status = dr_unregister_process(process, pid, global, dr_platform);
    if (status == DR_PROC_REG_INVALID) {
        error("no existing registration");
        return false;
    }
    else if (status == DR_FAILURE) {
        error("unregistration failed");
        return false;
    }
    return true;
}


/* Check if the provided root directory actually has the files we
 * expect.  Returns whether a fatal problem.
 */
static bool check_dr_root(const char *dr_root, bool debug,
                          dr_platform_t dr_platform, bool preinject)
{
    int i;
    char buf[MAXIMUM_PATH];
    bool ok = true;
    bool nowarn = false;

    const char *checked_files[] = {
#ifdef WINDOWS
        "lib32\\drpreinject.dll",
        "lib32\\release\\dynamorio.dll",
        "lib32\\debug\\dynamorio.dll",
        "lib64\\drpreinject.dll",
        "lib64\\release\\dynamorio.dll",
        "lib64\\debug\\dynamorio.dll"
#elif defined(MACOS)
        "lib32/debug/libdrpreload.dylib",
        "lib32/debug/libdynamorio.dylib",
        "lib32/release/libdrpreload.dylib",
        "lib32/release/libdynamorio.dylib",
        "lib64/debug/libdrpreload.dylib",
        "lib64/debug/libdynamorio.dylib",
        "lib64/release/libdrpreload.dylib",
        "lib64/release/libdynamorio.dylib"
#else /* LINUX */
        "lib32/debug/libdrpreload.so",
        "lib32/debug/libdynamorio.so",
        "lib32/release/libdrpreload.so",
        "lib32/release/libdynamorio.so",
        "lib64/debug/libdrpreload.so",
        "lib64/debug/libdynamorio.so",
        "lib64/release/libdrpreload.so",
        "lib64/release/libdynamorio.so"
#endif
    };

    const char *arch = IF_X64_ELSE("lib64", "lib32");
    if (dr_platform == DR_PLATFORM_32BIT)
        arch = "lib32";
    else if (dr_platform == DR_PLATFORM_64BIT)
        arch = "lib64";

    if (DR_dll_not_needed) {
        /* assume user knows what he's doing */
        return true;
    }

    /* don't warn if running from a build dir (i#458) which we attempt to detect
     * by looking for CMakeCache.txt in the root dir
     * (warnings can also be suppressed via -quiet)
     */
    _snprintf(buf, BUFFER_SIZE_ELEMENTS(buf), "%s/%s", dr_root, "CMakeCache.txt");
    if (_access(buf, 0) == 0)
        nowarn = true;

    for (i=0; i<BUFFER_SIZE_ELEMENTS(checked_files); i++) {
        _snprintf(buf, BUFFER_SIZE_ELEMENTS(buf), "%s/%s", dr_root, checked_files[i]);
        if (_access(buf, 0) == -1) {
            ok = false;
            if (!nocheck &&
                ((preinject && strstr(checked_files[i], "drpreinject")) ||
                 (!preinject && debug && strstr(checked_files[i], "debug") != NULL) ||
                 (!preinject && !debug && strstr(checked_files[i], "release") != NULL)) &&
                strstr(checked_files[i], arch) != NULL) {
                /* We don't want to create a .1config file that won't be freed
                 * b/c the core is never injected
                 */
                error("cannot find required file %s\n"
                      "Use -root to specify a proper DynamoRIO root directory.", buf);
                return false;
            } else if (!nowarn) {
                warn("cannot find %s: is this an incomplete installation?", buf);
            }
        }
    }
    if (!ok && !nowarn)
        warn("%s does not appear to be a valid DynamoRIO root", dr_root);
    return true;
}

/* Register a process to run under DR */
bool register_proc(const char *process,
                   process_id_t pid,
                   bool global,
                   const char *dr_root,
                   const dr_operation_mode_t dr_mode,
                   bool debug,
                   dr_platform_t dr_platform,
                   const char *extra_ops)
{
    dr_config_status_t status;

    assert(dr_root != NULL);
    if (_access(dr_root, 0) == -1) {
        error("cannot access DynamoRIO root directory %s", dr_root);
        return false;
    }
#ifdef CLIENT_INTERFACE
    if (dr_mode == DR_MODE_NONE) {
        error("you must provide a DynamoRIO mode");
        return false;
    }
#endif

    /* warn if the DR root directory doesn't look right, unless -norun,
     * in which case don't bother
     */
    if (dr_mode != DR_MODE_DO_NOT_RUN &&
        !check_dr_root(dr_root, debug, dr_platform, false))
        return false;

    if (dr_process_is_registered(process, pid, global, dr_platform,
                                 NULL, NULL, NULL, NULL)) {
        warn("overriding existing registration");
        if (!unregister_proc(process, pid, global, dr_platform))
            return false;
    }

    status = dr_register_process(process, pid, global, dr_root, dr_mode,
                                 debug, dr_platform, extra_ops);

    if (status != DR_SUCCESS) {
        /* USERPROFILE is not set by default over cygwin ssh */
#ifdef WINDOWS
        char buf[MAXIMUM_PATH];
        if (GetEnvironmentVariableA("USERPROFILE", buf,
                                    BUFFER_SIZE_ELEMENTS(buf)) == 0 &&
            GetEnvironmentVariableA("DYNAMORIO_CONFIGDIR", buf,
                                    BUFFER_SIZE_ELEMENTS(buf)) == 0) {
            error("process registration failed: neither USERPROFILE nor DYNAMORIO_CONFIGDIR env var set!");
        } else
#endif
            error("process registration failed");
        return false;
    }
    return true;
}


/* Check if the specified client library actually exists. */
void check_client_lib(const char *client_lib)
{
    if (_access(client_lib, 0) == -1) {
        warn("%s does not exist", client_lib);
    }
}


bool register_client(const char *process_name,
                     process_id_t pid,
                     bool global,
                     dr_platform_t dr_platform,
                     client_id_t client_id,
                     const char *path,
                     const char *options)
{
    size_t priority;
    dr_config_status_t status;

    if (!dr_process_is_registered(process_name, pid, global, dr_platform,
                                  NULL, NULL, NULL, NULL)) {
        error("can't register client: process is not registered");
        return false;
    }

    check_client_lib(path);

    /* just append to the existing client list */
    priority = dr_num_registered_clients(process_name, pid, global, dr_platform);

    status = dr_register_client(process_name, pid, global, dr_platform, client_id,
                                priority, path, options);

    if (status != DR_SUCCESS) {
        if (status == DR_CONFIG_STRING_TOO_LONG)
            error("client registration failed: option string too long");
        else
            error("client registration failed with error code %d", status);
        return false;
    }
    return true;
}

/* FIXME i#840: Port registered process iterator. */
#ifdef WINDOWS
static const char *
platform_name(dr_platform_t platform)
{
    return (platform == DR_PLATFORM_64BIT
            IF_X64(|| platform == DR_PLATFORM_DEFAULT)) ?
        "64-bit" : "32-bit/WOW64";
}

static void
list_process(char *name, bool global, dr_platform_t platform,
             dr_registered_process_iterator_t *iter)
{
    char name_buf[MAXIMUM_PATH] = {0};
    char root_dir_buf[MAXIMUM_PATH] = {0};
    dr_operation_mode_t dr_mode;
    bool debug;
    char dr_options[DR_MAX_OPTIONS_LENGTH] = {0};
    dr_client_iterator_t *c_iter;

    if (name == NULL) {
        dr_registered_process_iterator_next(iter, name_buf, root_dir_buf, &dr_mode,
                                            &debug, dr_options);
        name = name_buf;
    } else if (!dr_process_is_registered(name, 0, global, platform, root_dir_buf,
                                         &dr_mode, &debug, dr_options)) {
        printf("Process %s not registered for %s\n", name, platform_name(platform));
        return;
    }

    if (dr_mode == DR_MODE_DO_NOT_RUN) {
        printf("Process %s registered to NOT RUN on %s\n", name, platform_name(platform));
    } else {
        printf("Process %s registered for %s\n", name, platform_name(platform));
    }
    printf("\tRoot=\"%s\" Debug=%s\n\tOptions=\"%s\"\n",
           root_dir_buf, debug ? "yes" : "no", dr_options);

    c_iter = dr_client_iterator_start(name, 0, global, platform);
    while (dr_client_iterator_hasnext(c_iter)) {
        client_id_t id;
        size_t client_pri;
        char client_path[MAXIMUM_PATH] = {0};
        char client_opts[DR_MAX_OPTIONS_LENGTH] = {0};

        dr_client_iterator_next(c_iter, &id, &client_pri, client_path, client_opts);

        printf("\tClient=0x%08x Priority=%d\n\t\tPath=\"%s\"\n\t\tOptions=\"%s\"\n",
               id, (uint)client_pri, client_path, client_opts);
    }
    dr_client_iterator_stop(c_iter);
}
#endif /* WINDOWS */

#ifndef DRCONFIG
/* i#200/PR 459481: communicate child pid via file */
static void
write_pid_to_file(const char *pidfile, process_id_t pid)
{
    FILE *f = fopen(pidfile, "w");
    if (f == NULL) {
        warn("cannot open %s: %d\n", pidfile, GetLastError());
    } else {
        char pidbuf[16];
        ssize_t written;
        _snprintf(pidbuf, BUFFER_SIZE_ELEMENTS(pidbuf), "%d\n", pid);
        NULL_TERMINATE_BUFFER(pidbuf);
        written = fwrite(pidbuf, 1, strlen(pidbuf), f);
        assert(written == strlen(pidbuf));
        fclose(f);
    }
}
#endif /* DRCONFIG */

#if defined(DRCONFIG) || defined(DRRUN)
static void
append_client(const char *client, int id, const char *client_ops,
              char client_paths[MAX_CLIENT_LIBS][MAXIMUM_PATH],
              client_id_t client_ids[MAX_CLIENT_LIBS],
              const char *client_options[MAX_CLIENT_LIBS],
              size_t *num_clients)
{
    GetFullPathName(client, BUFFER_SIZE_ELEMENTS(client_paths[*num_clients]),
                    client_paths[*num_clients], NULL);
    NULL_TERMINATE_BUFFER(client_paths[*num_clients]);
    info("client %d path: %s", (int)*num_clients, client_paths[*num_clients]);
    client_ids[*num_clients] = id;
    client_options[*num_clients] = client_ops;
    (*num_clients)++;
}
#endif

/* Appends a space-separated option string to buf.  A space is appended only if
 * the buffer is non-empty.  Aborts on buffer overflow.  Always null terminates
 * the string.
 * XXX: Use print_to_buffer.
 */
static void
add_extra_option(char *buf, size_t bufsz, size_t *sofar, const char *fmt, ...)
{
    ssize_t len;
    va_list ap;
    if (*sofar > 0 && *sofar < bufsz)
        buf[(*sofar)++] = ' ';  /* Add a space. */

    va_start(ap, fmt);
    len = vsnprintf(buf + *sofar, bufsz - *sofar, fmt, ap);
    va_end(ap);

    if (len < 0 || (size_t)len >= bufsz) {
        error("option string too long, buffer overflow");
        die();
    }
    *sofar += len;
    /* be paranoid: though usually many calls in a row and could delay until end */
    buf[bufsz-1] = '\0';
}

#if defined(DRCONFIG) || defined(DRRUN)
/* Returns the path to the client library.  Appends to extra_ops.
 * A tool config file must contain one of these line types:
 *   CLIENT_ABS=<absolute path to client>
 *   CLIENT_REL=<path to client relative to DR root>
 * It can contain as many DR_OP= lines as desired.  Each must contain
 * one DynamoRIO option token:
 *   DR_OP=<DR option token>
 * It can also contain TOOL_OP= lines for tool options, though normally
 * tool default options should just be set in the tool:
 *   TOOL_OP=<tool option token>
 * We take one token per line rather than a string of options to avoid
 * having to do any string parsing.
 * DR ops go last (thus, user can't override); tool ops go first.
 */
static bool
read_tool_file(const char *toolname, const char *dr_root, dr_platform_t dr_platform,
               char *client, size_t client_size,
               char *ops, size_t ops_size, size_t *ops_sofar,
               char *tool_ops, size_t tool_ops_size, size_t *tool_ops_sofar)
{
    FILE *f;
    char config_file[MAXIMUM_PATH];
    char line[MAXIMUM_PATH];
    bool found_client = false;
    const char *arch = IF_X64_ELSE("64", "32");
    if (dr_platform == DR_PLATFORM_32BIT)
        arch = "32";
    else if (dr_platform == DR_PLATFORM_64BIT)
        arch = "64";
    _snprintf(config_file, BUFFER_SIZE_ELEMENTS(config_file),
              "%s/tools/%s.drrun%s", dr_root, toolname, arch);
    NULL_TERMINATE_BUFFER(config_file);
    info("reading tool config file %s", config_file);
    /* XXX i#943: we need to use _tfopen() on windows */
    f = fopen(config_file, "r");
    if (f == NULL) {
        error("Cannot find tool config file %s\n", config_file);
        return false;
    }
    while (fgets(line, BUFFER_SIZE_ELEMENTS(line), f) != NULL) {
        ssize_t len;
        NULL_TERMINATE_BUFFER(line);
        len = strlen(line) - 1;
        while (len >= 0 && (line[len] == '\n' || line[len] == '\r')) {
            line[len] = '\0';
            len--;
        }
        if (line[0] == '#') {
            continue;
        } else if (strstr(line, "CLIENT_REL=") == line) {
            _snprintf(client, client_size, "%s/%s", dr_root,
                      line + strlen("CLIENT_REL="));
            client[client_size-1] = '\0';
            found_client = true;
        } else if (strstr(line, "CLIENT_ABS=") == line) {
            strncpy(client, line + strlen("CLIENT_ABS="), client_size);
            found_client = true;
        } else if (strstr(line, "DR_OP=") == line) {
            add_extra_option(ops, ops_size, ops_sofar, "%s", line + strlen("DR_OP="));
        } else if (strstr(line, "TOOL_OP=") == line) {
            add_extra_option(tool_ops, tool_ops_size, tool_ops_sofar,
                             "%s", line + strlen("TOOL_OP="));
        } else if (line[0] != '\0') {
            error("Tool config file is malformed: unknown line %s\n", line);
            return false;
        }
    }
    fclose(f);
    return found_client;
}
#endif

int main(int argc, char *argv[])
{
    char *dr_root = NULL;
    char client_paths[MAX_CLIENT_LIBS][MAXIMUM_PATH];
#if defined(DRCONFIG) || defined(DRRUN)
    char *process = NULL;
    const char *client_options[MAX_CLIENT_LIBS] = {NULL,};
    client_id_t client_ids[MAX_CLIENT_LIBS] = {0,};
    size_t num_clients = 0;
    char single_client_ops[DR_MAX_OPTIONS_LENGTH];
#endif
#ifndef DRINJECT
# if defined(MF_API) || defined(PROBE_API)
    /* must set -mode */
    dr_operation_mode_t dr_mode = DR_MODE_NONE;
# else
    /* only one choice so no -mode */
#  ifdef CLIENT_INTERFACE
    dr_operation_mode_t dr_mode = DR_MODE_CODE_MANIPULATION;
#  else
    dr_operation_mode_t dr_mode = DR_MODE_NONE;
#  endif
# endif
#endif /* !DRINJECT */
    char extra_ops[MAX_OPTIONS_STRING];
    size_t extra_ops_sofar = 0;
#ifdef DRCONFIG
    action_t action = action_none;
#endif
    bool use_debug = false;
    dr_platform_t dr_platform = DR_PLATFORM_DEFAULT;
#ifdef WINDOWS
    /* FIXME i#840: Implement nudges on Linux. */
    bool nudge_all = false;
    process_id_t nudge_pid = 0;
    client_id_t nudge_id = 0;
    uint64 nudge_arg = 0;
    bool list_registered = false;
    uint nudge_timeout = INFINITE;
    bool syswide_on = false;
    bool syswide_off = false;
#endif /* WINDOWS */
    bool global = false;
#if defined(DRRUN) || defined(DRINJECT)
    char *pidfile = NULL;
    bool showstats = false;
    bool showmem = false;
    bool force_injection = false;
    bool inject = true;
    int limit = 0; /* in seconds */
    char *drlib_path = NULL;
    int exitcode;
# ifdef WINDOWS
    time_t start_time, end_time;
# else
    bool use_ptrace = false;
    bool kill_group = false;
# endif
    char *app_name;
    char full_app_name[MAXIMUM_PATH];
    const char **app_argv;
    char custom_dll[MAXIMUM_PATH];
    int errcode;
    void *inject_data;
    bool success;
    bool exit0 = false;
#endif
    int i;
#ifndef DRINJECT
    size_t j;
#endif
    char buf[MAXIMUM_PATH];
    char default_root[MAXIMUM_PATH];
    char *c;

    memset(client_paths, 0, sizeof(client_paths));
    extra_ops[0] = '\0';

    /* default root: we assume this tool is in <root>/bin{32,64}/dr*.exe */
    GetFullPathName(argv[0], BUFFER_SIZE_ELEMENTS(buf), buf, NULL);
    NULL_TERMINATE_BUFFER(buf);
    c = buf + strlen(buf) - 1;
    while (*c != '\\' && *c != '/' && c > buf)
        c--;
    _snprintf(c+1, BUFFER_SIZE_ELEMENTS(buf) - (c+1-buf), "..");
    NULL_TERMINATE_BUFFER(buf);
    GetFullPathName(buf, BUFFER_SIZE_ELEMENTS(default_root), default_root, NULL);
    NULL_TERMINATE_BUFFER(default_root);
    dr_root = default_root;
    info("default root: %s", default_root);

    /* parse command line */
    for (i=1; i<argc; i++) {

        /* params with no arg */
        if (strcmp(argv[i], "-verbose") == 0 ||
            strcmp(argv[i], "-v") == 0) {
            verbose = true;
            continue;
        }
        else if (strcmp(argv[i], "-quiet") == 0) {
            quiet = true;
            continue;
        }
        else if (strcmp(argv[i], "-nocheck") == 0) {
            nocheck = true;
            continue;
        }
        else if (strcmp(argv[i], "-debug") == 0) {
            use_debug = true;
            continue;
        }
        else if (!strcmp(argv[i], "-version")) {
#if defined(BUILD_NUMBER) && defined(VERSION_NUMBER)
          printf(TOOLNAME" version %s -- build %d\n", STRINGIFY(VERSION_NUMBER), BUILD_NUMBER);
#elif defined(BUILD_NUMBER)
          printf(TOOLNAME" custom build %d -- %s\n", BUILD_NUMBER, __DATE__);
#else
          printf(TOOLNAME" custom build -- %s, %s\n", __DATE__, __TIME__);
#endif
          exit(0);
        }
#ifdef DRCONFIG
# ifdef WINDOWS
        /* FIXME i#840: These are NYI for Linux. */
        else if (!strcmp(argv[i], "-list_registered")) {
            action = action_list;
            list_registered = true;
            continue;
        }
        else if (strcmp(argv[i], "-syswide_on") == 0) {
            syswide_on = true;
            continue;
        }
        else if (strcmp(argv[i], "-syswide_off") == 0) {
            syswide_off = true;
            continue;
        }
# endif
        else if (strcmp(argv[i], "-global") == 0) {
            global = true;
            continue;
        }
        else if (strcmp(argv[i], "-norun") == 0) {
            dr_mode = DR_MODE_DO_NOT_RUN;
            continue;
        }
#endif
        else if (strcmp(argv[i], "-32") == 0) {
            dr_platform = DR_PLATFORM_32BIT;
            continue;
        }
        else if (strcmp(argv[i], "-64") == 0) {
            dr_platform = DR_PLATFORM_64BIT;
            continue;
        }
#if defined(DRRUN) || defined(DRINJECT)
        else if (strcmp(argv[i], "-stats") == 0) {
            showstats = true;
            continue;
        }
        else if (strcmp(argv[i], "-mem") == 0) {
            showmem = true;
            continue;
        }
        else if (strcmp(argv[i], "-no_inject") == 0 ||
                 /* support old drinjectx param name */
                 strcmp(argv[i], "-noinject") == 0) {
            DR_dll_not_needed = true;
            inject = false;
            continue;
        }
        else if (strcmp(argv[i], "-force") == 0) {
            force_injection = true;
            continue;
        }
        else if (strcmp(argv[i], "-no_wait") == 0) {
            limit = -1;
            continue;
        }
# ifdef UNIX
        else if (strcmp(argv[i], "-use_ptrace") == 0) {
            /* Undocumented option for using ptrace on a fresh process. */
            use_ptrace = true;
            continue;
        }
        else if (strcmp(argv[i], "-attach") == 0) {
            const char *pid_str = argv[++i];
            process_id_t pid = strtoul(pid_str, NULL, 10);
            if (pid == ULONG_MAX)
                usage("-attach expects an integer pid");
            if (pid != 0)
                usage("attaching to running processes is not yet implemented");
            use_ptrace = true;
            /* FIXME: use pid below to attach. */
            continue;
        }
        else if (strcmp(argv[i], "-early") == 0) {
            /* Appending -early_inject to extra_ops communicates our intentions
             * to drinjectlib.
             */
            add_extra_option(extra_ops, BUFFER_SIZE_ELEMENTS(extra_ops),
                             &extra_ops_sofar, "-early_inject");
            continue;
        }
# endif /* UNIX */
        else if (strcmp(argv[i], "-exit0") == 0) {
            exit0 = true;
            continue;
        }
#endif
        /* all other flags have an argument -- make sure it exists */
        else if (argv[i][0] == '-' && i == argc - 1) {
            usage("invalid arguments");
        }

        /* params with an arg */
        if (strcmp(argv[i], "-root") == 0 ||
            /* support -dr_home alias used by script */
            strcmp(argv[i], "-dr_home") == 0) {
            dr_root = argv[++i];
        }
        else if (strcmp(argv[i], "-logdir") == 0) {
            /* Accept this for compatibility with the old drrun shell script. */
            const char *dir = argv[++i];
            if (_access(dir, 0) == -1)
                usage("-logdir %s does not exist", dir);
            add_extra_option(extra_ops, BUFFER_SIZE_ELEMENTS(extra_ops),
                             &extra_ops_sofar, "-logdir `%s`", dir);
            continue;
        }
#ifdef DRCONFIG
        else if (strcmp(argv[i], "-reg") == 0) {
            if (action != action_none) {
                usage("more than one action specified");
            }
            action = action_register;
            process = argv[++i];
        }
        else if (strcmp(argv[i], "-unreg") == 0) {
            if (action != action_none) {
                usage("more than one action specified");
            }
            action = action_unregister;
            process = argv[++i];
        }
        else if (strcmp(argv[i], "-isreg") == 0) {
            if (action != action_none) {
                usage("more than one action specified");
            }
            action = action_list;
            process = argv[++i];
        }
# ifdef WINDOWS
        /* FIXME i#840: Nudge is NYI for Linux. */
        else if (strcmp(argv[i], "-nudge_timeout") == 0) {
            nudge_timeout = strtoul(argv[++i], NULL, 10);
        }
        else if (strcmp(argv[i], "-nudge") == 0 ||
                 strcmp(argv[i], "-nudge_pid") == 0 ||
                 strcmp(argv[i], "-nudge_all") == 0){
            if (action != action_none) {
                usage("more than one action specified");
            }
            if (i + 2 >= argc ||
                (strcmp(argv[i], "-nudge_all") != 0 && i + 3 >= argc)) {
                usage("too few arguments to -nudge");
            }
            action = action_nudge;
            if (strcmp(argv[i], "-nudge") == 0)
                process = argv[++i];
            else if (strcmp(argv[i], "-nudge_pid") == 0)
                nudge_pid = strtoul(argv[++i], NULL, 10);
            else
                nudge_all = true;
            nudge_id = strtoul(argv[++i], NULL, 16);
            nudge_arg = _strtoui64(argv[++i], NULL, 16);
        }
# endif
#endif
#if defined(DRCONFIG) || defined(DRRUN)
# if defined(MF_API) || defined(PROBE_API)
        else if (strcmp(argv[i], "-mode") == 0) {
            char *mode_str = argv[++i];
            if (dr_mode == DR_MODE_DO_NOT_RUN)
                usage("cannot combine -norun with -mode");
            if (strcmp(mode_str, "code") == 0) {
                dr_mode = DR_MODE_CODE_MANIPULATION;
            }
#  ifdef MF_API
            else if (strcmp(mode_str, "security") == 0) {
                dr_mode = DR_MODE_MEMORY_FIREWALL;
            }
#  endif
#  ifdef PROBE_API
            else if (strcmp(mode_str, "probe") == 0) {
                dr_mode = DR_MODE_PROBE;
            }
#  endif
            else {
                usage("unknown mode: %s", mode_str);
            }
        }
# endif
        else if (strcmp(argv[i], "-client") == 0) {
            if (num_clients == MAX_CLIENT_LIBS) {
                error("Maximum number of clients is %d", MAX_CLIENT_LIBS);
                die();
            }
            else {
                const char *client;
                int id;
                const char *ops;
                if (i + 3 >= argc) {
                    usage("too few arguments to -client");
                }

                /* Support relative client paths: very useful! */
                client = argv[++i];
                id = strtoul(argv[++i], NULL, 16);
                ops = argv[++i];
                append_client(client, id, ops, client_paths, client_ids,
                              client_options, &num_clients);
            }
        }
        else if (strcmp(argv[i], "-ops") == 0) {
            /* support repeating the option (i#477) */
            add_extra_option(extra_ops, BUFFER_SIZE_ELEMENTS(extra_ops),
                             &extra_ops_sofar, "%s", argv[++i]);
        }
#endif
#if defined(DRRUN) || defined(DRINJECT)
        else if (strcmp(argv[i], "-pidfile") == 0) {
            pidfile = argv[++i];
        }
        else if (strcmp(argv[i], "-use_dll") == 0) {
            DR_dll_not_needed = true;
            /* Support relative path: very useful! */
            GetFullPathName(argv[++i], BUFFER_SIZE_ELEMENTS(custom_dll),
                            custom_dll, NULL);
            NULL_TERMINATE_BUFFER(custom_dll);
            drlib_path = custom_dll;
        }
        else if (strcmp(argv[i], "-s") == 0) {
            limit = atoi(argv[++i]);
            if (limit <= 0)
                usage("invalid time");
        }
        else if (strcmp(argv[i], "-m") == 0) {
            limit = atoi(argv[++i])*60;
            if (limit <= 0)
                usage("invalid time");
        }
        else if (strcmp(argv[i], "-h") == 0) {
            limit = atoi(argv[++i])*3600;
            if (limit <= 0)
                usage("invalid time");
        }
# ifdef UNIX
        else if (strcmp(argv[i], "-killpg") == 0) {
            kill_group = true;
        }
# endif
#endif
#if defined(DRCONFIG) || defined(DRRUN)
        /* if there are still options, assume user is using -- to separate and pass
         * through options to DR.  we do not handle mixing DR options with tool
         * options: DR must come last.  we would need to generate code here from
         * optionsx.h to do otherwise, or to sanity check the DR options here.
         */
        else if (argv[i][0] == '-') {
            while (i<argc) {
                if (strcmp(argv[i], "-c") == 0 ||
                    strcmp(argv[i], "-t") == 0 ||
                    strcmp(argv[i], "--") == 0) {
                    break;
                }
                add_extra_option(extra_ops, BUFFER_SIZE_ELEMENTS(extra_ops),
                                 &extra_ops_sofar, "%s", argv[i]);
                i++;
            }
            if (i < argc &&
                (strcmp(argv[i], "-t") == 0 ||
                 strcmp(argv[i], "-c") == 0)) {
                const char *client;
                char client_buf[MAXIMUM_PATH];
                size_t client_sofar = 0;
                if (i + 1 >= argc)
                    usage("too few arguments to %s", argv[i]);
                if (num_clients != 0)
                    usage("Cannot use -client with %s.", argv[i]);
                client = argv[++i];
                single_client_ops[0] = '\0';

                if (strcmp(argv[i-1], "-t") == 0) {
                    /* Client-requested DR default options come last, so they
                     * cannot be overridden by DR options passed here.
                     * The user must use -c or -client to do that.
                     */
                    if (!read_tool_file(client, dr_root, dr_platform,
                                        client_buf, BUFFER_SIZE_ELEMENTS(client_buf),
                                        extra_ops, BUFFER_SIZE_ELEMENTS(extra_ops),
                                        &extra_ops_sofar,
                                        single_client_ops,
                                        BUFFER_SIZE_ELEMENTS(single_client_ops),
                                        &client_sofar))
                        usage("unknown tool requested");
                    client = client_buf;
                }

                /* Treat everything up to -- or end of argv as client args. */
                i++;
                while (i < argc && strcmp(argv[i], "--") != 0) {
                    add_extra_option(single_client_ops,
                                     BUFFER_SIZE_ELEMENTS(single_client_ops),
                                     &client_sofar, "%s", argv[i]);
                    i++;
                }
                append_client(client, 0, single_client_ops, client_paths,
                              client_ids, client_options, &num_clients);
            }
            if (i < argc && strcmp(argv[i], "--") == 0) {
                i++;
                goto done_with_options;
            }
        }
#else /* DRINJECT */
        else if (strcmp(argv[i], "--") == 0) {
            i++;
            goto done_with_options;
        }
#endif
        else {
#ifdef DRCONFIG
            usage("unknown option: %s", argv[i]);
#else
            /* start of app and its args */
            break;
#endif
        }
    }

#if defined(DRCONFIG) || defined(DRRUN) || defined(DRINJECT)
 done_with_options:
#endif

#if defined(DRRUN) || defined(DRINJECT)
    if (i >= argc)
        usage("%s", "no app specified");
    app_name = argv[i++];
    _searchenv(app_name, "PATH", full_app_name);
    NULL_TERMINATE_BUFFER(full_app_name);
    if (full_app_name[0] == '\0') {
        /* may need to append .exe, FIXME : other executable types */
        char tmp_buf[MAXIMUM_PATH];
        _snprintf(tmp_buf, BUFFER_SIZE_ELEMENTS(tmp_buf),
                  "%s%s", app_name, ".exe");
        NULL_TERMINATE_BUFFER(tmp_buf);
        _searchenv(tmp_buf, "PATH", full_app_name);
    }
    if (full_app_name[0] == '\0') {
        /* last try */
        GetFullPathName(app_name, BUFFER_SIZE_ELEMENTS(full_app_name),
                        full_app_name, NULL);
        NULL_TERMINATE_BUFFER(full_app_name);
    }
    if (full_app_name[0] != '\0')
        app_name = full_app_name;
    info("targeting application: \"%s\"", app_name);

    /* note that we want target app name as part of cmd line
     * (hence &argv[i - 1])
     * (FYI: if we were using WinMain, the pzsCmdLine passed in
     *  does not have our own app name in it)
     */
    app_argv = (const char **) &argv[i - 1];
    if (verbose) {
        c = buf;
        for (i = 0; app_argv[i] != NULL; i++) {
            c += _snprintf(c, BUFFER_SIZE_ELEMENTS(buf) - (c - buf),
                           " \"%s\"", app_argv[i]);
        }
        info("app cmdline: %s", buf);
    }

#else
    if (i < argc)
        usage("%s", "invalid extra arguments specified");
#endif

#ifdef WINDOWS
    /* FIXME i#900: This doesn't work on Linux, and doesn't do the right thing
     * on Windows.
     */
    /* PR 244206: set the registry view before any registry access */
    set_dr_platform(dr_platform);
#endif

#ifdef DRCONFIG
    if (action == action_register) {
        if (!register_proc(process, 0, global, dr_root, dr_mode,
                           use_debug, dr_platform, extra_ops))
            die();
        for (j=0; j<num_clients; j++) {
            if (!register_client(process, 0, global, dr_platform, client_ids[j],
                                 client_paths[j], client_options[j]))
                die();
        }
    }
    else if (action == action_unregister) {
        if (!unregister_proc(process, 0, global, dr_platform))
            die();
    }
# ifndef WINDOWS
    else {
        usage("no action specified");
    }
# else /* WINDOWS */
    /* FIXME i#840: Nudge NYI on Linux. */
    else if (action == action_nudge) {
        int count = 1;
        dr_config_status_t res = DR_SUCCESS;
        if (nudge_all)
            res = dr_nudge_all(nudge_id, nudge_arg, nudge_timeout, &count);
        else if (nudge_pid != 0) {
            res = dr_nudge_pid(nudge_pid, nudge_id, nudge_arg, nudge_timeout);
            if (res == DR_NUDGE_PID_NOT_INJECTED)
                printf("process %d is not running under DR\n", nudge_pid);
            if (res != DR_SUCCESS && res != DR_NUDGE_TIMEOUT) {
                count = 0;
                res = ERROR_SUCCESS;
            }
        } else
            res = dr_nudge_process(process, nudge_id, nudge_arg, nudge_timeout, &count);

        printf("%d processes nudged\n", count);
        if (res == DR_NUDGE_TIMEOUT)
            printf("timed out waiting for nudge to complete");
        else if (res != DR_SUCCESS)
            printf("nudge operation failed, verify adequate permissions for this operation.");
    }
#  ifdef WINDOWS
    /* FIXME i#840: Process iterator NYI for Linux. */
    else if (action == action_list) {
        if (!list_registered)
            list_process(process, global, dr_platform, NULL);
        else /* list all */ {
            dr_registered_process_iterator_t *iter =
                dr_registered_process_iterator_start(dr_platform, global);
            printf("Registered %s processes for %s\n",
                   global ? "global" : "local", platform_name(dr_platform));
            while (dr_registered_process_iterator_hasnext(iter))
                list_process(NULL, global, dr_platform, iter);
            dr_registered_process_iterator_stop(iter);
        }
    }
#  endif
    else if (!syswide_on && !syswide_off) {
        usage("no action specified");
    }
    if (syswide_on) {
        DWORD platform;
        if (get_platform(&platform) != ERROR_SUCCESS)
            platform = PLATFORM_UNKNOWN;
        if (platform >= PLATFORM_WIN_8) {
            error("syswide_on is not yet supported on Windows 8");
            die();
        }
        if (!check_dr_root(dr_root, false, dr_platform, true))
            die();
        /* If this is the first setting of AppInit on NT, warn about reboot */
        if (!dr_syswide_is_on(dr_platform, dr_root)) {
            if (platform == PLATFORM_WIN_NT_4) {
                warn("on Windows NT, applications will not be taken over until reboot");
            }
            else if (platform >= PLATFORM_WIN_7) {
                /* i#323 will fix this but good to warn the user */
                warn("on Windows 7, syswide_on relaxes system security by removing certain code signing requirements");
            }
        }
        if (dr_register_syswide(dr_platform, dr_root) != ERROR_SUCCESS) {
            /* PR 233108: try to give more info on whether a privilege failure */
            warn("syswide set failed: re-run as administrator");
        }
    }
    if (syswide_off) {
        if (dr_unregister_syswide(dr_platform, dr_root) != ERROR_SUCCESS) {
            /* PR 233108: try to give more info on whether a privilege failure */
            warn("syswide set failed: re-run as administrator");
        }
    }
# endif /* WINDOWS */
    return 0;
#else /* DRCONFIG */
    if (!global) {
        /* i#939: attempt to work w/o any HOME/USERPROFILE by using a temp dir */
        dr_get_config_dir(global, true/*use temp*/, buf, BUFFER_SIZE_ELEMENTS(buf));
    }
# ifdef UNIX
    /* On Linux, we use exec by default to create the app process.  This matches
     * our drrun shell script and makes scripting easier for the user.
     */
    if (limit == 0 && !use_ptrace && !kill_group) {
        info("will exec %s", app_name);
        errcode = dr_inject_prepare_to_exec(app_name, app_argv, &inject_data);
    } else
# endif /* UNIX */
    {
        errcode = dr_inject_process_create(app_name, app_argv, &inject_data);
        info("created child with pid %d for %s",
             dr_inject_get_process_id(inject_data), app_name);
    }
# ifdef UNIX
    if (limit != 0 && kill_group) {
        /* Move the child to its own process group. */
        process_id_t child_pid = dr_inject_get_process_id(inject_data);
        int res = setpgid(child_pid, child_pid);
        if (res < 0) {
            perror("ERROR in setpgid");
            goto error;
        }
    }
# endif
    if (errcode == ERROR_IMAGE_MACHINE_TYPE_MISMATCH_EXE
        /* Check whether -32/64 is specified, but only for Linux as we do
         * not support cross-arch on Windows yet (i#803).
         */
        IF_UNIX(&& dr_platform != IF_X64_ELSE(DR_PLATFORM_32BIT,
                                              DR_PLATFORM_64BIT))) {
        if (nocheck) {
            /* Allow override for cases like i#1224 */
            warn("Target process %s appears to be for the wrong architecture.", app_name);
            warn("Attempting to run anyway, but it may run natively if injection fails.");
            errcode = 0;
        } else {
            /* For Windows, better error message than the FormatMessage */
            error("Target process %s is for the wrong architecture", app_name);
            goto error; /* the process was still created */
        }
    }
    if (errcode != 0
        IF_UNIX(&& errcode != ERROR_IMAGE_MACHINE_TYPE_MISMATCH_EXE)) {
        IF_WINDOWS(int sofar =)
            _snprintf(buf, BUFFER_SIZE_ELEMENTS(buf),
                      "Failed to create process for \"%s\": ", app_name);
# ifdef WINDOWS
        if (sofar > 0) {
            FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                          NULL, errcode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                          (LPTSTR) buf + sofar,
                          BUFFER_SIZE_ELEMENTS(buf) - sofar*sizeof(char), NULL);
        }
# endif /* WINDOWS */
        NULL_TERMINATE_BUFFER(buf);
        error("%s", buf);
        goto error;
    }

    /* i#200/PR 459481: communicate child pid via file */
    if (pidfile != NULL)
        write_pid_to_file(pidfile, dr_inject_get_process_id(inject_data));

# ifdef DRRUN
    /* even if !inject we create a config file, for use running standalone API
     * apps.  if user doesn't want a config file, should use "drinject -noinject".
     */
    process = dr_inject_get_image_name(inject_data);
    if (!register_proc(process, dr_inject_get_process_id(inject_data), global,
                       dr_root, dr_mode, use_debug, dr_platform, extra_ops))
        goto error;
    for (j=0; j<num_clients; j++) {
        if (!register_client(process, dr_inject_get_process_id(inject_data), global,
                             dr_platform, client_ids[j],
                             client_paths[j], client_options[j]))
            goto error;
    }
# endif

# ifdef UNIX
    if (use_ptrace) {
        if (!dr_inject_prepare_to_ptrace(inject_data)) {
            error("unable to use ptrace");
            goto error;
        } else {
            info("using ptrace to inject");
        }
    }
    if (kill_group) {
        /* Move the child to its own process group. */
        bool res = dr_inject_prepare_new_process_group(inject_data);
        if (!res) {
            error("error moving child to new process group");
            goto error;
        }
    }
# endif

    if (inject && !dr_inject_process_inject(inject_data, force_injection, drlib_path)) {
        error("unable to inject: did you forget to run drconfig first?");
        goto error;
    }

    IF_WINDOWS(start_time = time(NULL);)

    if (!dr_inject_process_run(inject_data)) {
        error("unable to run");
        goto error;
    }

# ifdef WINDOWS
    if (limit == 0 && dr_inject_using_debug_key(inject_data)) {
        info("%s", "Using debugger key injection");
        limit = -1; /* no wait */
    }
# endif

    if (limit >= 0) {
# ifdef WINDOWS
        double wallclock;
# endif
        uint64 limit_millis = limit * 1000;
        info("waiting %sfor app to exit...", (limit <= 0) ? "forever " : "");
        success = dr_inject_wait_for_child(inject_data, limit_millis);
# ifdef WINDOWS
        end_time = time(NULL);
        wallclock = difftime(end_time, start_time);
        if (showstats || showmem)
            dr_inject_print_stats(inject_data, (int) wallclock, showstats, showmem);
# endif
        if (!success)
            info("timeout after %d seconds\n", limit);
    } else {
        success = true;  /* Don't kill the child if we're not waiting. */
    }

    exitcode = dr_inject_process_exit(inject_data, !success/*kill process*/);

    if (limit < 0)
        exitcode = 0;  /* Return success if we didn't wait. */

    if (exit0)
        exitcode = 0;

    /* FIXME i#840: We can't actually match exit status on Linux perfectly
     * since the kernel reserves most of the bits for signal codes.  At the
     * very least, we should ensure if the app exits with a signal we exit
     * non-zero.
     */
    return exitcode;

 error:
    /* we created the process suspended so if we later had an error be sure
     * to kill it instead of leaving it hanging
     */
    if (inject_data != NULL)
        dr_inject_process_exit(inject_data, true/*kill process*/);
    return 1;
#endif /* !DRCONFIG */
}

