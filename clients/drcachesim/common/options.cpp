/* **********************************************************
 * Copyright (c) 2015 Google, Inc.  All rights reserved.
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
 * * Neither the name of Google, Inc. nor the names of its contributors may be
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

/* shared options for both the frontend and the client */

#include <string>
#include "droption.h"
#include "options.h"

droption_t<std::string> op_ipc_name
(DROPTION_SCOPE_ALL, "ipc_name", "drcachesimpipe", "Base name of named pipe",
 "Specifies the base name of the named pipe used to communicate between the target "
 "application processes and the cache simulator.  A unique name must be chosen "
 "for each instance of the simulator being run at any one time.");

droption_t<unsigned int> op_num_cores
(DROPTION_SCOPE_FRONTEND, "cores", 4, "Number of cores",
 "Specifies the number of cores to simulate.  Each core has an L1 instruction cache "
 "and an L1 data cache.");

droption_t<unsigned int> op_line_size
(DROPTION_SCOPE_FRONTEND, "line_size", 64, "Cache line size",
 "Specifies the cache line size, which is assumed to be identical for L1 and L2 "
 "caches.");

droption_t<bytesize_t> op_L1I_size
(DROPTION_SCOPE_FRONTEND, "L1I_size", 32*1024U, "Instruction cache total size",
 "Specifies the total size of each L1 instruction cache.");

droption_t<bytesize_t> op_L1D_size
(DROPTION_SCOPE_FRONTEND, "L1D_size", bytesize_t(32*1024), "Data cache total size",
 "Specifies the total size of each L1 data cache.");

droption_t<unsigned int> op_L1I_assoc
(DROPTION_SCOPE_FRONTEND, "L1I_assoc", 8, "Instruction cache associativity",
 "Specifies the associativity of each L1 instruction cache.");

droption_t<unsigned int> op_L1D_assoc
(DROPTION_SCOPE_FRONTEND, "L1D_assoc", 8, "Data cache associativity",
 "Specifies the associativity of each L1 data cache.");

droption_t<bytesize_t> op_LL_size
(DROPTION_SCOPE_FRONTEND, "LL_size", 8*1024*1024, "Last-level cache total size",
 "Specifies the total size of the unified last-level (L2) cache.");

droption_t<unsigned int> op_LL_assoc
(DROPTION_SCOPE_FRONTEND, "LL_assoc", 16, "Last-level cache associativity",
 "Specifies the associativity of the unified last-level (L2) cache.");

droption_t<bool> op_use_physical
(DROPTION_SCOPE_CLIENT, "use_physical", false, "Use physical addresses if possible",
 "If available, the default virtual addresses will be translated to physical.  "
 "This is not possible from user mode on all platforms.");

droption_t<bool> op_replace_lru
(DROPTION_SCOPE_FRONTEND, "replace_lru", false, "Use an LRU cache replacement policy",
 "Use a Least Recently Used (LRU) cache replacement algorithm."
 "If multiple replacement policies are passed, only one will be used.");

droption_t<bool> op_replace_lfu
(DROPTION_SCOPE_FRONTEND, "replace_lfu", true, "Use an LFU cache replacement policy",
 "Use a (default) Least Frequently Used (LFU) cache replacement algorithm."
 "If multiple replacement policies are passed, only one will be used.");

droption_t<unsigned int> op_virt2phys_freq
(DROPTION_SCOPE_CLIENT, "virt2phys_freq", 0, "Frequency of physical mapping refresh",
 "This option only applies if -use_physical is enabled.  The virtual to physical "
 "mapping is cached for performance reasons, yet the underlying mapping can change "
 "without notice.  This option controls the frequency with which the cached value is "
 "ignored in order to re-access the actual mapping and ensure accurate results.  "
 "The units are the number of memory accesses per forced access.  A value of 0 "
 "uses the cached values for the entire application execution.");

droption_t<unsigned int> op_verbose
(DROPTION_SCOPE_ALL, "verbose", 0, 0, 64, "Verbosity level",
 "Verbosity level for notifications.");

droption_t<std::string> op_dr_root
(DROPTION_SCOPE_FRONTEND, "dr", "", "Path to DynamoRIO root directory",
 "Specifies the path of the DynamoRIO root directory.");

droption_t<bool> op_dr_debug
(DROPTION_SCOPE_FRONTEND, "dr_debug", false, "Use DynamoRIO debug build",
 "Requests use of the debug build of DynamoRIO rather than the release build.");

droption_t<std::string> op_dr_ops
(DROPTION_SCOPE_FRONTEND, "dr_ops", "", "Options to pass to DynamoRIO",
 "Specifies the options to pass to DynamoRIO.");

droption_t<std::string> op_tracer
(DROPTION_SCOPE_FRONTEND, "tracer", "", "Path to the tracer",
 "The full path to the tracer library.");

droption_t<std::string> op_tracer_ops
(DROPTION_SCOPE_FRONTEND, "tracer_ops", DROPTION_FLAG_SWEEP | DROPTION_FLAG_ACCUMULATE,
 "", "(For internal use: sweeps up tracer options)",
 "This is an internal option that sweeps up other options to pass to the tracer.");
