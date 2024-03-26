/* **********************************************************
 * Copyright (c) 2017-2022 Google, Inc.  All rights reserved.
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

#ifndef _MISSING_INSTRUCTIONS_H_
#define _MISSING_INSTRUCTIONS_H_ 1

#include <iomanip>
#include <iostream>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "dr_api.h" // Must be before trace_entry.h from analysis_tool.h.
#include "analysis_tool.h"
#include "../simulator/cache_simulator.h"
#include "cachesim_row.h"
#include "memref.h"
#include <sqlite3.h>
namespace dynamorio {
namespace drmemtrace {
class missing_instructions_t : public cache_simulator_t {
public:
    // The module_file_path is optional and unused for traces with
    // OFFLINE_FILE_TYPE_ENCODINGS.
    // XXX: Once we update our toolchains to guarantee C++17 support we could use
    // std::optional here.

    void
    get_opcode(const memref_t &memref, cachesim_row &row);
    // Destructor to ensure the database is closed
    ~missing_instructions_t() final
    {
        close_database();
    }
    explicit missing_instructions_t(const cache_simulator_knobs_t &knobs);

    bool
    process_memref(const memref_t &memref) override;
    bool
    print_results() override;
    void
    print_instr_stats(int core);
    struct cache_metric_statistics {
        int current_instruction_id;
        int core;
        bool thread_switch;
        bool core_switch;
        int l1_data_hits;
        int l1_data_misses;
        float l1_data_ratio;
        int l1_inst_hits;
        int l1_inst_misses;
        float l1_inst_ratio;
        int ll_hits;
        int ll_misses;
        float ll_ratio;
    };
    struct miss_counts {
        std::string access_address;
        std::string pc_address;
        bool l1d_miss;
        bool l1i_miss;
        bool ll_miss;
        std::string instr_type;
        uint8_t byte_count;
        std::string disassembly_string;
    };

protected:
    struct dcontext_cleanup_last_t {
    public:
        ~dcontext_cleanup_last_t()
        {
            if (dcontext != nullptr)
                dr_standalone_exit();
        }
        void *dcontext = nullptr;
    };
    //     /* We make this the first field so that dr_standalone_exit() is called after
    //      * destroying the other fields which may use DR heap.
    //      */
    dcontext_cleanup_last_t dcontext_;

    //     // These are all optional and unused for OFFLINE_FILE_TYPE_ENCODINGS.
    //     // XXX: Once we update our toolchains to guarantee C++17 support we could use
    //     // std::optional here.

    static const std::string TOOL_NAME;

private:
    int current_instruction_id = 0;
    uintptr_t curr_core_id = 0;
    memref_tid_t curr_thread_id;

    void
    create_experiment_insert_statement(const cache_simulator_knobs_t &knobs);
    void
    update_instruction_stats(int core, bool thread_switch, bool core_switch,
                             const memref_t &memref, cachesim_row &row);

    void
    update_miss_stats(int core, const memref_t &memref, cachesim_row &row);
    void
    embed_address_deltas_into_row(cachesim_row &row);
    void
    open_database(const std::string db_filename);
    void
    create_table();
    void
    insert_row_into_database(const cachesim_row &row, sqlite3_stmt *stmt);
    void
    begin_transaction();
    void
    buffer_row(const cachesim_row &row);
    void
    flush_buffer_to_database();
    void
    end_transaction();
    void
    close_database();
    std::string cache_database_filename;
    std::string experiments_filename = "experiments.csv";
    std::string csv_log_path = "";
    addr_t last_pc_address = 0;
    addr_t last_access_address = 0;
    sqlite3 *db = nullptr;
    std::vector<cachesim_row> row_buffer;
};

} // namespace drmemtrace
} // namespace dynamorio

#endif /* _MISSING_INSTRUCTIONS_H_ */
