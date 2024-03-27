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

/* This trace analyzer requires access to the modules.log file and the
 * libraries and binary from the traced execution in order to obtain further
 * information about each instruction than was stored in the trace.
 * It does not support online use, only offline.
 */

#include "dr_api.h"
#include "missing_instructions.h"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <memory>
#include <vector>
#include <stdexcept>
#include "memref.h"
#include "memtrace_stream.h"
#include <fstream>
#include <ctime>
#include <zlib.h>
#include <sys/stat.h>
#include <sqlite3.h>

namespace dynamorio {
namespace drmemtrace {

const std::string missing_instructions_t::TOOL_NAME = "Missing_Instructions tool";

void
missing_instructions_t::get_opcode(const memref_t &memref, cachesim_row &row)
{

    static constexpr int name_width = 12;
    if (!type_is_instr(memref.instr.type) &&
        memref.data.type != TRACE_TYPE_INSTR_NO_FETCH) {

        std::string name;
        switch (memref.data.type) {
        default: name = "entry_type_" + memref.data.type; break;
        case TRACE_TYPE_THREAD_EXIT: name = "thread_exit"; break;

        case TRACE_TYPE_READ: name = "read"; break;
        case TRACE_TYPE_WRITE: name = "write"; break;
        case TRACE_TYPE_INSTR_FLUSH: name = "iflush"; break;
        case TRACE_TYPE_DATA_FLUSH: name = "dflush"; break;
        case TRACE_TYPE_PREFETCH: name = "pref"; break;
        case TRACE_TYPE_PREFETCH_READ_L1: name = "pref-r-L1"; break;
        case TRACE_TYPE_PREFETCH_READ_L2: name = "pref-r-L2"; break;
        case TRACE_TYPE_PREFETCH_READ_L3: name = "pref-r-L3"; break;
        case TRACE_TYPE_PREFETCHNTA: name = "pref-NTA"; break;
        case TRACE_TYPE_PREFETCH_READ: name = "pref-r"; break;
        case TRACE_TYPE_PREFETCH_WRITE: name = "pref-w"; break;
        case TRACE_TYPE_PREFETCH_INSTR: name = "pref-i"; break;
        case TRACE_TYPE_PREFETCH_READ_L1_NT: name = "pref-r-L1-NT"; break;
        case TRACE_TYPE_PREFETCH_READ_L2_NT: name = "pref-r-L2-NT"; break;
        case TRACE_TYPE_PREFETCH_READ_L3_NT: name = "pref-r-L3-NT"; break;
        case TRACE_TYPE_PREFETCH_INSTR_L1: name = "pref-i-L1"; break;
        case TRACE_TYPE_PREFETCH_INSTR_L1_NT: name = "pref-i-L1-NT"; break;
        case TRACE_TYPE_PREFETCH_INSTR_L2: name = "pref-i-L2"; break;
        case TRACE_TYPE_PREFETCH_INSTR_L2_NT: name = "pref-i-L2-NT"; break;
        case TRACE_TYPE_PREFETCH_INSTR_L3: name = "pref-i-L3"; break;
        case TRACE_TYPE_PREFETCH_INSTR_L3_NT: name = "pref-i-L3-NT"; break;
        case TRACE_TYPE_PREFETCH_WRITE_L1: name = "pref-w-L1"; break;
        case TRACE_TYPE_PREFETCH_WRITE_L1_NT: name = "pref-w-L1-NT"; break;
        case TRACE_TYPE_PREFETCH_WRITE_L2: name = "pref-w-L2"; break;
        case TRACE_TYPE_PREFETCH_WRITE_L2_NT: name = "pref-w-L2-NT"; break;
        case TRACE_TYPE_PREFETCH_WRITE_L3: name = "pref-w-L3"; break;
        case TRACE_TYPE_PREFETCH_WRITE_L3_NT: name = "pref-w-L3-NT"; break;
        case TRACE_TYPE_HARDWARE_PREFETCH: name = "pref-HW"; break;
        }

        row.set_byte_count(static_cast<uint8_t>(memref.data.size));
        row.set_instr_type(name);
        return;
    }

    app_pc decode_pc;
    auto orig_pc = (app_pc)memref.instr.addr;
    // if (TESTANY(OFFLINE_FILE_TYPE_ENCODINGS, filetype_)) {
    // The trace has instruction encodings inside it.
    decode_pc = const_cast<app_pc>(memref.instr.encoding);

    std::string disasm;
    // auto cached_disasm = disasm_cache_.find(orig_pc);
    //   if (cached_disasm != disasm_cache_.end()) {
    //       disasm = cached_disasm->second;
    //   } else {
    // MAX_INSTR_DIS_SZ is set to 196 in core/ir/disassemble.h but is not
    // exported so we just use the same value here.
    char buf[196]; // NOSONAR
    const byte *next_pc =
        disassemble_to_buffer(dcontext_.dcontext, decode_pc, orig_pc, /*show_pc=*/false,
                              /*show_bytes=*/true, buf, BUFFER_SIZE_ELEMENTS(buf),
                              /*printed=*/nullptr);
    if (next_pc == nullptr) {
        error_string_ = "Failed to disassemble " + to_hex_string(memref.instr.addr);
        throw std::invalid_argument(error_string_);
    }
    disasm = buf;

    auto newline = disasm.find('\n');
    if (newline != std::string::npos && newline < disasm.size() - 1) {
        std::stringstream prefix;

        std::string skip_name(name_width, ' ');
        disasm.insert(newline + 1,
                      prefix.str() + skip_name + "                               ");
    }
    disasm.erase(std::remove(disasm.begin(), disasm.end(), '\n'), disasm.end());

    row.set_instr_type("ifetch");
    row.set_disassembly_string(disasm);
    row.set_byte_count(static_cast<uint8_t>(memref.data.size));
}

analysis_tool_t *
missing_instructions_tool_create(const cache_simulator_knobs_t &knobs)
{
    // Won't fix this.
    return new missing_instructions_t(knobs);
}

missing_instructions_t::missing_instructions_t(const cache_simulator_knobs_t &knobs)
    : cache_simulator_t(knobs)
    , csv_log_path(knobs_.cache_trace_log_path)
    , max_buffer_size(knobs_.cachesim_row_buffer_size)
    , max_trace_length(knobs_.max_trace_length)
{
    std::string format = knobs_.trace_form;
    std::transform(format.begin(), format.end(), format.begin(), ::tolower);
    use_expanded_trace_format = (format == "expanded");

    std::cout << "Path for logging: " << csv_log_path << "\n";
    create_experiment_insert_statement(knobs_);
}

void
missing_instructions_t::create_experiment_insert_statement(
    const cache_simulator_knobs_t &knobs)
{
    // Generate a unique ID based on current time
    std::stringstream id_ss;
    id_ss << std::time(nullptr);
    std::string experiment_id = id_ss.str();

    experiments_filename = csv_log_path + experiments_filename;

    // Create or open the experiments CSV file
    std::ofstream experiments_file(experiments_filename, std::ios::app);

    // Check if the file is empty and write the header if it is
    std::ifstream check_file(experiments_filename);
    if (check_file.peek() == std::ifstream::traits_type::eof()) {
        experiments_file << "Experiment ID; L1D Size; L1I Size; Num Cores; "
                         << "L1I Assoc; L1D Assoc; LL Size; Line Size; LL Assoc; "
                         << "Model Coherence; Replace Policy; Skip Refs; Warmup Refs; "
                         << "Warmup Fraction; CPU Scheduling; Use Physical\n";
    }
    check_file.close();

    // Write experiment data to CSV
    experiments_file << experiment_id << "; " << (knobs.L1D_size / 1024) << "K; "
                     << (knobs.L1I_size / 1024) << "K; " << knobs.num_cores << "; "
                     << knobs.L1I_assoc << "; " << knobs.L1D_assoc << "; "
                     << (knobs.LL_size / (1024 * 1024)) << "M; " << knobs.line_size
                     << "; " << knobs.LL_assoc << "; " << (knobs.model_coherence ? 1 : 0)
                     << "; "
                     << "'" << knobs.replace_policy << "'; " << knobs.skip_refs << "; "
                     << knobs.warmup_refs << "; " << knobs.warmup_fraction << "; " << 0
                     << "; " // Assuming 0 for Sim Refs as per  method
                     << (knobs.cpu_scheduling ? 1 : 0) << "; "
                     << (knobs.use_physical ? 1 : 0) << "\n";
    experiments_file.close();
    // Open the corresponding cache statistics CSV file
    cache_database_filename = csv_log_path + "cache_stats_" + experiment_id + ".db";
    std::cerr << "Printing cache stats database to " << cache_database_filename << "\n";

    open_database(cache_database_filename);
    create_table();
}

bool
missing_instructions_t::process_memref(const memref_t &memref)
{
    if (static_cast<unsigned int>(current_instruction_id) >= max_trace_length) {
        close_database();
        return false;
    }
    current_instruction_id++;

    try {
        int core;
        bool thread_switch = false;
        bool core_switch = false;
        if (memref.data.tid == last_thread_)
            core = last_core_index_;
        else {
            core = core_for_thread(memref.data.tid);
            last_thread_ = memref.data.tid;
            std::cout << "< CORE_SWITCH_FROM_" << last_core_index_ << "_TO_" << core
                      << " >" << std::endl;
            thread_switch = true;
            if (core != last_thread_)
                core_switch = true;
            last_core_index_ = core;
        }
        if (current_instruction_id % 100000 == 0)
            std::cerr << "Doing " << current_instruction_id << std::endl;
        std::unique_ptr<cachesim_row> row;
        if (use_expanded_trace_format)
            row.reset(new expanded_cachesim_row()); // Replaces std::make_unique
        else
            row.reset(new cachesim_row(current_instruction_id, core, thread_switch,
                                       core_switch)); // Replaces std::make_unique
        update_instruction_stats(core, thread_switch, core_switch, *row);
        update_miss_stats(core, memref, *row);
        embed_address_deltas_into_row(*row);
        if (!(row->get_instr_type() == "ifetch" && row->get_access_address_delta() == 0 &&
              row->get_pc_address_delta() == 0)) {
            buffer_row(row);
        }
        return true;
    } catch (const std::exception &ex) {
        std::cerr << "Issue occurred during disassembly of trace: " << ex.what()
                  << std::endl;
        throw;
    }
}

void
missing_instructions_t::embed_address_deltas_into_row(cachesim_row &row)
{
    try {

        // Reset last addresses on thread switch
        if (row.get_thread_switch()) {
            last_pc_address = 0;
            last_access_address = 0;
        }
        // Convert addresses from string to numerical value for delta calculation
        addr_t current_pc = row.get_pc_address();
        addr_t current_access = row.get_access_address();

        // Calculate deltas with underflow check
        int64_t delta_pc =
            static_cast<int64_t>(current_pc) - static_cast<int64_t>(last_pc_address);
        int64_t delta_access = static_cast<int64_t>(current_access) -
            static_cast<int64_t>(last_access_address);

        // Handle potential underflow leading to large positive deltas
        if (delta_pc < -std::numeric_limits<int32_t>::max() ||
            delta_pc > std::numeric_limits<int32_t>::max()) {
            delta_pc = 0; // Reset delta if underflow is detected or the delta is
                          // unreasonably large
        }
        if (delta_access < -std::numeric_limits<int32_t>::max() ||
            delta_access > std::numeric_limits<int32_t>::max()) {
            delta_access = 0; // Reset delta if underflow is detected or the delta is
                              // unreasonably large
        }

        // Update last addresses
        last_pc_address = current_pc;
        last_access_address = current_access;

        // Construct the output row with deltas

        row.set_access_address_delta(static_cast<int>(delta_access));
        row.set_pc_address_delta(static_cast<int>(delta_pc));

    } catch (const std::exception &e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        throw;
    }
}
void
missing_instructions_t::update_miss_stats(int core, const memref_t &memref,
                                          cachesim_row &row)
{

    long int data_misses_l1_pre = cache_simulator_t::get_cache_metric(
        metric_name_t::MISSES, 0, core, cache_split_t::DATA);
    long int inst_misses_l1_pre = cache_simulator_t::get_cache_metric(
        metric_name_t::MISSES, 0, core, cache_split_t::INSTRUCTION);
    long int unified_misses_ll_pre = cache_simulator_t::get_cache_metric(
        metric_name_t::MISSES, 2, core, cache_split_t::DATA);

    cache_simulator_t::process_memref(memref);
    long int data_misses_l1_post = cache_simulator_t::get_cache_metric(
        metric_name_t::MISSES, 0, core, cache_split_t::DATA);
    long int inst_misses_l1_post = cache_simulator_t::get_cache_metric(
        metric_name_t::MISSES, 0, core, cache_split_t::INSTRUCTION);
    long int unified_misses_ll_post = cache_simulator_t::get_cache_metric(
        metric_name_t::MISSES, 2, core, cache_split_t::DATA);

    auto data_misses_l1 = static_cast<int>(data_misses_l1_post - data_misses_l1_pre);
    auto inst_misses_l1 = static_cast<int>(inst_misses_l1_post - inst_misses_l1_pre);
    auto unified_misses_ll =
        static_cast<int>(unified_misses_ll_post - unified_misses_ll_pre);

    bool data_miss_l1 = false;
    bool inst_miss_l1 = false;
    bool unified_miss_ll = false;

    if (data_misses_l1 == 1)
        data_miss_l1 = true;
    else if (data_misses_l1 != 0)
        throw std::runtime_error("Data shouldn't happen...");

    if (1 <= inst_misses_l1 && inst_misses_l1 <= 2)
        inst_miss_l1 = true;
    else if (inst_misses_l1 != 0) {
        std::cout << "Inst misses:" << inst_misses_l1 << std::endl;
        throw std::runtime_error("Inst shouldn't happen...");
    }

    if (1 <= unified_misses_ll && unified_misses_ll <= 2)
        unified_miss_ll = true;
    else if (unified_misses_ll != 0) {
        std::string regular_message_pre = "LL miss over 2 shouldn't happen. LL pre: ";
        std::string regular_message_post = " LL post: ";
        std::string error_message = regular_message_pre +
            std::to_string(unified_misses_ll_pre) + regular_message_post +
            std::to_string(unified_misses_ll_post);
        throw std::runtime_error(error_message);
    }

    addr_t pc;
    addr_t addr;
    if (type_is_instr(memref.data.type)) {
        pc = memref.instr.addr;
        addr = pc;
    } else {
        assert(type_is_prefetch(memref.data.type) ||
               memref.data.type == TRACE_TYPE_READ ||
               memref.data.type == TRACE_TYPE_WRITE);
        pc = memref.data.pc;
        addr = memref.data.addr;
    }

    row.set_pc_address(pc);
    row.set_access_address(addr);
    row.set_l1d_miss(data_miss_l1);
    row.set_l1i_miss(inst_miss_l1);
    row.set_ll_miss(unified_miss_ll);

    get_opcode(memref, row);
}
void
missing_instructions_t::update_instruction_stats(int core, bool thread_switch,
                                                 bool core_switch,
                                                 cachesim_row &row) const
{
    row.set_current_instruction_id(current_instruction_id);
    row.set_core(static_cast<uint8_t>(core));
    row.set_thread_switch(thread_switch);
    row.set_core_switch(core_switch);
}
void
missing_instructions_t::update_instruction_stats(int core, bool thread_switch,
                                                 bool core_switch,
                                                 expanded_cachesim_row &row) const
{
    long int l1_data_hits = cache_simulator_t::get_cache_metric(
        metric_name_t::HITS, 0, core, cache_split_t::DATA);
    long int l1_inst_hits = cache_simulator_t::get_cache_metric(
        metric_name_t::HITS, 0, core, cache_split_t::INSTRUCTION);
    long int l1_data_misses = cache_simulator_t::get_cache_metric(
        metric_name_t::MISSES, 0, core, cache_split_t::DATA);
    long int l1_inst_misses = cache_simulator_t::get_cache_metric(
        metric_name_t::MISSES, 0, core, cache_split_t::INSTRUCTION);
    long int ll_hits = cache_simulator_t::get_cache_metric(metric_name_t::HITS, 2, core,
                                                           cache_split_t::DATA);
    long int ll_misses = cache_simulator_t::get_cache_metric(metric_name_t::MISSES, 2,
                                                             core, cache_split_t::DATA);

    float l1_data_ratio = static_cast<float>(l1_data_misses) /
        static_cast<float>(l1_data_misses + l1_data_hits);
    float l1_inst_ratio = static_cast<float>(l1_inst_misses) /
        static_cast<float>(l1_inst_misses + l1_inst_hits);
    float ll_ratio =
        static_cast<float>(ll_misses) / static_cast<float>(ll_misses + ll_hits);

    row.set_current_instruction_id(current_instruction_id);
    row.set_core(static_cast<uint8_t>(core));
    row.set_thread_switch(thread_switch);
    row.set_core_switch(core_switch);
    row.set_l1_data_misses(static_cast<int>(l1_data_misses));
    row.set_l1_data_hits(static_cast<int>(l1_data_hits));
    row.set_l1_inst_hits(static_cast<int>(l1_inst_hits));
    row.set_l1_inst_misses(static_cast<int>(l1_inst_misses));
    row.set_l1_data_ratio(l1_data_ratio);
    row.set_l1_inst_ratio(l1_inst_ratio);
    row.set_ll_hits(static_cast<int>(ll_hits));
    row.set_ll_misses(static_cast<int>(ll_misses));
    row.set_ll_ratio(ll_ratio);
}

bool
missing_instructions_t::print_results()
{
    std::cerr << TOOL_NAME << " finished.\n";
    return true;
}

void
missing_instructions_t::begin_transaction()
{
    char *errmsg;
    int rc = sqlite3_exec(db, "BEGIN TRANSACTION;", nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error beginning transaction: " << errmsg;
        // Handle error appropriately...
    }
    sqlite3_free(errmsg);
}

void
missing_instructions_t::open_database(const std::string &db_filename)
{
    int rc = sqlite3_open(db_filename.c_str(), &db);

    if (rc != SQLITE_OK) {
        std::cerr << "Cannot open database: " << sqlite3_errmsg(db);
        sqlite3_close(db);
        throw std::runtime_error("Failed to open database");
    }
}

void
missing_instructions_t::create_table()
{
    const char *sql_create_table = use_expanded_trace_format
        ? expanded_cachesim_row::create_table_string
        : cachesim_row::create_table_string;

    char *errmsg;
    int rc = sqlite3_exec(db, sql_create_table, nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << errmsg;
        sqlite3_free(errmsg);
        throw std::runtime_error("Failed to create table");
    } else {
        sqlite3_free(errmsg);
    }
}

void
missing_instructions_t::buffer_row(const std::unique_ptr<cachesim_row> &row)
{
    row_buffer.push_back(row);

    if (row_buffer.size() % 100000 == 0) {
        std::cout << "buffer at " << row_buffer.size() << std::endl;
    }
    if (row_buffer.size() >= max_buffer_size) { // Check if we've reached the buffer limit
        flush_buffer_to_database();
    }
}

void
missing_instructions_t::flush_buffer_to_database()
{
    std::cout << "Flushing buffer!" << std::endl;

    try {
        begin_transaction(); // Start the transaction

        // Preparing the SQL statement once, instead of re-preparing it for every row
        const char *sql_insert = use_expanded_trace_format
            ? expanded_cachesim_row::insert_row_string
            : cachesim_row::insert_row_string;

        sqlite3_stmt *stmt;
        int rc = sqlite3_prepare_v2(db, sql_insert, -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            std::stringstream ss;
            ss << "Cannot prepare insert statement: " << sqlite3_errmsg(db);
            std::string error_msg = ss.str();
            std::cerr << error_msg << std::endl;
            throw std::runtime_error(error_msg);
        }

        for (auto const &row : row_buffer) {
            row->insert_into_database(stmt);
            rc = sqlite3_step(stmt);
            if (rc != SQLITE_DONE) {
                std::stringstream ss;
                ss << "Insertion failed: " << sqlite3_errmsg(db);
                std::string error_msg = ss.str();
                std::cerr << error_msg << std::endl;
                throw std::runtime_error(error_msg);
            }
            // Reset the statement to reuse it for the next insert
            sqlite3_reset(stmt);
        }
        end_transaction(); // Commit the transaction
        std::cout << "Clearing buffer..." << std::endl;
    } catch (const std::exception &e) {
        std::cerr << "Exception occurred during flushing: " << e.what() << std::endl;
        throw;
    }
    row_buffer.clear(); // Clear the buffer for the next batch
    row_buffer.shrink_to_fit();
    std::vector<std::unique_ptr<cachesim_row>>().swap(row_buffer);
}

void
missing_instructions_t::end_transaction()
{
    char *errmsg;
    int rc = sqlite3_exec(db, "END TRANSACTION;", nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error ending transaction: " << errmsg;
        // Handle error appropriately...
    }
    sqlite3_free(errmsg);
}

void
missing_instructions_t::close_database()
{
    // After all rows have been buffered and you're done processing
    if (!row_buffer.empty()) {
        flush_buffer_to_database();
    }
    end_transaction(); // Clean up the prepared statement
    sqlite3_close(db);
}

} // namespace drmemtrace
} // namespace dynamorio
