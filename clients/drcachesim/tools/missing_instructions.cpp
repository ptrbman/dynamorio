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

namespace dynamorio {
namespace drmemtrace {

const std::string missing_instructions_t::TOOL_NAME = "Missing_Instructions tool";

// TODO: fix this entire method.
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

        row.set_byte_count(memref.data.size);
        row.set_instr_type(name);
        return;
    }

    // TODO: see what's to be done here (based on the newest drio code) maybe
    app_pc decode_pc;
    const app_pc orig_pc = (app_pc)memref.instr.addr;
    // if (TESTANY(OFFLINE_FILE_TYPE_ENCODINGS, filetype_)) {
    // The trace has instruction encodings inside it.
    decode_pc = const_cast<app_pc>(memref.instr.encoding);
    // if (memref.instr.encoding_is_new) {
    //     // The code may have changed: invalidate the cache.
    //     disasm_cache_.erase(orig_pc);
    // } else {
    //     // Legacy trace support where we need the binaries.
    //     decode_pc = module_mapper_->find_mapped_trace_address(orig_pc);
    //     if (!module_mapper_->get_last_error().empty()) {
    //         error_string_ = "Failed to find mapped address for " +
    //             to_hex_string(memref.instr.addr) + ": " +
    //             module_mapper_->get_last_error();
    //         return false;
    //     }
    // }

    std::string disasm;
    // auto cached_disasm = disasm_cache_.find(orig_pc);
    //   if (cached_disasm != disasm_cache_.end()) {
    //       disasm = cached_disasm->second;
    //   } else {
    // MAX_INSTR_DIS_SZ is set to 196 in core/ir/disassemble.h but is not
    // exported so we just use the same value here.
    char buf[196];
    byte *next_pc =
        disassemble_to_buffer(dcontext_.dcontext, decode_pc, orig_pc, /*show_pc=*/false,
                              /*show_bytes=*/true, buf, BUFFER_SIZE_ELEMENTS(buf),
                              /*printed=*/nullptr);
    if (next_pc == nullptr) {
        error_string_ = "Failed to disassemble " + to_hex_string(memref.instr.addr);
        throw std::invalid_argument(error_string_);
    }
    disasm = buf;
    // disasm_cache_.insert({ orig_pc, disasm });
    //   }
    //   // Put our prefix on raw byte spillover, and skip the other columns.
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
    row.set_byte_count(memref.data.size);
}

analysis_tool_t *
missing_instructions_tool_create(const cache_simulator_knobs_t &knobs)
{
    return new missing_instructions_t(knobs);
}

missing_instructions_t::missing_instructions_t(const cache_simulator_knobs_t &knobs)
    : cache_simulator_t(knobs)
{
    
    csv_log_path = knobs_.cache_trace_log_path;
    std::cout << "Path for logging: " << csv_log_path << "\n";
    create_experiment_insert_statement(knobs_);
    curr_core_id = 0;
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
        experiments_file << "Experiment ID, L1D Size, L1I Size, Num Cores, "
                         << "L1I Assoc, L1D Assoc, LL Size, Line Size, LL Assoc, "
                         << "Model Coherence, Replace Policy, Skip Refs, Warmup Refs, "
                         << "Warmup Fraction, CPU Scheduling, Use Physical\n";
    }
    check_file.close();

    // Write experiment data to CSV
    experiments_file << experiment_id << ", " << (knobs.L1D_size / 1024) << "K, "
                     << (knobs.L1I_size / 1024) << "K, " << knobs.num_cores << ", "
                     << knobs.L1I_assoc << ", " << knobs.L1D_assoc << ", "
                     << (knobs.LL_size / (1024 * 1024)) << "M, " << knobs.line_size
                     << ", " << knobs.LL_assoc << ", " << (knobs.model_coherence ? 1 : 0)
                     << ", "
                     << "'" << knobs.replace_policy << "', " << knobs.skip_refs << ", "
                     << knobs.warmup_refs << ", " << knobs.warmup_fraction << ", " << 0
                     << ", " // Assuming 0 for Sim Refs as per  method
                     << (knobs.cpu_scheduling ? 1 : 0) << ", "
                     << (knobs.use_physical ? 1 : 0) << "\n";
    experiments_file.close();
    // Open the corresponding cache statistics CSV file
    cache_stats_filename = csv_log_path + "cache_stats_" + experiment_id + ".csv";
    std::cerr << "Printing cache stats file to " << cache_stats_filename << "\n";

    write_csv_header();
}

bool
missing_instructions_t::process_memref(const memref_t &memref)
{
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
        std::unique_ptr<cachesim_row> row(new cachesim_row());

        update_instruction_stats(core, thread_switch, core_switch, memref, *row);
        update_miss_stats(core, memref, *row);
        write_compressed_row_with_delta(*row);
        return true;
    } catch (const std::exception &ex) {
        std::cerr << "Issue occurred during disassembly of trace: " << ex.what();
        return false;
    }
}

void
missing_instructions_t::write_csv_header()
{
    try {
        if (!gz_cache_file)
            open_compressed_output();

        // Construct the output row with deltas
        std::stringstream ss;
        ss << "Instruction number, Access Address, PC Address, L1D Miss, L1I Miss, LL "
              "Miss, "
              "Instr Type, "
           << "Byte Count, Disassembly String, Current Instruction ID, Core, "
           << "Thread Switch, Core Switch, L1 Data Hits, L1 Data Misses, L1 Data Ratio, "
           << "L1 Inst Hits, L1 Inst Misses, L1 Inst Ratio, LL Hits, LL Misses, LL Ratio";

        // Write the constructed string to the compressed file
        write_compressed_row(ss.str());
    } catch (const std::exception &e) {
        std::cerr << "Exception: " << e.what();
        throw;
    }
}
void
missing_instructions_t::write_compressed_row_with_delta(const cachesim_row &row)
{
    try {
        if (!gz_cache_file)
            open_compressed_output();
        // Reset last addresses on thread switch
        if (row.get_thread_switch()) {
            last_pc_address = 0;
            last_access_address = 0;
        }
        // Convert addresses from string to numerical value for delta calculation
        addr_t current_pc = std::stoull(row.get_pc_address(), nullptr, 16);
        addr_t current_access = std::stoull(row.get_access_address(), nullptr, 16);

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
        std::stringstream ss;
        ss << current_instruction_id << ", " << delta_access << ", " << delta_pc << ", "
           << (row.get_l1d_miss() ? 1 : 0) << ", " << (row.get_l1i_miss() ? 1 : 0) << ", "
           << (row.get_ll_miss() ? 1 : 0) << ", " << row.get_instr_type() << ", "
           << static_cast<int>(row.get_byte_count()) << ", "
           << "\"" << row.get_disassembly_string() << "\", "
           << row.get_current_instruction_id() << ", " << row.get_core() << ", "
           << (row.get_thread_switch() ? 1 : 0) << ", " << (row.get_core_switch() ? 1 : 0)
           << ", " << row.get_l1_data_hits() << ", " << row.get_l1_data_misses() << ", "
           << row.get_l1_data_ratio() << ", " << row.get_l1_inst_hits() << ", "
           << row.get_l1_inst_misses() << ", " << row.get_l1_inst_ratio() << ", "
           << row.get_ll_hits() << ", " << row.get_ll_misses() << ", "
           << row.get_ll_ratio();

        // Write the constructed string to the compressed file
        write_compressed_row(ss.str());
    } catch (const std::exception &e) {
        std::cerr << "Exception: " << e.what();
        throw;
    }
}
void
missing_instructions_t::update_miss_stats(int core, const memref_t &memref,
                                          cachesim_row &row)
{

    int data_misses_l1_pre = cache_simulator_t::get_cache_metric(
        metric_name_t::MISSES, 0, core, cache_split_t::DATA);
    int inst_misses_l1_pre = cache_simulator_t::get_cache_metric(
        metric_name_t::MISSES, 0, core, cache_split_t::INSTRUCTION);
    int unified_misses_ll_pre = cache_simulator_t::get_cache_metric(
        metric_name_t::MISSES, 2, core, cache_split_t::DATA);

    // bool cache_ret = cache_simulator_t::process_memref(memref);
    cache_simulator_t::process_memref(memref);
    int data_misses_l1_post = cache_simulator_t::get_cache_metric(
        metric_name_t::MISSES, 0, core, cache_split_t::DATA);
    int inst_misses_l1_post = cache_simulator_t::get_cache_metric(
        metric_name_t::MISSES, 0, core, cache_split_t::INSTRUCTION);
    int unified_misses_ll_post = cache_simulator_t::get_cache_metric(
        metric_name_t::MISSES, 2, core, cache_split_t::DATA);

    int data_misses_l1 = data_misses_l1_post - data_misses_l1_pre;
    int inst_misses_l1 = inst_misses_l1_post - inst_misses_l1_pre;
    int unified_misses_ll = unified_misses_ll_post - unified_misses_ll_pre;

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

    addr_t pc, addr;
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

    std::stringstream ss;
    ss << std::setfill('0') << std::setw(16) << std::hex << addr; // Pad to 16 characters
    std::string address_hex = ss.str();
    ss.str("");
    ss.clear();

    ss << std::setfill('0') << std::setw(16) << std::hex << pc; // Pad to 16 characters
    std::string pc_hex = ss.str();

    row.set_pc_address(pc_hex);
    row.set_access_address(address_hex);
    row.set_l1d_miss(data_miss_l1);
    row.set_l1i_miss(inst_miss_l1);
    row.set_ll_miss(unified_miss_ll);

    get_opcode(memref, row);

    write_compressed_row_with_delta(row);
}

void
missing_instructions_t::update_instruction_stats(int core, bool thread_switch,
                                                 bool core_switch, const memref_t &memref,
                                                 cachesim_row &row)
{
    int l1_data_hits = cache_simulator_t::get_cache_metric(metric_name_t::HITS, 0, core,
                                                           cache_split_t::DATA);
    int l1_inst_hits = cache_simulator_t::get_cache_metric(metric_name_t::HITS, 0, core,
                                                           cache_split_t::INSTRUCTION);
    int l1_data_misses = cache_simulator_t::get_cache_metric(metric_name_t::MISSES, 0,
                                                             core, cache_split_t::DATA);
    int l1_inst_misses = cache_simulator_t::get_cache_metric(
        metric_name_t::MISSES, 0, core, cache_split_t::INSTRUCTION);
    int ll_hits = cache_simulator_t::get_cache_metric(metric_name_t::HITS, 2, core,
                                                      cache_split_t::DATA);
    int ll_misses = cache_simulator_t::get_cache_metric(metric_name_t::MISSES, 2, core,
                                                        cache_split_t::DATA);

    float l1_data_ratio = static_cast<float>(l1_data_misses) /
        static_cast<float>(l1_data_misses + l1_data_hits);
    float l1_inst_ratio = static_cast<float>(l1_inst_misses) /
        static_cast<float>(l1_inst_misses + l1_inst_hits);
    float ll_ratio =
        static_cast<float>(ll_misses) / static_cast<float>(ll_misses + ll_hits);

    row.set_current_instruction_id(current_instruction_id);
    row.set_core(core);
    row.set_thread_switch(thread_switch);
    row.set_core_switch(core_switch);
    row.set_l1_data_misses(l1_data_misses);
    row.set_l1_data_hits(l1_data_hits);
    row.set_l1_inst_hits(l1_inst_hits);
    row.set_l1_inst_misses(l1_inst_misses);
    row.set_l1_data_ratio(l1_data_ratio);
    row.set_l1_inst_ratio(l1_inst_ratio);
    row.set_ll_hits(ll_hits);
    row.set_ll_misses(ll_misses);
    row.set_ll_ratio(ll_ratio);
}

bool
missing_instructions_t::print_results()
{
    std::cerr << TOOL_NAME << " results:\n";
    cache_simulator_t::print_results();
    return true;
}

// Function to get the size of a file
long
missing_instructions_t::getFileSize(const std::string &fileName)
{
    struct stat stat_buf;
    int rc = stat(fileName.c_str(), &stat_buf);
    return rc == 0 ? stat_buf.st_size : -1;
}

void
missing_instructions_t::open_compressed_output()
{
    std::string compressed_filename = cache_stats_filename + ".gz";
    gz_cache_file = gzopen(compressed_filename.c_str(), "wb");
    if (!gz_cache_file) {
        throw std::runtime_error("Failed to open compressed output file");
    }
}

void
missing_instructions_t::write_compressed_row(const std::string &row)
{
    // Append the new row to the buffer
    write_buffer += row + "\n"; // Ensure newline is included

    // Check if buffer exceeds threshold and needs flushing
    if (write_buffer.size() >= buffer_threshold) {
        flush_buffer();
    }
}

void
missing_instructions_t::flush_buffer()
{
    if (!write_buffer.empty()) {
        // Write buffer to compressed file
        gzwrite(gz_cache_file, write_buffer.data(), write_buffer.size());
        write_buffer.clear(); // Reset buffer after writing
    }
}

void
missing_instructions_t::close_compressed_output()
{
    flush_buffer(); // Flush any remaining data in the buffer
    if (gz_cache_file) {
        gzclose(gz_cache_file); // Close the gzFile resource
        gz_cache_file = nullptr;
    }
}

} // namespace drmemtrace
} // namespace dynamorio
