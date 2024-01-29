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
#include <mysql_driver.h>
#include <mysql_connection.h>
#include <cppconn/prepared_statement.h>

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <memory>
#include <vector>
#include <stdexcept>
#include "memref.h"
#include "memtrace_stream.h"
#include "raw2trace.h"
#include "raw2trace_directory.h"

namespace dynamorio {
namespace drmemtrace {

const std::string missing_instructions_t::TOOL_NAME = "Missing_Instructions tool";

// TODO: Fix this entire method.
bool
missing_instructions_t::get_opcode(const memref_t &memref)
{

    static constexpr int name_width = 12;
    if (!type_is_instr(memref.instr.type) &&
        memref.data.type != TRACE_TYPE_INSTR_NO_FETCH) {

        std::string name;
        switch (memref.data.type) {
        default: return std::string("<entry type " + memref.data.type) + ">\n";
        case TRACE_TYPE_THREAD_EXIT:
            return std::string("<thread " + memref.data.tid) + " exited>\n";

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
        std::cerr << std::left << std::setw(name_width) << name << std::right
                  << std::setw(2) << memref.data.size << " byte(s) @ 0x" << std::hex
                  << std::setfill('0') << std::setw(sizeof(void *) * 2)
                  << memref.data.addr << " by PC 0x" << std::setw(sizeof(void *) * 2)
                  << memref.data.pc << std::dec << std::setfill(' ') << "\n";
        return true;
    }

    std::cerr << std::left << std::setw(name_width) << "ifetch" << std::right
              << std::setw(2) << memref.instr.size << " byte(s) @ 0x" << std::hex
              << std::setfill('0') << std::setw(sizeof(void *) * 2) << memref.instr.addr
              << std::dec << std::setfill(' ');
    //   if (!TESTANY(OFFLINE_FILE_TYPE_ENCODINGS, filetype_) && !has_modules_) {
    //       // We can't disassemble so we provide what info the trace itself contains.
    //       // XXX i#5486: We may want to store the taken target for conditional
    //       // branches; if added, we can print it here.
    //       // XXX: It may avoid initial confusion over the record-oriented output
    //       // to indicate whether an instruction accesses memory, but that requires
    //       // delayed printing.
    //       std::cerr << " ";
    //       switch (memref.instr.type) {
    //       case TRACE_TYPE_INSTR: std::cerr << "non-branch\n"; break;
    //       case TRACE_TYPE_INSTR_DIRECT_JUMP: std::cerr << "jump\n"; break;
    //       case TRACE_TYPE_INSTR_INDIRECT_JUMP: std::cerr << "indirect jump\n"; break;
    //       case TRACE_TYPE_INSTR_CONDITIONAL_JUMP: std::cerr << "conditional jump\n";
    //       break; case TRACE_TYPE_INSTR_DIRECT_CALL: std::cerr << "call\n"; break; case
    //       TRACE_TYPE_INSTR_INDIRECT_CALL: std::cerr << "indirect call\n"; break; case
    //       TRACE_TYPE_INSTR_RETURN: std::cerr << "return\n"; break; case
    //       TRACE_TYPE_INSTR_NO_FETCH: std::cerr << "non-fetched instruction\n"; break;
    //       case TRACE_TYPE_INSTR_SYSENTER: std::cerr << "sysenter\n"; break;
    //       default: error_string_ = "Uknown instruction type\n"; return false;
    //       }
    //       ++num_disasm_instrs_;
    //       return true;
    //   }

    app_pc decode_pc;
    const app_pc orig_pc = (app_pc)memref.instr.addr;
    // if (TESTANY(OFFLINE_FILE_TYPE_ENCODINGS, filetype_)) {
    // The trace has instruction encodings inside it.
    decode_pc = const_cast<app_pc>(memref.instr.encoding);
    if (memref.instr.encoding_is_new) {
        // The code may have changed: invalidate the cache.
        // disasm_cache_.erase(orig_pc);
    }
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
        return false;
    }
    disasm = buf;
    // disasm_cache_.insert({ orig_pc, disasm });
    //   }
    //   // Put our prefix on raw byte spillover, and skip the other columns.
    auto newline = disasm.find('\n');
    if (newline != std::string::npos && newline < disasm.size() - 1) {
        std::stringstream prefix;
        // print_prefix(memstream, memref, -1, prefix);
        std::string skip_name(name_width, ' ');
        disasm.insert(newline + 1,
                      prefix.str() + skip_name + "                               ");
    }
    std::cerr << disasm;
    //   ++num_disasm_instrs_;
    return true;
}

analysis_tool_t *
missing_instructions_tool_create(const cache_simulator_knobs_t &knobs)
{
    return new missing_instructions_t(knobs);
}
// missing_instructions_tool_create(const std::string &module_file_path, memref_tid_t
// thread,
//                  uint64_t skip_refs, uint64_t sim_refs, const std::string &syntax,
//                  unsigned int verbose, const std::string &alt_module_dir)
// {
//     return new missing_instructions_t(module_file_path, thread, skip_refs, sim_refs,
//     syntax, verbose,
//                       alt_module_dir);
// }

missing_instructions_t::missing_instructions_t(const cache_simulator_knobs_t &knobs)
    : cache_simulator_t(knobs)
{
    last_experiment_id = insert_new_experiment(knobs);
}

int
missing_instructions_t::insert_new_experiment(const cache_simulator_knobs_t &knobs)
{
    try {
        sql::mysql::MySQL_Driver *driver = sql::mysql::get_mysql_driver_instance();
        std::unique_ptr<sql::Connection> conn(
            driver->connect("tcp://db:3306", "root", "cta"));
        conn->setSchema("test_db_1");

        std::unique_ptr<sql::PreparedStatement> pstmt(
            conn->prepareStatement(create_experiment_insert_statement(knobs)));

        pstmt->executeUpdate();

        std::unique_ptr<sql::Statement> stmt(conn->createStatement());

        // Get the last insert id
        std::unique_ptr<sql::ResultSet> res(
            stmt->executeQuery("SELECT LAST_INSERT_ID()"));
        if (res->next()) {
            return res->getInt64(1); // The first column in the result set
        } else {
            return -1;
        }
    } catch (sql::SQLException &e) {
        std::cerr << "SQLException: " << e.what();
        return -1;
    }
}

std::string
missing_instructions_t::create_experiment_insert_statement(
    const cache_simulator_knobs_t &knobs)
{
    std::stringstream ss;
    ss << "INSERT INTO experiments ("
       << "l1d_size, l1i_size, num_cores, l1i_assoc, l1d_assoc, "
       << "ll_size, line_size, ll_assoc, model_coherence, replace_policy, "
       << "skip_refs, warmup_refs, warmup_fraction, sim_refs, cpu_scheduling, "
       << "use_physical, verbose"
       << ") VALUES ("
       << "'" << (knobs.L1D_size / 1024) << "K', "
       << "'" << (knobs.L1I_size / 1024) << "K', " << knobs.num_cores << ", "
       << knobs.L1I_assoc << ", " << knobs.L1D_assoc << ", "
       << "'" << (knobs.LL_size / (1024 * 1024)) << "M', " << knobs.line_size << ", "
       << knobs.LL_assoc << ", " << (knobs.model_coherence ? "TRUE" : "FALSE") << ", "
       << "'" << knobs.replace_policy << "', " << knobs.skip_refs << ", "
       << knobs.warmup_refs << ", " << knobs.warmup_fraction << ", " << knobs.sim_refs
       << ", " << (knobs.cpu_scheduling ? "TRUE" : "FALSE") << ", "
       << (knobs.use_physical ? "TRUE" : "FALSE") << ", " << knobs.verbose << ");";
    return ss.str();
}

bool
missing_instructions_t::process_memref(const memref_t &memref)
{
    current_instruction_id++;

    int core;
    bool thread_switch = false;
    bool core_switch = false;
    if (memref.data.tid == last_thread_)
        core = last_core_index_;
    else {
        core = core_for_thread(memref.data.tid);
        last_thread_ = memref.data.tid;
        std::cout << "< CORE_SWITCH_FROM_" << last_core_ << "_TO_" << core << " >"
                  << std::endl;
        thread_switch = true;
        if (core != last_thread_)
            core_switch = true;
        last_core_index_ = core;
    }

    std::unique_ptr<cachesim_row> row = std::make_unique<cachesim_row>();

    print_instr_stats(core, thread_switch, core_switch, memref, *row);
    print_miss_stats_and_run_cache_instr_sim(core, memref, *row);
    insert_new_row(*row);
    return "";
}

void
missing_instructions_t::insert_new_row(const cachesim_row &row)
{
    try {
        std::unique_ptr<sql::mysql::MySQL_Driver> driver(
            sql::mysql::get_mysql_driver_instance());
        std::unique_ptr<sql::Connection> conn(
            driver->connect("tcp://HOST:3306", "USERNAME", "PASSWORD"));
        conn->setSchema("DATABASE_NAME");

        std::unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement(
            "INSERT INTO cache_stats (core, thread_switch, core_switch, l1_data_hits, "
            "...) VALUES (?, ?, ?, ?, ...)"));

        pstmt->setInt(1, core);
        pstmt->setInt(2, thread_switch);
        // Set the rest of the parameters similarly
        pstmt->executeUpdate();
    } catch (sql::SQLException &e) {
        std::cerr << "SQLException: " << e.what();
    }
}

missing_instructions_t::miss_counts
missing_instructions_t::print_miss_stats_and_run_cache_instr_sim(int core,
                                                                 const memref_t &memref,
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
    ss << std::hex << addr;
    std::string address_hex = ss.str();
    ss << std::hex << pc;
    std::string pc_hex = ss.str();

    std::cerr << "[Access address: " << address_hex << "]";
    std::cerr << "[PC: " << pc_hex << "]";
    std::cerr << "[L1D miss: " << data_miss_l1 << "]";
    std::cerr << "[L1I miss: " << inst_miss_l1 << "]";
    std::cerr << "[LL miss: " << unified_miss_ll << "]";

    get_opcode(memref);
    missing_instructions_t::miss_counts counts;
    return counts;
}

missing_instructions_t::cache_metric_statistics
missing_instructions_t::print_instr_stats(int core, bool thread_switch, bool core_switch,
                                          const memref_t &memref, cachesim_row &row)
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

    missing_instructions_t::cache_metric_statistics stats;
    stats.current_instruction_id = current_instruction_id;
    stats.core = core;
    stats.thread_switch = thread_switch;
    stats.core_switch = core_switch;
    stats.l1_data_misses = l1_data_misses;
    stats.l1_data_hits = l1_data_hits;
    stats.l1_inst_hits = l1_inst_hits;
    stats.l1_inst_misses = l1_inst_misses;
    stats.l1_data_ratio = l1_data_ratio;
    stats.l1_inst_ratio = l1_inst_ratio;
    stats.ll_hits = ll_hits;
    stats.ll_misses = ll_misses;
    stats.ll_ratio = ll_ratio;

    return stats;
}

// TODO: implement this
// void insertStatsToDatabase(/* Parameters representing each stat */)
// {
//     try {
//         sql::mysql::MySQL_Driver *driver = sql::mysql::get_mysql_driver_instance();
//         std::unique_ptr<sql::Connection> conn(
//             driver->connect("tcp://HOST:3306", "USERNAME", "PASSWORD"));
//         conn->setSchema("DATABASE_NAME");

//         std::unique_ptr<sql::PreparedStatement> pstmt(conn->prepareStatement(
//             "INSERT INTO cache_stats (core, thread_switch, core_switch, l1_data_hits, "
//             "...) VALUES (?, ?, ?, ?, ...)"));

//         pstmt->setInt(1, core);
//         pstmt->setInt(2, thread_switch);
//         // Set the rest of the parameters similarly
//         pstmt->executeUpdate();
//     } catch (sql::SQLException &e) {
//         std::cerr << "SQLException: " << e.what();
//     }
// }

bool
missing_instructions_t::print_results()
{
    std::cerr << TOOL_NAME << " results:\n";
    cache_simulator_t::print_results();
    // std::cerr << std::setw(15) << num_disasm_instrs_ << " : total instructions\n";
    return true;
}

} // namespace drmemtrace
} // namespace dynamorio
