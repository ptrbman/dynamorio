#include "expanded_cachesim_row.h"

namespace dynamorio {
namespace drmemtrace {

const char *expanded_cachesim_row::create_table_string =
    "CREATE TABLE IF NOT EXISTS cache_stats ("
    "instruction_number INTEGER, "
    "access_address_delta INTEGER, "
    "pc_address_delta INTEGER, "
    "l1d_miss INTEGER, "
    "l1i_miss INTEGER, "
    "ll_miss INTEGER, "
    "instr_type TEXT, "
    "byte_count INTEGER, "
    "disassembly_string TEXT, "
    "current_instruction_id INTEGER, "
    "core INTEGER, "
    "thread_switch INTEGER, "
    "core_switch INTEGER, "
    "l1_data_hits INTEGER, "
    "l1_data_misses INTEGER, "
    "l1_data_ratio REAL, "
    "l1_inst_hits INTEGER, "
    "l1_inst_misses INTEGER, "
    "l1_inst_ratio REAL, "
    "ll_hits INTEGER, "
    "ll_misses INTEGER, "
    "ll_ratio REAL);";

const char *expanded_cachesim_row::insert_row_string =
    "INSERT INTO cache_stats ("
    "instruction_number, "
    "access_address_delta, "
    "pc_address_delta, "
    "l1d_miss, "
    "l1i_miss, "
    "ll_miss, "
    "instr_type, "
    "byte_count, "
    "disassembly_string, "
    "current_instruction_id, "
    "core, "
    "thread_switch, "
    "core_switch, "
    "l1_data_hits, "
    "l1_data_misses, "
    "l1_data_ratio, "
    "l1_inst_hits, "
    "l1_inst_misses, "
    "l1_inst_ratio, "
    "ll_hits, "
    "ll_misses, "
    "ll_ratio"
    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
    "?, ?, ?, ?, ?, ?, ?);";

// Setters
void
expanded_cachesim_row::set_l1_data_hits(int value)
{
    l1_data_hits = value;
}
void
expanded_cachesim_row::set_l1_data_misses(int value)
{
    l1_data_misses = value;
}
void
expanded_cachesim_row::set_l1_data_ratio(float value)
{
    l1_data_ratio = value;
}
void
expanded_cachesim_row::set_l1_inst_hits(int value)
{
    l1_inst_hits = value;
}
void
expanded_cachesim_row::set_l1_inst_misses(int value)
{
    l1_inst_misses = value;
}
void
expanded_cachesim_row::set_l1_inst_ratio(float value)
{
    l1_inst_ratio = value;
}
void
expanded_cachesim_row::set_ll_hits(int value)
{
    ll_hits = value;
}
void
expanded_cachesim_row::set_ll_misses(int value)
{
    ll_misses = value;
}
void
expanded_cachesim_row::set_ll_ratio(float value)
{
    ll_ratio = value;
}

// Getters
int
expanded_cachesim_row::get_l1_data_hits() const
{
    return l1_data_hits;
}
int
expanded_cachesim_row::get_l1_data_misses() const
{
    return l1_data_misses;
}
float
expanded_cachesim_row::get_l1_data_ratio() const
{
    return l1_data_ratio;
}
int
expanded_cachesim_row::get_l1_inst_hits() const
{
    return l1_inst_hits;
}
int
expanded_cachesim_row::get_l1_inst_misses() const
{
    return l1_inst_misses;
}
float
expanded_cachesim_row::get_l1_inst_ratio() const
{
    return l1_inst_ratio;
}
int
expanded_cachesim_row::get_ll_hits() const
{
    return ll_hits;
}
int
expanded_cachesim_row::get_ll_misses() const
{
    return ll_misses;
}
float
expanded_cachesim_row::get_ll_ratio() const
{
    return ll_ratio;
}

} // namespace drmemtrace
} // namespace dynamorio