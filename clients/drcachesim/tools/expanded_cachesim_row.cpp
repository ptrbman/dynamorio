#include "expanded_cachesim_row.h"

namespace dynamorio {
namespace drmemtrace {

// Justification for too many params: Class holds data.
expanded_cachesim_row::expanded_cachesim_row(long l1_data_misses, long l1_data_hits,
                                             long l1_inst_hits, long l1_inst_misses,
                                             long ll_hits, long ll_misses,
                                             float l1_data_ratio, float l1_inst_ratio,
                                             float ll_ratio, int current_instruction_id,
                                             int core, bool thread_switch,
                                             bool core_switch)
    : cachesim_row(current_instruction_id, core, thread_switch, core_switch)
    , l1_data_hits(static_cast<int>(l1_data_hits))
    , l1_data_misses(static_cast<int>(l1_data_misses))
    , l1_data_ratio(l1_data_ratio)
    , l1_inst_hits(static_cast<int>(l1_inst_hits))
    , l1_inst_misses(static_cast<int>(l1_inst_misses))
    , l1_inst_ratio(l1_inst_ratio)
    , ll_hits(static_cast<int>(ll_hits))
    , ll_misses(static_cast<int>(ll_misses))
    , ll_ratio(ll_ratio)
{
}

void
expanded_cachesim_row::insert_into_database(sqlite3_stmt *stmt) const
{
    try {

        // Bind values from 'row' to the prepared SQL statement
        sqlite3_bind_int(stmt, 1, get_current_instruction_id());
        sqlite3_bind_int(stmt, 2, get_access_address_delta());
        sqlite3_bind_int(stmt, 3, get_pc_address_delta());
        sqlite3_bind_int(stmt, 4, get_l1d_miss() ? 1 : 0);
        sqlite3_bind_int(stmt, 5, get_l1i_miss() ? 1 : 0);
        sqlite3_bind_int(stmt, 6, get_ll_miss() ? 1 : 0);
        sqlite3_bind_text(stmt, 7, get_instr_type().c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 8, get_byte_count());
        sqlite3_bind_text(stmt, 9, get_disassembly_string().c_str(), -1,
                          SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 10, get_current_instruction_id());
        sqlite3_bind_int(stmt, 11, get_core());
        sqlite3_bind_int(stmt, 12, get_thread_switch() ? 1 : 0);
        sqlite3_bind_int(stmt, 13, get_core_switch() ? 1 : 0);
        sqlite3_bind_int(stmt, 14, get_l1_data_hits());
        sqlite3_bind_int(stmt, 15, get_l1_data_misses());
        sqlite3_bind_double(stmt, 16, get_l1_data_ratio());
        sqlite3_bind_int(stmt, 17, get_l1_inst_hits());
        sqlite3_bind_int(stmt, 18, get_l1_inst_misses());
        sqlite3_bind_double(stmt, 19, get_l1_inst_ratio());
        sqlite3_bind_int(stmt, 20, get_ll_hits());
        sqlite3_bind_int(stmt, 21, get_ll_misses());
        sqlite3_bind_double(stmt, 22, get_ll_ratio());

    } catch (const std::exception &e) {
        std::cerr << "Exception: " << e.what() << std::endl;
        throw;
    }
}

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