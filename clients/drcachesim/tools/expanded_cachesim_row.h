#ifndef _EXPANDED_CACHE_SIMULATOR_ROW_H_
#define _EXPANDED_CACHE_SIMULATOR_ROW_H_ 1

#include <iostream>
#include "memref.h"
#include "cachesim_row.h"

namespace dynamorio {
namespace drmemtrace {
/// @brief Class contains data used for inserting new execution row into a DB.
class expanded_cachesim_row : public cachesim_row {
private:
    /* data */
    int l1_data_hits;
    int l1_data_misses;
    float l1_data_ratio;
    int l1_inst_hits;
    int l1_inst_misses;
    float l1_inst_ratio;
    int ll_hits;
    int ll_misses;
    float ll_ratio;

public:
    // Setters declarations
    void
    set_l1_data_hits(int value);
    void
    set_l1_data_misses(int value);
    void
    set_l1_data_ratio(float value);
    void
    set_l1_inst_hits(int value);
    void
    set_l1_inst_misses(int value);
    void
    set_l1_inst_ratio(float value);
    void
    set_ll_hits(int value);
    void
    set_ll_misses(int value);
    void
    set_ll_ratio(float value);

    // Getters declarations
    int
    get_l1_data_hits() const;
    int
    get_l1_data_misses() const;
    float
    get_l1_data_ratio() const;
    int
    get_l1_inst_hits() const;
    int
    get_l1_inst_misses() const;
    float
    get_l1_inst_ratio() const;
    int
    get_ll_hits() const;
    int
    get_ll_misses() const;
    float
    get_ll_ratio() const;

    static constexpr char* create_table_string =
        "CREATE TABLE IF NOT EXISTS cache_stats ("
        "instruction_number INTEGER PRIMARY KEY, "
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

    static constexpr char* insert_row_string =
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
};

} // namespace drmemtrace
} // namespace dynamorio
#endif /*_EXPANDED_CACHE_SIMULATOR_ROW_H*/