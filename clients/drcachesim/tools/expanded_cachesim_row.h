#ifndef _EXPANDED_CACHE_SIMULATOR_ROW_H_
#define _EXPANDED_CACHE_SIMULATOR_ROW_H_ 1

#include <iostream>
#include "memref.h"
#include "cachesim_row.h"
#include "sqlite3.h"

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
    expanded_cachesim_row(long l1_data_misses, long l1_data_hits, long l1_inst_hits,
                          long l1_inst_misses, long ll_hits, long ll_misses,
                          float l1_data_ratio, float l1_inst_ratio, float ll_ratio,
                          int current_instruction_id, int core, bool thread_switch,
                          bool core_switch);
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

    static const char *create_table_string;

    static const char *insert_row_string;

    void
    insert_into_database(sqlite3_stmt *stmt) const override;
};

} // namespace drmemtrace
} // namespace dynamorio
#endif /*_EXPANDED_CACHE_SIMULATOR_ROW_H*/