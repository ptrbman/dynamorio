#ifndef _CACHE_SIMULATOR_ROW_H_
#define _CACHE_SIMULATOR_ROW_H_ 1

#include <iostream>
#include "memref.h"
namespace dynamorio {
namespace drmemtrace {
/// @brief Class contains data used for inserting new execution row into a DB.
class cachesim_row {
protected:
    /* data */
    addr_t access_address;
    addr_t pc_address;
    int access_address_delta;
    int pc_address_delta;
    bool l1d_miss;
    bool l1i_miss;
    bool ll_miss;
    std::string instr_type = "";
    uint8_t byte_count;
    std::string disassembly_string;
    int current_instruction_id;
    uint8_t core;
    bool thread_switch;
    bool core_switch;


public:
    // Setters declarations
    void
    set_access_address(const addr_t value);
    void
    set_pc_address(const addr_t value);
    void
    set_access_address_delta(int value);
    void
    set_pc_address_delta(int value);
    void
    set_l1d_miss(bool value);
    void
    set_l1i_miss(bool value);
    void
    set_ll_miss(bool value);
    void
    set_instr_type(const std::string &value);
    void
    set_byte_count(uint8_t value);
    void
    set_disassembly_string(const std::string &value);
    void
    set_current_instruction_id(int value);
    void
    set_core(uint8_t value);
    void
    set_thread_switch(bool value);
    void
    set_core_switch(bool value);

    // Getters declarations
    addr_t
    get_access_address() const;
    addr_t
    get_pc_address() const;
    int
    get_access_address_delta() const;
    int
    get_pc_address_delta() const;
    bool
    get_l1d_miss() const;
    bool
    get_l1i_miss() const;
    bool
    get_ll_miss() const;
    std::string
    get_instr_type() const;
    uint8_t
    get_byte_count() const;
    std::string
    get_disassembly_string() const;
    int
    get_current_instruction_id() const;
    uint8_t
    get_core() const;
    bool
    get_thread_switch() const;
    bool
    get_core_switch() const;
};


} // namespace drmemtrace
} // namespace dynamorio
#endif /*_CACHE_SIMULATOR_ROW_H*/