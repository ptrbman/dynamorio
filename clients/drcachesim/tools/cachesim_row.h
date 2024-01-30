#ifndef _CACHE_SIMULATOR_ROW_H_
#    define _CACHE_SIMULATOR_H_ 1

#    include <iostream>
namespace dynamorio {
namespace drmemtrace {
/// @brief Class contains data used for inserting new execution row into a DB.
class cachesim_row {
private:
    /* data */
    std::string access_address;
    std::string pc_address;
    bool l1d_miss;
    bool l1i_miss;
    bool ll_miss;
    std::string instr_type;
    uint8_t byte_count;
    std::string disassembly_string;
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

public:
    // cachesim_row(/* args */);
    // ~cachesim_row();

    // Setters declarations
    void
    set_access_address(const std::string &value);
    void
    set_pc_address(const std::string &value);
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
    set_core(int value);
    void
    set_thread_switch(bool value);
    void
    set_core_switch(bool value);
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
    std::string
    get_access_address() const;
    std::string
    get_pc_address() const;
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
    int
    get_core() const;
    bool
    get_thread_switch() const;
    bool
    get_core_switch() const;
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
};

// cachesim_row::cachesim_row(/* args */)
// {
// }

// cachesim_row::~cachesim_row()
// {
// }
} // namespace drmemtrace
} // namespace dynamorio
#endif /*_CACHE_SIMULATOR_ROW_H*/