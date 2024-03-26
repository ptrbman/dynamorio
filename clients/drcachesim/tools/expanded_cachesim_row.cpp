#include "expanded_cachesim_row.h"

namespace dynamorio {
namespace drmemtrace {
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