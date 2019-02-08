#include "esp32_ip.hpp"

eth_settings::eth_settings(){
    set_l2p(ETH);
}

eth_settings::eth_settings(const eth_settings &s){
    l2p = s.l2p;
    got_ip_callback = s.got_ip_callback;
    got_ip_callback_set = s.got_ip_callback_set;
    got_ip_callback_ctx = s.got_ip_callback_ctx;
    event_group = s.event_group;
}