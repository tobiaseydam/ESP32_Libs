#include "esp32_mqtt.hpp"

void mqtt_payload::add_string(std::string str){
    uint16_t l = str.length();
    pl[0+len] = (uint8_t) (l>>8);
    pl[1+len] = (uint8_t) (l&0xFF);
    memcpy(pl + 2 + len, str.c_str(), l);
    len += l + 2;
}

void mqtt_payload::set_string_no_len(std::string str){
    uint16_t l = str.length();
    memcpy(pl, str.c_str(), l);
    one_string = true;
    len += l;
}

void mqtt_payload::explain(){
    if(one_string){
        char str[256];
        strncpy(str, (const char*)pl, len);
        ESP_LOGI(TAG, "String: %s", str);
    }else{
        uint16_t i = 0;
        while(i<len){
            uint16_t str_len = (pl[i]<<8) + pl[i+1];
            i += 2;
            if(i>0){
                char str[256];
                strncpy(str, (const char*)pl+i, str_len);
                str[str_len] = 0;
                ESP_LOGI(TAG, "String (%d): %s", str_len, str);
            }
            i += str_len;
        }
    }
}