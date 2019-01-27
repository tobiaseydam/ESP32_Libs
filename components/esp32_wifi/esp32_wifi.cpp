#include "esp32_wifi.hpp"
#include "esp_log.h"

wifi_settings::wifi_settings(){
    ESP_LOGI(TAG, "empty wifi setting created");
}

wifi_settings::wifi_settings(wifi_station_mode a_mode, std::string a_ssid, std::string a_pass){
    mode = a_mode;
    ssid = a_ssid;
    pass = a_pass;
    ESP_LOGI(TAG, "standard wifi setting created");
}