#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"

#include "esp32_wifi.hpp"

extern "C" {
    void app_main(void);
}

void app_main(void){
    ESP_LOGI("main", "Hello World");
    wifi_settings s;
    ESP_LOGI("main", "%s", s.get_ssid().c_str());
    
}