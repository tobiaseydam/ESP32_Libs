#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"

#include "esp32_ip.hpp"

extern "C" {
    void app_main(void);
}

void app_main(void){
    eth_settings s = eth_settings();
    eth_adapter e(s);
    e.init();
    e.start();
}