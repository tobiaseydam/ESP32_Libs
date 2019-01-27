#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"

extern "C" {
    void app_main(void);
}

void app_main(void){
    ESP_LOGI("main", "Hello World");
}