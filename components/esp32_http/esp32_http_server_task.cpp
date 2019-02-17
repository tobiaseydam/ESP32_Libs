#include "esp32_http.hpp"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_log.h"

TaskHandle_t http_server_task::handle = NULL;

http_server_task::http_server_task(http_settings* as){
    ESP_LOGI("test", "%p", &as->get_settings_manager()->mapOfCategories);
    switch (as->get_http_server_class())
    {
        case DEFAULT_HTTP_SERVER:
            ESP_LOGI(TAG, "Creating default_http_server...");
            srv = new default_http_server(as);
            break;
        
        case HEIZUNGS_HTTP_SERVER:
            ESP_LOGI(TAG, "Creating heizung_http_server...");
            srv = new heizung_http_server(as);
            break;

        default:
            srv = new default_http_server(as);
            break;
    }
    
    xTaskCreate( startup_task, "SERVER_TASK", 4096, srv, tskIDLE_PRIORITY, &handle );
}

void http_server_task::startup_task(void* param){
    http_server* s = (http_server*)param;
    s->start();
    s->init();
    vTaskDelete(handle);
}