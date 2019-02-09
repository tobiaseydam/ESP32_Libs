#include "esp32_http.hpp"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

TaskHandle_t http_server_task::handle = NULL;

http_server_task::http_server_task(http_settings as, string root_folder_name){
    srv = new default_http_server(as, root_folder_name);
    xTaskCreate( startup_task, "SERVER_TASK", 2048, srv, tskIDLE_PRIORITY, &handle );
}

void http_server_task::startup_task(void* param){
    default_http_server* s = (default_http_server*)param;
    s->start();
    s->init();
    vTaskDelete(handle);
}