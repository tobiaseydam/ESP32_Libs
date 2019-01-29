#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"

#include "esp32_ip.hpp"
#include "esp32_http.hpp"

extern "C" {
    void app_main(void);
}

void app_main(void){
    eth_settings eth_s;

    http_settings srv_s;
    http_server srv(srv_s);

    eth_s.set_got_ip_callback([](void *ctx){
        http_server* srv = (http_server*) ctx;
        ESP_LOGI("main", "Online :)");
        srv->start();
        srv->example();
    }, &srv);

    eth_adapter eth(eth_s);
    eth.init();
    eth.start();
}