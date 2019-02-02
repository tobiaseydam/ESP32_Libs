#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"

#include "esp32_ip.hpp"
#include "esp32_http.hpp"
#include "esp32_storage.hpp"

extern "C" {
    void app_main(void);
}

void app_main(void){
    storage_adapter stor;
    stor.init();

    eth_settings eth_s;

    http_settings srv_s;
    default_http_server *srv = new default_http_server(srv_s, stor.get_root_folder_name());

    eth_s.set_got_ip_callback([](void *ctx){
        default_http_server* srv = (default_http_server*) ctx;
        ESP_LOGI("main", "Online :)");
        srv->start();
        srv->init();
    }, srv);

    eth_adapter eth(eth_s);
    eth.init();
    eth.start();
}