#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "freertos/queue.h"
#include "rom/ets_sys.h"

#include "esp32_ip.hpp"
#include "esp32_http.hpp"
#include "esp32_storage.hpp"
#include "esp32_onewire.hpp"
#include "esp32_logger.hpp"

#include <string>

extern "C" {
    void app_main(void);
}

void app_main(void){
    #ifdef GIT_VERSION
        string version = GIT_VERSION;
        ESP_LOGI("test", "Version: %s", version.c_str());
    #endif   

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

    onewire_adapter* ow = new onewire_adapter(17);

    onewire_logger owl;
    owl.run(ow);

    log_manager l;
    ow->get_log_elements(l.get_list());

    while(true){
        string s = l.json_elements_to_string();
        ESP_LOGI("test", "%s", s.c_str());
        vTaskDelay(pdMS_TO_TICKS(2000));
    }

}