#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/queue.h"
#include "esp_event_loop.h"
#include "esp_system.h"
#include "esp_log.h"
#include "rom/ets_sys.h"

#include "defines.hpp"

#include "esp32_ip.hpp"
#include "esp32_http.hpp"
#include "esp32_storage.hpp"
#include "esp32_onewire.hpp"
#include "esp32_logger.hpp"
#include "esp32_time.hpp"
#include "esp32_aws.hpp"
#include "esp32_settings.hpp"

#include <string>

extern "C" {
    void app_main(void);
}


EventGroupHandle_t ip_event_group;

void app_main(void){

    ip_event_group = xEventGroupCreate();

    storage_adapter stor;
    stor.init();

    settings_manager_heizung* sm = new settings_manager_heizung;
    sm->load();
    
    eth_settings eth_s;
    eth_s.set_event_group(ip_event_group);

    eth_adapter eth(eth_s);
    eth.init();
    eth.start();

    http_settings* srv_s = new http_settings;
    srv_s->set_event_group(ip_event_group);
    srv_s->set_http_server_class(HEIZUNGS_HTTP_SERVER);
    srv_s->set_settings_manager(sm);
    srv_s->set_root_folder(stor.get_root_folder_name());

    http_server_task hst(srv_s);
    
    //system_clock_task sct(ip_event_group);

    //onewire_adapter* ow = new onewire_adapter(17);
    //onewire_logger owl;
    //owl.run(ow);

    //log_config lc;

    //log_manager l(lc);
    //ow->get_log_elements(l.get_list());

    while(false){
        //string s = l.json_elements_to_string();
        //ESP_LOGI("test", "%s", s.c_str());
        //vTaskDelay(pdMS_TO_TICKS(2000));
    }
    
    xEventGroupWaitBits(ip_event_group, GOT_IP_BIT, false, true, portMAX_DELAY);
    //aws_task aws;
    //aws.run();
    //vTaskDelay(pdMS_TO_TICKS(10000));
    
    //system_clock c;
    

}