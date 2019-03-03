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
//#include "esp32_onewire.hpp"
//#include "esp32_logger.hpp"
//#include "esp32_time.hpp"
//#include "esp32_aws.hpp"
#include "esp32_mqtt.hpp"
#include "esp32_settings.hpp"
#include "esp32_tls.hpp"

#include <string> 

extern "C" {
    void app_main(void);
}


EventGroupHandle_t ip_event_group;

void aws_task(void* param){
    tls_layer* tls = new tls_layer();
    tls->set_root_ca_file("/spiffs/root-ca-cert.pem");
    tls->set_cert_pem_file("/spiffs/certificate.pem.crt");
    tls->set_private_key_pem_file("/spiffs/private.pem.key");
    tls->set_hostname("a38mp4h6o8iiol-ats.iot.us-east-1.amazonaws.com");
    tls->set_port("8883");

    mqtt_client* mqtt_cl = new mqtt_client(tls);

    tls->tls_connect(mqtt_cl);

    mqtt_cl->init();
    char* temp = new char[50];
    //sprintf(temp, "ESP32_3C-71-BF-96-DF-C0");
    sprintf(temp, "ESP32_%x", esp_random());
    ESP_LOGI("test", "client: %s", temp);
    std::string clientName = temp;
    mqtt_cl->set_client_name(clientName);
    mqtt_cl->set_clean_session(true);
    
    mqtt_cl->connect();
    
    while(1){
        ESP_LOGI("test", ".");
        mqtt_cl->publish("a/b", "test_payload", eQOS0);
        vTaskDelay(pdMS_TO_TICKS(15000));
    }
    

    vTaskDelete(NULL);
}

void app_main(void){
    //uint32_t freeRAM = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    //ESP_LOGI("TAG", "free RAM is %d.", freeRAM);
   
    ip_event_group = xEventGroupCreate();

    storage_adapter stor;
    stor.init();

    settings_manager_heizung* sm = new settings_manager_heizung;
    sm->init();
    sm->load();
    
    eth_settings eth_s;
    eth_s.set_event_group(ip_event_group);

    eth_adapter eth(eth_s);
    eth.init();
    eth.start();
    /*
    http_settings* srv_s = new http_settings;
    srv_s->set_event_group(ip_event_group);
    srv_s->set_http_server_class(HEIZUNGS_HTTP_SERVER);
    srv_s->set_settings_manager(sm);
    srv_s->set_root_folder(stor.get_root_folder_name());

    http_server_task hst(srv_s);
    */
    //system_clock_task sct(ip_event_group);

    
    
    xEventGroupWaitBits(ip_event_group, GOT_IP_BIT, false, true, portMAX_DELAY);
    //websocket_server wss(3333);
    //wss.run();

    TaskHandle_t aws = NULL;
    xTaskCreate( aws_task, "CONNECT TASK", 8196, NULL, tskIDLE_PRIORITY, &aws );   
    

    //tls_client tls_cl;
    //tls_layer* tls = new tls_layer();
    //tls->set_root_ca_file("/spiffs/root-ca-cert.pem");
    //tls->set_cert_pem_file("/spiffs/certificate.pem.crt");
    //tls->set_private_key_pem_file("/spiffs/private.pem.key");
    //tls->set_hostname("a38mp4h6o8iiol-ats.iot.us-east-1.amazonaws.com");
    //tls->set_port("8883");

    //mqtt_client* mqtt_cl = new mqtt_client(tls);

    //tls->tls_connect(mqtt_cl);
    //tls_cl.connect(mqtt_cl);
    /*
    xEventGroupWaitBits(tls->get_event_group(), TLS_EG_CONNECTED, false, true, portMAX_DELAY);

    
    
    mqtt_cl->set_client_name("ESP32_3C-71-BF-96-DF-C0");
    //mqtt_cl->set_client_name("python_test");
    mqtt_cl->set_clean_session(true);
    mqtt_cl->connect();
    while(1){
        vTaskDelay(pdMS_TO_TICKS(5000));
        mqtt_cl->publish("test_topic/a", "test_payload", eQOS0);
    }
    */

    //aws_task aws(sm);
    //aws.run();
    //while(true){
    //    vTaskDelay(pdMS_TO_TICKS(10000));
    //    aws.pl->add_msg("{\"HELLO\":\"WORLD\"}");
    //}
/*
    onewire_adapter* ow = new onewire_adapter(17);
    onewire_logger owl;
    owl.run(ow);

    log_config lc;

    log_manager l(lc);
    ow->get_log_elements(l.get_list());

    while(true){
        string s = l.json_elements_to_string();
        aws.pl->add_msg(s);
        vTaskDelay(pdMS_TO_TICKS(30000));
    }
    //vTaskDelay(pdMS_TO_TICKS(10000));
    
    //system_clock c;
    
    */
}
