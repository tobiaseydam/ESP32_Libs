#include "esp32_tls.hpp"
#include "esp32_mqtt.hpp"

tls_client::tls_client(){
    tls = new tls_layer();
    tls->set_root_ca_file("/spiffs/root-ca-cert.pem");
    tls->set_cert_pem_file("/spiffs/certificate.pem.crt");
    tls->set_private_key_pem_file("/spiffs/private.pem.key");
    tls->set_hostname("a38mp4h6o8iiol-ats.iot.us-east-1.amazonaws.com");
    tls->set_port("8883");

}

void tls_client::connect_task(void* params){
    tls_layer* tls = (tls_layer*) params;
    tls->tls_connect(NULL);
    vTaskDelete(NULL);
}

void tls_client::read_task(void* params){
    param_group_send_task_t* p = (param_group_send_task_t*) params; 
    tls_layer* tls = p->tls;
    protocol_client* prot_cl = p->prot_cl;
    uint16_t len = 512;
    uint8_t* buf = new uint8_t[len];

    while(1){
        tls->tls_read(buf, len);
        mqtt_message* m = mqtt_message::create_message(buf, len);
        prot_cl->handle_message(m);
        //m->explain();
    }
}


void tls_client::connect(protocol_client* prot_cl){
    xTaskCreate( connect_task, "CONNECT TASK", 8196, tls, tskIDLE_PRIORITY, &connect_task_handle );   
    xEventGroupWaitBits(get_event_group(), TLS_EG_CONNECTED, false, true, portMAX_DELAY);
    param_group_send_task_t* pg = new param_group_send_task_t();
    pg->prot_cl = prot_cl;
    pg->tls = tls;
    xTaskCreate( read_task, "READ TASK", 8196, pg, tskIDLE_PRIORITY, &read_task_handle );   
}

void tls_client::tls_write(uint8_t* buf, uint16_t len){
    tls->tls_write(buf, len);
}

