#include "esp32_mqtt.hpp"

void mqtt_message::explain(){

    ESP_LOGI(TAG, "----- FIXED HEADER -----");
    fh->explain();
    
    if(vh != NULL){
        ESP_LOGI(TAG, "----- VARIABLE HEADER -----");
        vh->explain();
    }

    if(pl != NULL){
        ESP_LOGI(TAG, "----- PAYLOAD -----");
        pl->explain();
    }

}

mqtt_message* mqtt_message::create_message(uint8_t* a_msg, uint16_t a_len){
    e_mqtt_message_type_t t = static_cast<e_mqtt_message_type_t>(a_msg[0]>>4);
    switch (t){
        case CONNACK:
            return new mqtt_message_connack(a_msg, a_len);
            break;
    
        default:
            return NULL;
            break;
    }
}
