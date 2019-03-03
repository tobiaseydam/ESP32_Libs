#include "esp32_mqtt.hpp"

mqtt_message_pingreq::mqtt_message_pingreq(){
    fh = new mqtt_fixed_header(PINGREQ, eQOS0, false, false, 0);
    msg = new uint8_t[len + 3];
}

uint8_t* mqtt_message_pingreq::get_message(){
    uint16_t l1 = fh->get_length();
    
    memcpy(msg, fh->get_header(), l1);
    return msg;
}

void mqtt_message_pingreq::to_string(){
    uint8_t* temp_msg = get_message();

    ESP_LOGI(TAG, "----- FIXED HEADER -----");

    for(uint16_t i = 0; i<fh->get_length(); i++){
        ESP_LOGI(TAG, "Byte: %d: 0x%02x - %c", i, temp_msg[i], temp_msg[i]);
    } 
}