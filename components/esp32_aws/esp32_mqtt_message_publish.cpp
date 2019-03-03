#include "esp32_mqtt.hpp"

mqtt_message_publish::mqtt_message_publish(bool a_dub_flag, e_mqtt_qos_t a_qos, 
    bool a_retain, uint16_t a_packed_identifier, std::string a_topic, 
    std::string payload){
    
    vh = new mqtt_variable_header_publish(a_topic, a_packed_identifier);

    pl = new mqtt_payload();
    //pl->add_string(payload);
    pl->set_string_no_len(payload);

    len = pl->get_length() + vh->get_length();
    fh = new mqtt_fixed_header(PUBLISH, a_qos, a_retain, a_dub_flag, len);

    msg = new uint8_t[len + 5];
}

uint8_t* mqtt_message_publish::get_message(){
    uint16_t l1 = fh->get_length();
    uint16_t l2 = vh->get_length();
    uint16_t l3 = pl->get_length();
    
    memcpy(msg, fh->get_header(), l1);
    memcpy(msg + l1, vh->get_variable_header(), l2);
    memcpy(msg + l1 + l2, pl->get_payload(), l3);
    return msg;
}

uint16_t mqtt_message_publish::get_message_len(){
    uint16_t l1 = fh->get_length();
    uint16_t l2 = vh->get_length();
    uint16_t l3 = pl->get_length();

    return l1+l2+l3;
}

void mqtt_message_publish::to_string(){
    uint8_t* temp_msg = get_message();

    ESP_LOGI(TAG, "----- FIXED HEADER -----");

    for(uint16_t i = 0; i<fh->get_length(); i++){
        ESP_LOGI(TAG, "Byte: %d: 0x%02x - %c", i, temp_msg[i], temp_msg[i]);
    }
    
    ESP_LOGI(TAG, "----- VARIABLE HEADER -----");

    for(uint16_t i = fh->get_length(); i<fh->get_length() + vh->get_length(); i++){
        ESP_LOGI(TAG, "Byte: %d: 0x%20x - %c", i, temp_msg[i], temp_msg[i]);
    }

    ESP_LOGI(TAG, "----- PAYLOAD -----");

    for(uint16_t i = fh->get_length() + vh->get_length(); i<fh->get_length() + vh->get_length() + pl->get_length(); i++){
        ESP_LOGI(TAG, "Byte: %d: 0x%02x - %c", i, temp_msg[i], temp_msg[i]);
    }
}