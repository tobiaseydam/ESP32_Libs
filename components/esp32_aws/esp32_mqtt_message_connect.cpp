#include "esp32_mqtt.hpp"

mqtt_message_connect::mqtt_message_connect(std::string a_client_name,
    std::string a_user_name, std::string a_password, bool a_will_retain, 
    e_mqtt_qos_t a_will_qos, bool a_will_flag, bool a_clean_session, 
    uint16_t a_keep_alive){
    
    pl = new mqtt_payload();
    pl->add_string(a_client_name);
    pl->add_string(a_user_name);
    pl->add_string(a_password);
    vh = new mqtt_variable_header_connect(a_will_retain, a_will_qos, a_will_flag, 
        a_clean_session, a_keep_alive, pl);
    len = pl->get_length() + vh->get_length() + 1;
    fh = new mqtt_fixed_header(CONNECT, eQOS0, false, false, len - 1);
    msg = new uint8_t[len + 5];
}


mqtt_message_connect::mqtt_message_connect(std::string a_client_name, 
    bool a_will_retain, e_mqtt_qos_t a_will_qos, bool a_will_flag, 
    bool a_clean_session, uint16_t a_keep_alive){

    pl = new mqtt_payload();
    pl->add_string(a_client_name);
    vh = new mqtt_variable_header_connect(a_will_retain, a_will_qos, a_will_flag, 
        a_clean_session, a_keep_alive, pl);
    len = pl->get_length() + vh->get_length() + 1;
    fh = new mqtt_fixed_header(CONNECT, eQOS0, false, false, len - 1);
    msg = new uint8_t[len + 5];
}

uint8_t* mqtt_message_connect::get_message(){
    uint16_t l1 = fh->get_length();
    uint16_t l2 = vh->get_length();
    uint16_t l3 = pl->get_length();
    
    memcpy(msg, fh->get_header(), l1);
    memcpy(msg + l1, vh->get_variable_header(), l2);
    memcpy(msg + l1 + l2, pl->get_payload(), l3);
    return msg;
}

uint16_t mqtt_message_connect::get_message_len(){
    uint16_t l1 = fh->get_length();
    uint16_t l2 = vh->get_length();
    uint16_t l3 = pl->get_length();

    return l1+l2+l3+1;
}

void mqtt_message_connect::to_string(){
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