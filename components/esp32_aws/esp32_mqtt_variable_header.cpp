#include "esp32_mqtt.hpp"

mqtt_variable_header_connect::mqtt_variable_header_connect(std::string a_user_name, 
    std::string a_password, bool a_will_retain, e_mqtt_qos_t a_will_qos,
    bool a_will_flag, bool a_clean_session, uint16_t a_keep_alive, mqtt_payload* a_pl){
    
    user_name = a_user_name;
    user_name_flag = true;

    password = a_password;
    password_flag = true;

    will_retain = a_will_retain;
    will_qos = a_will_qos;
    will_flag = a_will_flag;
    clean_session = a_clean_session;
    keep_alive = a_keep_alive;
    encodedData = new uint8_t[10];

    pl = a_pl;
}


mqtt_variable_header_connect::mqtt_variable_header_connect(bool a_will_retain, 
    e_mqtt_qos_t a_will_qos, bool a_will_flag, bool a_clean_session, 
    uint16_t a_keep_alive, mqtt_payload* a_pl){

    will_retain = a_will_retain;
    will_qos = a_will_qos;
    will_flag = a_will_flag;
    clean_session = a_clean_session;
    keep_alive = a_keep_alive;
    encodedData = new uint8_t[10];

    pl = a_pl;
}

uint8_t* mqtt_variable_header_connect::get_variable_header(){
    memcpy(encodedData, protocol_name, 6);
    encodedData[6] = protocol_level;
    uint8_t b8 = 0;
    b8 |= user_name_flag << 7;
    b8 |= password_flag << 6;
    b8 |= will_retain << 5;
    b8 |= will_qos << 3;
    b8 |= will_flag << 2;
    b8 |= clean_session << 1;
    encodedData[7] = b8;
    encodedData[8] = (uint8_t) (keep_alive>>8);
    encodedData[9] = (uint8_t) (keep_alive&0xFF);

    return encodedData;
}

void mqtt_variable_header_connect::explain(){
    ESP_LOGI(TAG, "Byte 0-5: 0x%02x %02x %02x %02x %02x %02x", protocol_name[0], 
        protocol_name[1], protocol_name[2], protocol_name[3], protocol_name[4], 
        protocol_name[5]);
    ESP_LOGI(TAG, "  MQTT             (protocol name)");
    ESP_LOGI(TAG, "Byte 6: 0x%02x (protocol level)", protocol_level);
    ESP_LOGI(TAG, "Byte 7:");
    ESP_LOGI(TAG, "  x....... = 0x%02x  (user name flag)", (uint8_t)user_name_flag);
    ESP_LOGI(TAG, "  .x...... = 0x%02x  (password flag)", (uint8_t)password_flag);
    ESP_LOGI(TAG, "  ..x..... = 0x%02x  (will retain)", (uint8_t)will_retain);
    ESP_LOGI(TAG, "  ...xx... = 0x%02x  (will qos)", (uint8_t)will_qos);
    ESP_LOGI(TAG, "  .....x.. = 0x%02x  (will flag)", (uint8_t)will_flag);
    ESP_LOGI(TAG, "  ......x. = 0x%02x  (clean session)", (uint8_t)clean_session);
    ESP_LOGI(TAG, "Byte 8-9:  0x%04x = %d (keep alive)", keep_alive, keep_alive);
}

mqtt_variable_header_connack::mqtt_variable_header_connack(uint8_t* msg){
    uint8_t b0 = msg[0];
    session_present = b0;

    uint8_t b1 = msg[1];
    return_code = b1;

    encodedData = new uint8_t[2];
}

void mqtt_variable_header_connack::explain(){
    ESP_LOGI(TAG, "Byte 0: 0x%02x (session present)", (uint8_t)session_present);
    ESP_LOGI(TAG, "Byte 1: 0x%02x (return_code)", (uint8_t)return_code);
}

uint8_t* mqtt_variable_header_connack::get_variable_header(){
    encodedData[0] = session_present;
    encodedData[1] = return_code;
    return encodedData;
}

mqtt_variable_header_publish::mqtt_variable_header_publish(std::string a_topic, 
    uint16_t a_packed_identifier){
    topic = a_topic;
    packet_identifier = a_packed_identifier;
    len = topic.length() + 4;
    encodedData = new uint8_t[len];
}

uint8_t* mqtt_variable_header_publish::get_variable_header(){
    uint16_t top_len = topic.length();
    encodedData[0] = top_len>>8;
    encodedData[1] = top_len&0xFF;
    memcpy(encodedData+2, topic.c_str(), top_len);
    encodedData[top_len+2] = packet_identifier>>8;
    encodedData[top_len+3] = packet_identifier&0xFF;
    return encodedData;
}

void mqtt_variable_header_publish::explain(){
    uint16_t top_len = (uint16_t)topic.length();
    ESP_LOGI(TAG, "Byte 0-1: 0x%04x = %d (topic_len)", top_len, top_len);
    ESP_LOGI(TAG, "Byte 2-%d: %s (topic)", top_len+1, topic.c_str());
    ESP_LOGI(TAG, "Byte %d-%d: 0x%04x (packed_identifier)", top_len+2, top_len+3, packet_identifier);
}