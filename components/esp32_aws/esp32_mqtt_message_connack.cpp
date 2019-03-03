#include "esp32_mqtt.hpp"

mqtt_message_connack::mqtt_message_connack(uint8_t* a_msg, uint16_t a_len){
    fh = new mqtt_fixed_header(a_msg);
    vh = new mqtt_variable_header_connack(a_msg+2);//fh->get_length());
    msg = a_msg;
    len = a_len;
}

uint8_t* mqtt_message_connack::get_message(){
    return msg;
}

uint16_t mqtt_message_connack::get_message_len(){
    return len;
}

void mqtt_message_connack::to_string(){

}