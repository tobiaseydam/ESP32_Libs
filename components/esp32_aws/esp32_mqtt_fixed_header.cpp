#include "esp32_mqtt.hpp"

uint8_t mqtt_fixed_header::get_byte_1(){
    uint8_t b = 0;
    b = msg_type << 4;

    switch(msg_type){
        case PUBLISH:
            b |= dub << 3;
            b |= qos << 1;
            b |= retain;
            break;
        case PUBREL:
        case SUBSCRIBE:
        case UNSUBSCRIBE:
            b |= 2;
            break;
        default:
            break;
    }
    return b;
}

mqtt_fixed_header::mqtt_fixed_header(e_mqtt_message_type_t a_msg_type,
    e_mqtt_qos_t a_qos, bool a_retain, bool a_dub, uint32_t a_len){
    msg_type = a_msg_type;
    qos = a_qos;
    retain = a_retain;
    dub = a_dub;
    len = a_len;
    encodedData = new uint8_t[4];
    get_header();
}

mqtt_fixed_header::mqtt_fixed_header(uint8_t* msg){
    uint8_t b0 = msg[0];
    msg_type = static_cast<e_mqtt_message_type_t>(b0>>4);
    if(msg_type == PUBLISH){
        dub = (b0>>3) & 0x01;
        qos = (e_mqtt_qos_t)((b0>>1) & 0x03);
        retain = b0 & 0x01;
    }

    len = 0;
    uint8_t i = 1;
    uint8_t bx = 0;
    do{
        bx = msg[i];
        len += (bx & 0x7f);
        if(bx & 0x80) len <<= 7;
        i++;
    }while(bx & 0x80);
    encodedData = new uint8_t[4];
    get_header();
}

uint8_t* mqtt_fixed_header::get_header(){
    uint8_t encodedLen[4];
    memset(&encodedLen, 0, 4);
    uint8_t l = 0;

    uint32_t len_cpy = len;

    do{
        encodedLen[l] = len_cpy % 0x80;
        len_cpy = len_cpy / 0x80;
        if(len_cpy > 0){
            encodedLen[l] |= 0x80;
        }
        l++;
    }while(len_cpy>0);

    
    encodedData[0] = get_byte_1();
    
    uint8_t i = 1;
    while(l>=i){
        encodedData[i] = encodedLen[i-1];
        i++;
    } 
    header_len = l + 1;
    encodedData[l+1] = '\0';
    return encodedData;
}

void mqtt_fixed_header::explain(){
    ESP_LOGI(TAG, "Byte 0: 0x%02x", get_byte_1());
    ESP_LOGI(TAG, "  xxxx.... = 0x%02x  (message type)", (uint8_t)get_msg_type());
    switch(msg_type){
        case PUBLISH:
            ESP_LOGI(TAG, "  ....x... = 0x%02x  (dub)", (uint8_t)get_dub());
            ESP_LOGI(TAG, "  .....xx. = 0x%02x  (qos)", (uint8_t)get_qos());
            ESP_LOGI(TAG, "  .......x = 0x%02x  (retain)", (uint8_t)get_retain());
            break;
        case PUBREL:
        case SUBSCRIBE:
        case UNSUBSCRIBE:
            ESP_LOGI(TAG, "  ......x. = 0x%02x  (...)", (uint8_t)get_retain());
            break;
        default:
            break;
    }

    for(uint8_t i = 1; i<header_len; i++){
        ESP_LOGI(TAG, "Byte %d: 0x%02x", i, encodedData[i]);
    }
    ESP_LOGI(TAG, "  length = %d", len);

}