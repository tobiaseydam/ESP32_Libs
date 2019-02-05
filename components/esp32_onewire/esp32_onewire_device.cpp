#include "esp32_onewire.hpp"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "rom/ets_sys.h"
#include "esp_log.h"

onewire_device::onewire_device(onewire_addr_t a){
    addr = a;
    ESP_LOGI(TAG, "new device: %02x %02x %02x %02x %02x %02x %02x %02x", a.x[0],a.x[1],a.x[2],a.x[3],a.x[4],a.x[5],a.x[6],a.x[7]);
}

double onewire_device::get_temperature(){
    uint8_t msb = data.x[1];
    uint8_t lsb = data.x[0];

    uint16_t raw = (msb<<8) + lsb;
    bool sign = (raw>>11>0);

    if(sign){
        return -((raw ^ 0xFFFF) + 1)/16.0;
    }else{
        return raw/16.0;
    }
}


void onewire_device::print_data(){
        ESP_LOGI(TAG, "data: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x", data.x[0],data.x[1],data.x[2],data.x[3],data.x[4],data.x[5],data.x[6],data.x[7],data.x[8],data.x[9]);
        check_crc();
}


uint8_t onewire_device::hlp_crc(uint8_t crc, uint8_t d){
    uint8_t poly = 0x8c;
    for (uint8_t i = 8; i>0; i--){
        uint8_t mix = (crc^d) & 0x01;
        crc >>= 1;
        if(mix) crc ^= poly;
        d >>=1;
    }
    return crc;
}

void onewire_device::check_crc(){
    uint8_t crc = 0;
    for(uint8_t i = 0; i<9; i++){
        crc = hlp_crc(crc, data.x[i]);
        //ESP_LOGI(TAG, "CRC: %2x", crc);
    }
    b_crc = (crc==0);
}


void onewire_device::set_data(onewire_data_t d ){
    data = d;
    check_crc();
    readings++;
    if(!b_crc){
        fails++;
    }
}

void onewire_device::print(){
    ESP_LOGI(TAG, "%02x %02x %02x %02x %02x %02x %02x %02x : %08f °C - readings: %d, fails: %d", addr.x[0],addr.x[1],addr.x[2],addr.x[3],addr.x[4],addr.x[5],addr.x[6],addr.x[7], get_temperature(), readings, fails);
}



string onewire_device::addr_to_string(){
    char buffer[24];
    sprintf(buffer, "%02x %02x %02x %02x %02x %02x %02x %02x", addr.x[0],addr.x[1],addr.x[2],addr.x[3],addr.x[4],addr.x[5],addr.x[6],addr.x[7]);
    return string(buffer);
}   

string onewire_device::data_to_string(){
    char buffer[27];
    sprintf(buffer, "%02x %02x %02x %02x %02x %02x %02x %02x %02x", data.x[0],data.x[1],data.x[2],data.x[3],data.x[4],data.x[5],data.x[6],data.x[7],data.x[8]);
    return string(buffer);
}