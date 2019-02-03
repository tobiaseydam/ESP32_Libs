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

}