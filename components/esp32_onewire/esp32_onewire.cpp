#include "esp32_onewire.hpp"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "rom/ets_sys.h"
#include "esp_log.h"



onewire_adapter::onewire_adapter(uint8_t p){
    pin = (gpio_num_t)p;

    gpio_config_t io_conf;
    io_conf.intr_type = GPIO_INTR_DISABLE;
    io_conf.mode = GPIO_MODE_OUTPUT;
    io_conf.pin_bit_mask = (1ULL<<p);
    io_conf.pull_down_en = GPIO_PULLDOWN_DISABLE;
    io_conf.pull_up_en = GPIO_PULLUP_DISABLE;
    gpio_config(&io_conf);
    //gpio_pad_select_gpio(p);
    search_devices();
    read_data();
}

void onewire_adapter::search_devices(){
    ESP_LOGI(TAG, "searching onewire devices");
    num_devices = 0;
    uint8_t b1=0, b2=0, b=0, m=0, s=0;
    int i, j, k = 0;
    bool first = true;
    bool finished = false;
    onewire_addr_t addr, mask;
    while(!finished){
        finished = true;
        if(reset_pulse() == 1){
            //ESP_LOGI(TAG, "presence ok");
            // search rom
            send_byte(0xF0);
            for(j = 0; j<8; j++){
                for(i = 0; i<8; i++){
                    b1 = read_bit();
                    ets_delay_us(15);
                    b2 = read_bit();
                    ets_delay_us(15);
                    if(first || !check_mask(mask,i,j)){
                        s = b1;
                        m = m << 1 | !(b1 | b2);
                    }else{
                        s = 1;
                        m = m << 1;
                    }
                    send_bit(s);
                    //ESP_LOGI(TAG, "%d - %d - %d", b1, b2, s);
                    b = b >> 1 | (b1|s)<<7;
                }
                //ESP_LOGI(TAG, "d4: %X", b);
                addr.x[j] = b;
                mask.x[j] = m;
                finished = finished & (m==0);
            }
            //print_addr(addr);
            //print_addr(mask);
            devices[k] = new onewire_device(addr);
            k++;
            first = false;
            num_devices ++;
        }
    }
}

uint8_t onewire_adapter::reset_pulse(){
    uint8_t PRESENCE;
    gpio_set_direction(pin, GPIO_MODE_OUTPUT);
    gpio_set_level(pin,0);
    ets_delay_us(500);
    //gpio_set_level(pin,1);
    gpio_set_direction(pin, GPIO_MODE_INPUT);
    ets_delay_us(30);
    if(gpio_get_level(pin)==0) PRESENCE=1; else PRESENCE=0;
    ets_delay_us(470);
    if(gpio_get_level(pin)==1) PRESENCE=1; else PRESENCE=0;
    return PRESENCE;
}


void onewire_adapter::send_bit(uint8_t data){
    gpio_set_direction(pin, GPIO_MODE_OUTPUT);
    gpio_set_level(pin,0);
    ets_delay_us(5);
    if(data==1)gpio_set_direction(pin, GPIO_MODE_INPUT);//gpio_set_level(pin,1);
    ets_delay_us(80);
    gpio_set_direction(pin, GPIO_MODE_INPUT);//
    //gpio_set_level(pin,1);
}   


uint8_t onewire_adapter::read_bit(){
    uint8_t PRESENCE=0;
    gpio_set_direction(pin, GPIO_MODE_OUTPUT);
    gpio_set_level(pin,0);
    ets_delay_us(2);
    gpio_set_direction(pin, GPIO_MODE_INPUT);//
    //gpio_set_level(pin,1);
    ets_delay_us(15);
    //gpio_set_direction(pin, GPIO_MODE_INPUT);
    if(gpio_get_level(pin)==1) PRESENCE=1; else PRESENCE=0;
    return(PRESENCE);
}


void onewire_adapter::send_byte(uint8_t data){
    uint8_t i;
    uint8_t x;
    for(i=0;i<8;i++){
        x = data>>i;
        x &= 0x01;
        send_bit(x);
    }
    ets_delay_us(100);
}   


uint8_t onewire_adapter::read_byte(){
    uint8_t i;
    uint8_t data = 0;
    for (i=0;i<8;i++){
        if(read_bit()) data|=0x01<<i;
        ets_delay_us(15);
    }
    return(data);
}

void onewire_adapter::print_addr(onewire_addr_t a){
    ESP_LOGI(TAG, "%02x %02x %02x %02x %02x %02x %02x %02x", a.x[0],a.x[1],a.x[2],a.x[3],a.x[4],a.x[5],a.x[6],a.x[7]);
}


bool onewire_adapter::check_mask(onewire_addr_t mask, uint8_t bit, uint8_t byte){
    for(int i = 7; i>byte; i--){
        if(mask.x[i]>0){
            //ESP_LOGI(TAG, "check_mask(%d, %d): 0", bit, byte);
            return false;
        }
    }

    uint8_t a = mask.x[byte]<<(bit+1);
    //ESP_LOGI(TAG, "a = %d << %d = %d",mask.x[byte], (bit+1), a);
    if(a>0){
        //ESP_LOGI(TAG, "check_mask(%d, %d): 1", bit, byte);
        return false;
    }
    
    uint8_t b = mask.x[byte]<<(bit);
    //ESP_LOGI(TAG, "b = %d << %d = %d",mask.x[byte], bit, b);
    if(b>0){
        //ESP_LOGI(TAG, "check_mask(%d, %d): 2", bit, byte);
        return true;
    }

    //ESP_LOGI(TAG, "check_mask(%d, %d): 3", bit, byte);
    return false;
}

void onewire_adapter::read_data(){
    reset_pulse();
    send_byte(0xCC);
    send_byte(0x44);
    while(read_bit() == 0){
        ets_delay_us(100000);
        ESP_LOGI(TAG, ".");
    }
    
    reset_pulse();

    for(int i = 0; i<num_devices; i++){
        ESP_LOGI(TAG, "Reading device...");
        send_byte(0x55);
        onewire_addr_t addr = devices[i]->get_addr();
        print_addr(addr);
        for(int j = 0; j<8; j++){
            send_byte(addr.x[j]);
        }
        send_byte(0xBE);
        onewire_data d;
        for(int j = 0; j<9; j++){
            d.x[j] = read_byte();
            //ESP_LOGI(TAG, "%x", d.x[j]);
        }
        devices[i]->set_data(d);
        ESP_LOGI(TAG, "%f", devices[i]->get_temperature());
        devices[i]->print_data();
        ESP_LOGI(TAG, "--------------------");
        reset_pulse();
    }
}

void onewire_logger::log_task(void *param){
    onewire_adapter* ow = (onewire_adapter*)param;
    while(true){
        ow->read_data();
        vTaskDelay(pdMS_TO_TICKS(5000));
        ESP_LOGI(TAG, "Stack remaining for task '%s' is %d bytes", pcTaskGetTaskName(NULL), uxTaskGetStackHighWaterMark(NULL));
    }
}

void onewire_logger::run(onewire_adapter* ow){
    TaskHandle_t xHandle = NULL;
    xTaskCreate( log_task, "ONEWIRE LOGGER", 2048, ow, tskIDLE_PRIORITY, &xHandle );
}