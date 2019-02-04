#ifndef ESP32_ONEWIRE_HPP
#define ESP32_ONEWIRE_HPP

#include <string>
#include "driver/gpio.h"

#define MAX_NUM_ONEWIRE_DEVICES 8

typedef struct onewire_addr { uint8_t x[8]; } onewire_addr_t;
typedef struct onewire_data { uint8_t x[10]; } onewire_data_t;

class onewire_device{
    private:
        static constexpr char *TAG = (char*)"onewire_device";
        onewire_addr_t addr;
        onewire_data_t data;
        bool b_crc;
        uint8_t hlp_crc(uint8_t crc, uint8_t d);
        uint16_t readings = 0;
        uint16_t fails = 0;
    public:
        onewire_device(onewire_addr_t a);
        onewire_addr_t get_addr(){return addr;};
        onewire_data_t get_data(){return data;};
        bool get_crc(){return b_crc;};
        void set_data(onewire_data_t d );
        double get_temperature();
        void print_data();
        void check_crc();
        void print();
};

class onewire_adapter{
    private:
        static constexpr char *TAG = (char*)"onewire_adapter";
        gpio_num_t pin;
        uint8_t num_devices = 0;
        onewire_device* devices[MAX_NUM_ONEWIRE_DEVICES];
        uint8_t reset_pulse();

        void send_bit(uint8_t data);
        uint8_t read_bit();
        
        void send_byte(uint8_t data);
        uint8_t read_byte();

        void print_addr(onewire_addr_t a);
        bool check_mask(onewire_addr_t mask, uint8_t bit, uint8_t byte);

        void search_devices();

    public:
        int get_num_devices(){return num_devices;};
        onewire_adapter(uint8_t p);
        void read_data();
        
};

class onewire_logger{
    static constexpr char *TAG = (char*)"onewire_logger";
    private:
        static void log_task(void *param);
    public:
        void run(onewire_adapter* ow);
};

#endif