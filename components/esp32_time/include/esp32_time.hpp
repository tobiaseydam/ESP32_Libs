#ifndef ESP32_TIME_HPP
#define ESP32_TIME_HPP


#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#define WIFI_CONNECTED_BIT  BIT0
#define ETH_CONNECTED_BIT   BIT1
#define GOT_IP_BIT          BIT2
#define HTTP_ONLINE_BIT     BIT3
#define SNTP_CLOCK_SET_BIT  BIT4

class system_clock{
    private:
        static constexpr char *TAG = (char*)"system_clock";
        EventGroupHandle_t event_group = NULL;
    public:
        system_clock();
        void init();
        
        void set_event_group(EventGroupHandle_t e) { event_group = e; };
        EventGroupHandle_t get_event_group() { return event_group; };
};

class system_clock_task{
    private:
        static constexpr char *TAG = (char*)"system_clock_task";
        static TaskHandle_t handle;
        static void set_task(void* param);
        system_clock* c;
    public:
        system_clock_task(EventGroupHandle_t event_group);
};

#endif