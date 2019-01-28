#ifndef ESP32_WIFI_HPP
#define ESP32_WIFI_HPP

#include <string>
#include "esp_err.h"
#include "esp_event_loop.h"
#include "freertos/event_groups.h"

using namespace std;

typedef enum {
    WIFI_STA,    // Staion mode
    WIFI_AP,     // Access point
    ETH
} wifi_station_mode_t;

class wifi_settings{
    private:
        static constexpr char *TAG = (char*)"wifi_settings";
        wifi_station_mode_t mode = WIFI_AP;
        string ssid = "ESP32_test"; 
        string pass = "k79Zqr2LjOOd";
        bool auto_reconnect = true;    //reconnect after disconnect
        uint8_t max_tries = 5;
    public:
        wifi_settings();
        wifi_settings(wifi_station_mode_t a_mode, std::string a_ssid, std::string a_pass);
        
        void set_mode(wifi_station_mode_t a_mode){ mode = a_mode; };
        wifi_station_mode_t get_mode(){ return mode; };

        void set_ssid(string value){ ssid = value; };
        string get_ssid(){ return ssid; };

        void set_pass(string value){ pass = value; };
        string get_pass(){ return pass; };

        void set_max_tries(int value){ max_tries = value; };
        int get_max_tries(){ return max_tries; };
};

class wifi_adapter{
    private:
        static constexpr char *TAG = (char*)"wifi_adapter";
        static wifi_settings ws;
        static int tries;
        static esp_err_t event_handler(void *ctx, system_event_t *event);
        static void eth_gpio_config_rmii();
    public:
        static void init(wifi_settings a_ws);
        static void start();
};

#endif