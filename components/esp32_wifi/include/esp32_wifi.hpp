#ifndef ESP32_WIFI_HPP
#define ESP32_WIFI_HPP

#include <string>

using namespace std;

enum wifi_station_mode{
    sta,    // Staion mode
    ap      // Access point
};

class wifi_settings{
    private:
        static constexpr char *TAG = (char*)"wifi_settings";
        wifi_station_mode mode;
        string ssid = "ESP32_test"; 
        string pass = "k79Zqr2LjOOd";
        bool auto_reconnect = true;    //reconnect after disconnect
        uint8_t max_tries = 5;
    public:
        wifi_settings();
        wifi_settings(wifi_station_mode a_mode, std::string a_ssid, std::string a_pass);
        
        void set_mode(wifi_station_mode a_mode){ mode = a_mode; };
        wifi_station_mode get_mode(){ return mode; };

        void set_ssid(string value){ ssid = value; };
        string get_ssid(){ return ssid; };

        void set_pass(string value){ pass = value; };
        string get_pass(){ return pass; };
};

class wifi_adapter{
    private:
        static constexpr char *TAG = (char*)"wifi_adapter";
    
};

#endif