#ifndef ESP32_IP_HPP
#define ESP32_IP_HPP

#include <string>
#include "esp_err.h"
#include "esp_event_loop.h"
#include "freertos/event_groups.h"

using namespace std;

typedef enum{
    WIFI_AP,
    WIFI_STA,
    ETH
}layer2_protocol_t;

typedef void (*got_ip_callback_t)(void *ctx);

class ip_settings{
    protected:
        layer2_protocol_t l2p = WIFI_AP;
        got_ip_callback_t got_ip_callback = NULL;
        void* got_ip_callback_ctx = NULL;
        bool got_ip_callback_set = false;
    public:
        void set_l2p(layer2_protocol_t value){ l2p = value; }
        layer2_protocol_t get_l2p(){ return l2p; }
        
        void set_got_ip_callback(got_ip_callback_t value, void *ctx){ 
            got_ip_callback = value; 
            got_ip_callback_ctx = ctx;
            got_ip_callback_set = true;
        };
        got_ip_callback_t get_got_ip_callback(){ return got_ip_callback; };
        bool is_got_ip_callback_set(){ return got_ip_callback_set; };
        void* get_got_ip_callback_ctx(){ return got_ip_callback_ctx; };
};

class eth_settings: public ip_settings{
    private:
    public:
        eth_settings();
        eth_settings(const eth_settings &s);
};

class wifi_settings: public ip_settings{
    private:
        string ssid = "ESP32_test";
        string pass = "k79Zqr2LjOOd";
        int ap_max_connection = 5;
        wifi_auth_mode_t ap_authmode = WIFI_AUTH_WPA_WPA2_PSK;
        int max_tries = 5;
        int current_try = 0;
    public:
        void set_ssid(string value){ ssid = value; };
        string get_ssid(){ return ssid; };

        void set_pass(string value){ pass = value; };
        string get_pass(){ return pass; };

        void set_ap_max_connection(int value){ ap_max_connection = value; };
        int get_ap_max_connection(){ return ap_max_connection; };

        void set_ap_authmode(wifi_auth_mode_t value){ ap_authmode = value; };
        wifi_auth_mode_t get_ap_authmode(){ return ap_authmode; };

        void set_max_tries(int value){ max_tries = value; };
        int get_max_tries(){ return max_tries; };

        void set_current_try(int value){ current_try = value; };
        int get_current_try(){ return current_try; };
        void inc_current_try(){ current_try++; };
        void reset_current_try(){ current_try = 0; };
};


class layer2_adapter{
    protected:
        static constexpr char *TAG = (char*)"layer2_adapter";
        static esp_err_t event_handler(void *ctx, system_event_t *event);
        
    public:
        virtual void init();
        virtual void start();
        virtual void stop();
};

class eth_adapter : public layer2_adapter{
    protected:
        static constexpr char *TAG = (char*)"eth_adapter";
        eth_settings* s;
        static void eth_gpio_config_rmii();
    public:
        eth_adapter(eth_settings as);
        void init() override;
        void start() override;
        void stop() override;
};

class wifi_adapter : public layer2_adapter{
    protected:
        static constexpr char *TAG = (char*)"wifi_adapter";
        wifi_settings s;
    public:
        wifi_adapter(wifi_settings as);
        void init() override;
        void start() override;
        void stop() override;
};

class ip_adapter{
    private:
        layer2_adapter l2a;
    public:
};


#endif