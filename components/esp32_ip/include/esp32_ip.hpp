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

class ip_settings{
    private:
        layer2_protocol_t l2p = ETH;
    public:
        void set_l2p(layer2_protocol_t value){ l2p = value; }
        layer2_protocol_t get_l2p(){ return l2p; }
};

class eth_settings: public ip_settings{
    private:
    public:
};

class wifi_settings: public ip_settings{
    private:
        string ssid;
        string pass;
    public:
        void set_ssid(string value){ ssid = value; };
        string get_ssid(){ return ssid; };

        void set_pass(string value){ pass = value; };
        string get_pass(){ return pass; };
};

class layer2_adapter{
    private:
        static esp_err_t event_handler(void *ctx, system_event_t *event); 
    public:
        virtual void init(ip_settings s);
        virtual void start();
        virtual void stop();
};

class eth_adapter : public layer2_adapter{
    public:
        void init(ip_settings s) override;
        void start() override;
        void stop() override;
};

class wifi_adapter : public layer2_adapter{
    public:
        void init(ip_settings s) override;
        void start() override;
        void stop() override;
};

class ip_adapter{
    private:
        layer2_adapter l2a;
    public:
};


#endif