#ifndef ESP32_HTTP_HPP
#define ESP32_HTTP_HPP

#include "esp_http_server.h"
#include "esp_https_server.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include <string>
#include <stdio.h>
#include <dirent.h>

#include "esp32_settings.hpp"

#ifndef MIN
    #define MIN(x, y)  ((x) < (y) ? (x) : (y))
#endif

#define WIFI_CONNECTED_BIT  BIT0
#define ETH_CONNECTED_BIT   BIT1
#define GOT_IP_BIT          BIT2
#define HTTP_ONLINE_BIT     BIT3
#define SNTP_CLOCK_SET_BIT  BIT4

//#define ROOT_CA_PEM_FILE    "/spiffs/cacert.pem"
//#define PRIVATE_KEY_FILE    "/spiffs/prvtkey.pem"

#define ROOT_CA_PEM_FILE    "/spiffs/cert.pem"
#define PRIVATE_KEY_FILE    "/spiffs/private.key"

using namespace std;

typedef enum{
    DEFAULT_HTTP_SERVER,
    HEIZUNGS_HTTP_SERVER
} e_http_server_class;

class http_settings{
    private:
        static constexpr char *TAG = (char*)"http_settings";
        bool https = false;
        EventGroupHandle_t event_group = NULL;
        e_http_server_class hsc = DEFAULT_HTTP_SERVER;
        settings_manager* sm = NULL;
        string root_folder;
    public:
        http_settings(){};
        http_settings(const http_settings &s);

        void set_https(bool value){ https = value; };
        bool get_https(){ return https; };

        void set_event_group(EventGroupHandle_t e) { event_group = e; };
        EventGroupHandle_t get_event_group() { return event_group; };

        void set_http_server_class(e_http_server_class e) { hsc = e; };
        e_http_server_class get_http_server_class() { return hsc; };

        void set_settings_manager(settings_manager* e) { sm = e; };
        settings_manager* get_settings_manager() { return sm; };

        void set_root_folder(string e) { root_folder = e; };
        string get_root_folder() { return root_folder; };
};

typedef esp_err_t (*uri_handler_t)(httpd_req_t *r);

class http_uri_handler{
    private:
        static constexpr char *TAG = (char*)"http_uri_handler";
        string uri;
        httpd_method_t method;
        uri_handler_t handler;
        void *user_ctx;
    public:
        void set_uri(string value){ uri = value; };
        string get_uri(){ return uri; };

        void set_method(httpd_method_t value){ method = value; };
        httpd_method_t get_method(){ return method; };

        void set_handler(uri_handler_t value){ handler = value; };
        uri_handler_t get_handler(){ return handler; };

        void set_user_ctx(void* value){ user_ctx = value; };
        void* get_user_ctx(){ return user_ctx; };
};

class http_get_query_processor{
    private:
        static constexpr char *TAG = (char*)"http_get_query_processor";
        string buf;
        settings_manager* sm;
        void replaceAll(string& str, const string& from, const string& to);
    public:
        http_get_query_processor(string buffer, settings_manager* sett_man);
        void process();
};

class http_server{
    private:
        static constexpr char *TAG = (char*)"http_server";
    protected:
        http_settings* s;
        httpd_handle_t* server;
        const char* root_ca_pem; 
        const char* private_key_pem; 
        bool load_cert();
    public:
        http_server(http_settings* as);
        void register_uri_handler(http_uri_handler ahandler);
        virtual void init();
        void start();
        void stop();
        void example();
};

class default_http_server: public http_server{
    protected:
        static constexpr char *TAG = (char*)"default_http_server";
    public:
        default_http_server(http_settings* as);
        virtual void init() override;

        static esp_err_t* spiffs_handler(httpd_req_t *req);
        static esp_err_t* upload_handler(httpd_req_t *req);
};

class heizung_http_server: public default_http_server{
    protected:
        static constexpr char *TAG = (char*)"heizung_http_server";
    public:
        void init() override;
        heizung_http_server(http_settings* as);
        static esp_err_t* settings_handler(httpd_req_t *req);
};

class http_server_task{
    private:
        static constexpr char *TAG = (char*)"http_server_task";
        http_server *srv;
        static TaskHandle_t handle;
        static void startup_task(void* param);
    public:
        http_server_task(http_settings* as);
};





#endif