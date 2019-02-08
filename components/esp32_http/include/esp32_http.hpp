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

#ifndef MIN
    #define MIN(x, y)  ((x) < (y) ? (x) : (y))
#endif

//#define ROOT_CA_PEM_FILE    "/spiffs/cacert.pem"
//#define PRIVATE_KEY_FILE    "/spiffs/prvtkey.pem"

#define ROOT_CA_PEM_FILE    "/spiffs/cert.pem"
#define PRIVATE_KEY_FILE    "/spiffs/private.key"

using namespace std;

class http_settings{
    private:
        static constexpr char *TAG = (char*)"http_settings";
        bool https = false;
        EventGroupHandle_t event_group = NULL;
    public:
        void set_https(bool value){ https = value; };
        bool get_https(){ return https; };

        void set_event_group(EventGroupHandle_t e) { event_group = e; };
        EventGroupHandle_t get_event_group() { return event_group; };
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

class http_server{
    private:
        static constexpr char *TAG = (char*)"http_server";
        http_settings s;
        httpd_handle_t* server;
        const char* root_ca_pem; 
        const char* private_key_pem; 
        bool load_cert();
    public:
        http_server(http_settings as);
        void register_uri_handler(http_uri_handler ahandler);
        virtual void init();
        void start();
        void stop();
        void example();
};

class default_http_server: public http_server{
    protected:
        static constexpr char *TAG = (char*)"default_http_server";
        string rf;
    public:
        default_http_server(http_settings as, string root_folder_name);
        void init() override;

        static esp_err_t* spiffs_handler(httpd_req_t *req);
        static esp_err_t* upload_handler(httpd_req_t *req);
};

#endif