#ifndef ESP32_HTTP_HPP
#define ESP32_HTTP_HPP

#include "esp_http_server.h"
#include <string>
using namespace std;


class http_settings{
    private:
        bool https = false;
    public:
        void set_https(bool value){ https = value; };
        bool get_https(){ return https; };
};

class http_uri_handler{
    private:
        string uri;
        httpd_method_t method;
        esp_err_t (*handler)(httpd_req_t *r);
        void *user_ctx;
};

class http_server{
    private:
        http_settings s;
    public:
        http_server(http_settings as);
        void register_uri_handler(http_uri_handler ahandler);
        void init();
        void start();
        void stop();
};

#endif