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

typedef esp_err_t (*uri_handler_t)(httpd_req_t *r);

class http_uri_handler{
    private:
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
        http_settings s;
        httpd_handle_t* server;
    public:
        http_server(http_settings as);
        //http_server(const http_server &s);
        void register_uri_handler(http_uri_handler ahandler);
        void init();
        void start();
        void stop();
        void example();
};

#endif