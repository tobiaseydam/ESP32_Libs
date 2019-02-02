#include "esp32_http.hpp"
#include "esp_err.h"
#include "esp_log.h"
#include <string.h>

http_server::http_server(http_settings as){
    s = as;
    server = new httpd_handle_t;
}

void http_server::register_uri_handler(http_uri_handler ahandler){
    httpd_uri_t u;
    memset(&u, 0, sizeof(u));
    u.uri = ahandler.get_uri().c_str();
    u.method = ahandler.get_method();
    u.handler = ahandler.get_handler();
    u.user_ctx = ahandler.get_user_ctx();
    httpd_register_uri_handler(*server, &u);
}


void http_server::init(){
    
}

void http_server::start(){
    httpd_config_t config;
    config.task_priority      = tskIDLE_PRIORITY+5;
    config.stack_size         = 4096;
    config.server_port        = 80;
    config.ctrl_port          = 32768;
    config.max_open_sockets   = 7;
    config.max_uri_handlers   = 8;
    config.max_resp_headers   = 8;
    config.backlog_conn       = 5;
    config.lru_purge_enable   = false;
    config.recv_wait_timeout  = 5;
    config.send_wait_timeout  = 5;
    ESP_ERROR_CHECK(httpd_start(server, &config));
}

void http_server::stop(){

}

void http_server::example(){
    http_uri_handler* h = new http_uri_handler();
    h->set_uri("/test");
    h->set_method(HTTP_POST);
    h->set_handler([](httpd_req_t *req){
        int remaining = req->content_len;
        ESP_LOGI(TAG, "%d", remaining);
        char buffer[256];
        esp_err_t ret;
        while (remaining > 0){
            if ((ret = httpd_req_recv(req, buffer, MIN(remaining, sizeof(buffer)))) < 0) {
                return ESP_FAIL;
            }
            remaining -= ret;
            ESP_LOGI(TAG, "%s", buffer);
        }
        string resp = "Hello World";
        httpd_resp_send(req, resp.c_str(), resp.length());
        return ESP_OK;
    });
    h->set_user_ctx(NULL);
    register_uri_handler(*h);
}