#include "esp32_http.hpp"
#include "esp_err.h"
#include "esp_log.h"
#include <string.h>
#include "esp32_storage.hpp"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#define WIFI_CONNECTED_BIT  BIT0
#define ETH_CONNECTED_BIT   BIT1
#define GOT_IP_BIT          BIT2

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
    xEventGroupWaitBits(s.get_event_group(), GOT_IP_BIT, false, true, portMAX_DELAY);
    if(s.get_https() && load_cert()){
        httpd_ssl_config_t config;    

        config.httpd.task_priority      = tskIDLE_PRIORITY+5;
        config.httpd.stack_size         = 10240;
        config.httpd.server_port        = 0;
        config.httpd.ctrl_port          = 32768;
        config.httpd.max_open_sockets   = 4;
        config.httpd.max_uri_handlers   = 8;
        config.httpd.max_resp_headers   = 8;
        config.httpd.backlog_conn       = 5;
        config.httpd.lru_purge_enable   = true;
        config.httpd.recv_wait_timeout  = 5;
        config.httpd.send_wait_timeout  = 5;
        config.httpd.global_user_ctx = NULL;
        config.httpd.global_user_ctx_free_fn = NULL;
        config.httpd.global_transport_ctx = NULL;
        config.httpd.global_transport_ctx_free_fn = NULL;
        config.httpd.open_fn = NULL;
        config.httpd.close_fn = NULL;

        config.transport_mode = HTTPD_SSL_TRANSPORT_SECURE;
        config.port_secure = 443;
        config.port_insecure = 80;

        config.cacert_pem = (const uint8_t*) root_ca_pem;
        config.cacert_len = storage_adapter::get_file_size(ROOT_CA_PEM_FILE);   
        config.prvtkey_pem = (const uint8_t*) private_key_pem;
        config.prvtkey_len = storage_adapter::get_file_size(PRIVATE_KEY_FILE);

        ESP_LOGI(TAG, "starting HTTPS server");

        ESP_ERROR_CHECK(httpd_ssl_start(server, &config));
    }else{
        
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
        config.global_user_ctx    = NULL;
        config.global_user_ctx_free_fn = NULL;
        config.global_transport_ctx = NULL;
        config.global_transport_ctx_free_fn = NULL;
        config.open_fn            = NULL;
        config.close_fn           = NULL;

        ESP_LOGI(TAG, "starting HTTP server");

        ESP_ERROR_CHECK(httpd_start(server, &config));
    }
    xEventGroupSetBits(s.get_event_group(), HTTP_ONLINE_BIT);
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

bool http_server::load_cert(){
    FILE* file = fopen(ROOT_CA_PEM_FILE, "r");
    if(file){
        if(!root_ca_pem){
            char *root_ca = new char[storage_adapter::get_file_size(ROOT_CA_PEM_FILE)]();
            char buffer[32];
            while(fgets(buffer, 32 , file)){
                strcat(root_ca, buffer);
            }
            root_ca_pem = root_ca;
            
            fclose(file);
        }
    }else{
        return false;
    }
    file = fopen(PRIVATE_KEY_FILE, "r");
    if(file){
        if(!private_key_pem){
            char *private_key = new char[storage_adapter::get_file_size(PRIVATE_KEY_FILE)]();
            char buffer[32];
            while(fgets(buffer, 32 , file)){
                strcat(private_key, buffer);
            }
            private_key_pem = private_key;
            
            fclose(file);
        }
    }else{
        return false;
    }
    return true;
}