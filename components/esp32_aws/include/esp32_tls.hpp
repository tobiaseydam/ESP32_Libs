#ifndef ESP32_TLS_HPP
#define ESP32_TLS_HPP

#include <string>
#include <string.h>

#include "esp_log.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"


#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

#define TLS_EG_CONNECTED    BIT0

class protocol_message{

};

class protocol_client{
    public:
        virtual void handle_message(protocol_message *msg){};
        virtual void handle_message(uint8_t* buf, uint16_t len){};
};

typedef struct param_group_net_rcv{
    mbedtls_net_context* server_fd;
    protocol_client* prot_cl;
}param_group_net_rcv_t;

class tls_layer{
    private:
        static constexpr char *TAG = (char*)"tls_layer";
    protected:
        const char* root_ca_pem = NULL; 
        const char* cert_pem = NULL; 
        const char* private_key_pem = NULL; 

        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_x509_crt cacert;
        mbedtls_x509_crt groupcacert;
        mbedtls_x509_crt client_cert;
        mbedtls_pk_context prvkey;
        mbedtls_ssl_config conf;
        mbedtls_net_context server_fd;
        mbedtls_ssl_context ssl;

        char rx_buffer[128];
        char addr_str[128];
        int addr_family;
        int ip_protocol;
        struct sockaddr_in destAddr;

        std::string root_ca_file;
        std::string cert_pem_file;
        std::string private_key_pem_file;

        std::string hostname;
        std::string port;

        EventGroupHandle_t tls_event_group = NULL;
        static int recv_bytes_avail;
        static int net_recv(void *ctx, unsigned char *buf, size_t len);
        static int net_send(void *ctx, const unsigned char *buf, size_t len);

        SemaphoreHandle_t xSemaphore = NULL;

        const char* load_cert(std::string value);
    public:
        tls_layer();

        void set_root_ca_file(std::string value) 
            { root_ca_file = value; };
        std::string get_root_ca_file(){ return root_ca_file; };

        void set_cert_pem_file(std::string value) 
            { cert_pem_file = value; };
        std::string get_cert_pem_file(){ return cert_pem_file; };

        void set_private_key_pem_file(std::string value) 
            { private_key_pem_file = value; };
        std::string get_private_key_pem_file(){ return private_key_pem_file; };
        
        void set_hostname(std::string value) { hostname = value; };
        std::string get_hostname(){ return hostname; };

        void set_port(std::string value) { port = value; };
        std::string get_port(){ return port; };
        
        EventGroupHandle_t get_event_group(){ return tls_event_group; };

        void load_certs();

        bool tls_connect(protocol_client* mqtt_cl);
        
        uint16_t tls_read(uint8_t* buf, uint16_t len);

        void tls_write(uint8_t* buf, uint16_t len);
};



typedef struct param_group_send_task{
    tls_layer* tls;
    protocol_client* prot_cl;
}param_group_send_task_t;

class tls_client{
    private:
        static constexpr char *TAG = (char*)"tls_client";

    protected:
        tls_layer* tls;
        
        TaskHandle_t connect_task_handle = NULL;
        static void connect_task(void* params);
        
        TaskHandle_t read_task_handle = NULL;
        static void read_task(void* params);
    public:
        tls_client();
        void connect(protocol_client* mqtt_cl);
        EventGroupHandle_t get_event_group(){ return tls->get_event_group(); };

        void tls_write(uint8_t* buf, uint16_t len);
};

#endif