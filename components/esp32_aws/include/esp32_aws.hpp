#ifndef ESP32_AWS_HPP
#define ESP32_AWS_HPP

#include <string>
#include <string.h>
#include <vector>
#include <list>

#include "aws_iot_config.h"
#include "aws_iot_log.h"
#include "aws_iot_version.h"
#include "aws_iot_mqtt_client_interface.h"
#include "aws_iot_mqtt_client.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include <lwip/netdb.h>

#include "esp32_settings.hpp"

//#include "mqtt_client.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "freertos/queue.h"

//#define AWS_ROOT_CA_PEM_FILE    "/spiffs/root-ca-cert.pem"
//#define AWS_CERT_PEM_FILE       "/spiffs/certificate.pem.crt"
//#define AWS_PRIVATE_KEY_FILE    "/spiffs/private.pem.key"
//#define AWS_GGCORE_CA_PEM_FILE  "/spiffs/group-ca-cert.pem"
/*
#define HOST_URL            "a38mp4h6o8iiol-ats.iot.us-east-1.amazonaws.com"
#define HOST_URL2           "192.168.178.43"

//#define WEB_SERVER "a38mp4h6o8iiol-ats.iot.us-east-1.amazonaws.com"
#define WEB_SERVER "192.168.178.43"
                    
//#define WEB_PORT "8443"
#define WEB_PORT "8883"
//#define WEB_URL "https://a38mp4h6o8iiol-ats.iot.us-east-1.amazonaws.com"
#define WEB_URL "https://192.168.178.43"

using namespace std;

class aws_Connectivity{
    public:
        string id;
        string hostAddress;
        int portNumber;
        string metadata;
};

class aws_Core{
    public:
        string thingArn;
        vector <aws_Connectivity*> connectivity;
};

class aws_GGGroup{
    public:
        string gGGroupId;
        vector <aws_Core*> cores;
        vector <string> cas;
};

class aws_GGGroups{
    public:
        vector <aws_GGGroup*> groups;
};

class aws_publish_list{
    private:
        static constexpr char *TAG = (char*)"aws_publish_list";
        vector <string> messages;
        QueueHandle_t xmessages_queue;
        //SemaphoreHandle_t xSemaphore = NULL;
        uint16_t cntr = 0;
    public:
        aws_publish_list();
        void add_msg(string s);
        string get_next_msg();
        bool has_next_msg();
};

class aws_adapter{
    private:
        static constexpr char *TAG = (char*)"aws_adapter";

        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_x509_crt cacert;
        mbedtls_x509_crt groupcacert;
        mbedtls_x509_crt client_cert;
        mbedtls_pk_context prvkey;
        mbedtls_ssl_config conf;
        mbedtls_net_context server_fd;
        mbedtls_ssl_context ssl;

        settings_manager* sm;
        const char* load_cert(string filename);
    public:
        const char* aws_root_ca_pem = NULL; 
        const char* aws_cert_pem = NULL; 
        const char* aws_private_key_pem = NULL; 
        const char* aws_group_ca_cert = NULL; 

        bool gg_avl = false;
        bool connected = false;

        void set_settings_manager(settings_manager* sett_man){ sm = sett_man; };
        settings_manager* get_settings_manager(){ return sm; };

        void load_certs();

        bool connect(bool gg, const char* port);

        void disconnect();
        string ggd();
        string mqtt_connect();
        
        aws_GGGroups* parse_ggd(string json_string);
        aws_publish_list* pl;

        static esp_err_t mqtt_event_handler(esp_mqtt_event_handle_t event);

        void test_connect();

        void printCertInfo(mbedtls_x509_crt* cert);
        void printCertField(mbedtls_x509_name *field);
};

class aws_task{
    private:
        static constexpr char *TAG = (char*)"aws_task";
        static void connect_task(void *param);
        static void run_aws_task(void *param);
        static void run_aws_task2(void *param);
        settings_manager* sm;
        static AWS_IoT_Client* client;
        static IoT_Client_Init_Params mqttInitParams;
        aws_adapter* aws;
        static void iot_subscribe_callback_handler(AWS_IoT_Client *pClient, char *topicName, uint16_t topicNameLen,
                                    IoT_Publish_Message_Params *params, void *pData);
    public:
        aws_task(settings_manager* sett_man);
        void run();
        aws_publish_list* pl;
};
*/
#endif