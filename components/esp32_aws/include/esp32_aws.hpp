#ifndef ESP32_AWS_HPP
#define ESP32_AWS_HPP

#include <string.h>

#include "aws_iot_config.h"
#include "aws_iot_log.h"
#include "aws_iot_version.h"
#include "aws_iot_mqtt_client_interface.h"
#include "aws_iot_mqtt_client.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include <lwip/netdb.h>

#define AWS_ROOT_CA_PEM_FILE    "/spiffs/root-ca-cert.pem"
#define AWS_CERT_PEM_FILE       "/spiffs/certificate.pem.crt"
#define AWS_PRIVATE_KEY_FILE    "/spiffs/private.pem.key"
//#define AWS_ROOT_CA_PEM_FILE    "/spiffs/server_root_cert.pem"

#define HOST_URL            "a38mp4h6o8iiol-ats.iot.us-east-1.amazonaws.com"

#define WEB_SERVER "a38mp4h6o8iiol-ats.iot.us-east-1.amazonaws.com"
#define WEB_PORT "8443"
#define WEB_URL "https://a38mp4h6o8iiol-ats.iot.us-east-1.amazonaws.com"
//#define WEB_SERVER "www.howsmyssl.com"
//#define WEB_PORT "443"
//#define WEB_URL "https://www.howsmyssl.com/a/check"
class aws_adapter{
    private:
        static constexpr char *TAG = (char*)"aws_adapter";
        static const char* aws_root_ca_pem; 
        static const char* aws_cert_pem; 
        static const char* aws_private_key_pem; 

        AWS_IoT_Client* client;
        IoT_Client_Init_Params mqttInitParams;
        IoT_Client_Connect_Params connectParams;
    public:
        bool load_certs();
        aws_adapter(){};
        void init();
        void start();
        bool send_test_message();

        void ggd();
        void ggd2();
};

class aws_task{
    private:
        static constexpr char *TAG = (char*)"aws_task";
        static void connect_task(void *param);
    public:
        void run();
};

#endif