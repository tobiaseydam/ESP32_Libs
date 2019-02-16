#ifndef ESP32_AWS_HPP
#define ESP32_AWS_HPP

#include <string>
#include <string.h>
#include <vector>

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
#define AWS_GGCORE_CA_PEM_FILE  "/spiffs/group-ca-cert.pem"

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

class aws_adapter{
    private:
        static constexpr char *TAG = (char*)"aws_adapter";
        static const char* aws_root_ca_pem; 
        static const char* aws_cert_pem; 
        static const char* aws_private_key_pem; 
        static const char* ggcore_ca_cert; 

        AWS_IoT_Client* client;
        IoT_Client_Init_Params mqttInitParams;
        IoT_Client_Connect_Params connectParams;

        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_ssl_context ssl;
        mbedtls_x509_crt cacert;
        mbedtls_x509_crt groupcacert;
        mbedtls_x509_crt client_cert;
        mbedtls_pk_context prvkey;
        mbedtls_ssl_config conf;
        mbedtls_net_context server_fd;
    public:
        bool load_certs();
        aws_adapter(){};
        void init();
        void start();
        bool send_test_message();

        void mbedtls_connect();
        void mbedtls_disconnect();
        string ggd();
        aws_GGGroups* parse_ggd(string json_string);

        void test_connect();

        void printCertInfo(mbedtls_x509_crt* cert);
        void printCertField(mbedtls_x509_name *field);
};

class aws_task{
    private:
        static constexpr char *TAG = (char*)"aws_task";
        static void connect_task(void *param);
    public:
        void run();
};

#endif