#include "esp32_aws.hpp"

#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_event_loop.h"

#include "esp32_storage.hpp"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"

#include "esp_tls.h"
#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"


const char* aws_adapter::aws_root_ca_pem = NULL;
const char* aws_adapter::aws_cert_pem = NULL;
const char* aws_adapter::aws_private_key_pem = NULL;

bool aws_adapter::load_certs(){
    ESP_LOGI(TAG, "loading ROOT_CA");
    FILE* file = fopen(AWS_ROOT_CA_PEM_FILE, "r");
    uint16_t len = 0;
    if(file){
        if(!aws_root_ca_pem){
            len = storage_adapter::get_file_size(AWS_ROOT_CA_PEM_FILE);
            char *root_ca = new char[len]();
            memset(root_ca, '\0', len);
            char buffer[32];
            while(fgets(buffer, 32 , file)){
                strcat(root_ca, buffer);
            }
            root_ca[len-1] = '\0';
            aws_root_ca_pem = root_ca;
            
            fclose(file);
        }
    }else{
        return false;
    }
    ESP_LOGI(TAG, "loading PRIVATE_KEY");
    file = fopen(AWS_PRIVATE_KEY_FILE, "r");
    if(file){
        if(!aws_private_key_pem){
            len = storage_adapter::get_file_size(AWS_PRIVATE_KEY_FILE);
            char *private_key = new char[len]();
            memset(private_key, 0, len);
            char buffer[32];
            while(fgets(buffer, 32 , file)){
                strcat(private_key, buffer);
            }
            private_key[len-1] = '\0';
            aws_private_key_pem = private_key;
            
            fclose(file);
        }
    }else{
        return false;
    }
    ESP_LOGI(TAG, "loading CERT_PEM");
    file = fopen(AWS_CERT_PEM_FILE, "r");
    if(file){
        if(!aws_cert_pem){
            len = storage_adapter::get_file_size(AWS_CERT_PEM_FILE);
            char *cert_key = new char[len]();
            memset(cert_key, 0, len);
            char buffer[32];
            while(fgets(buffer, 32 , file)){
                strcat(cert_key, buffer);
            }
            cert_key[len-1] = '\0';
            aws_cert_pem = cert_key;
            
            fclose(file);
        }
    }else{
        return false;
    }
    ESP_LOGI(TAG, "loading finished");
    return true;
}

void aws_adapter::init(){
    ESP_LOGI(TAG, "AWS IoT init");
    load_certs();
    client = new AWS_IoT_Client;
    mqttInitParams = iotClientInitParamsDefault;
    connectParams = iotClientConnectParamsDefault;

    ESP_LOGI(TAG, "AWS IoT SDK Version %d.%d.%d-%s", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH, VERSION_TAG);
    
    mqttInitParams.enableAutoReconnect = false;
    mqttInitParams.pHostURL = HOST_URL;
    mqttInitParams.port = 8883;

    mqttInitParams.pRootCALocation = aws_root_ca_pem;
    mqttInitParams.pDeviceCertLocation = aws_cert_pem;
    mqttInitParams.pDevicePrivateKeyLocation = aws_private_key_pem;

    mqttInitParams.mqttCommandTimeout_ms = 20000;
    mqttInitParams.tlsHandshakeTimeout_ms = 5000;
    mqttInitParams.isSSLHostnameVerify = true;

    connectParams.keepAliveIntervalInSec = 10;
    connectParams.isCleanSession = true;
    connectParams.MQTTVersion = MQTT_3_1_1;
    connectParams.pClientID = "1943708d0d";
    connectParams.clientIDLen = 10;
    connectParams.isWillMsgPresent = false;
    
}


void aws_adapter::start(){
    IoT_Error_t rc = FAILURE;

    rc = aws_iot_mqtt_init(client, &mqttInitParams);
    if(SUCCESS != rc) {
        ESP_LOGE(TAG, "aws_iot_mqtt_init returned error : %d ", rc);
        abort();
    }

    ESP_LOGI(TAG, "Connecting to AWS...");
    do {
        rc = aws_iot_mqtt_connect(client, &connectParams);
        if(SUCCESS != rc) {
            ESP_LOGE(TAG, "Error(%d) connecting to %s:%d", rc, mqttInitParams.pHostURL, mqttInitParams.port);
            vTaskDelay(1000 / portTICK_RATE_MS);
        }
    } while(SUCCESS != rc);

    rc = aws_iot_mqtt_autoreconnect_set_status(client, true);
    if(SUCCESS != rc) {
        ESP_LOGE(TAG, "Unable to set Auto Reconnect to true - %d", rc);
        abort();
    }
}


bool aws_adapter::send_test_message(){
    ESP_LOGI(TAG, "Sending test message");
    
    char cPayload[100];
    
    sprintf(cPayload, "{\"Hello\": \"World\"}");
    string p = "{\"Hello\": \"World\"}";
    IoT_Error_t rc = FAILURE;
    const char *TOPIC = "$aws/things/ESP32_3C-71-BF-96-DF-C0/test";
    const int TOPIC_LEN = strlen(TOPIC);
    
    IoT_Publish_Message_Params paramsQOS0;
    paramsQOS0.qos = QOS0;
    paramsQOS0.payload = (void *)p.c_str();
    paramsQOS0.payloadLen = p.length();
    paramsQOS0.isRetained = 0;

    rc = aws_iot_mqtt_publish(client, TOPIC, TOPIC_LEN, &paramsQOS0);

    return rc==SUCCESS;
}


void aws_adapter::ggd(){

    static const char *REQUEST = "GET /greengrass/discover/thing/GG_WohnungBerlin HTTP/1.1\r\n\r\n";
    //static const char *REQUEST = "GET " WEB_URL " HTTP/1.0\r\n"
    //"Host: "WEB_SERVER"\r\n"
    //"User-Agent: esp-idf/1.0 esp32\r\n"
    //"\r\n";
    char buf[512];
    int ret, len;
    esp_tls_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.cacert_pem_buf = (const unsigned char*) aws_root_ca_pem;
    cfg.cacert_pem_bytes = storage_adapter::get_file_size(AWS_ROOT_CA_PEM_FILE);
    cfg.clientcert_pem_buf = (const unsigned char*) aws_cert_pem;
    cfg.clientcert_pem_bytes = storage_adapter::get_file_size(AWS_CERT_PEM_FILE);
    cfg.clientkey_pem_buf = (const unsigned char*) aws_private_key_pem;
    cfg.clientkey_pem_bytes = storage_adapter::get_file_size(AWS_PRIVATE_KEY_FILE);
    cfg.timeout_ms = 5000;

    ESP_LOGI(TAG, "Connecting...");
    struct esp_tls *tls = esp_tls_conn_http_new(WEB_URL, &cfg);
    
    mbedtls_ssl_config conf;
    mbedtls_ssl_context ssl;
    mbedtls_net_context listen_fd, client_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_x509_crt srvcert;
    mbedtls_x509_crt cachain;
    mbedtls_pk_context pkey;
    
    mbedtls_net_init(&listen_fd);
    mbedtls_net_init(&client_fd);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);	
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_x509_crt_init(&cachain);
    mbedtls_pk_init(&pkey);

    mbedtls_x509_crt_parse(&cachain, (const unsigned char*)aws_root_ca_pem, storage_adapter::get_file_size(AWS_ROOT_CA_PEM_FILE));
    mbedtls_x509_crt_parse(&srvcert, (const unsigned char*)aws_cert_pem, storage_adapter::get_file_size(AWS_CERT_PEM_FILE));
    mbedtls_pk_parse_key(&pkey, (const unsigned char*)aws_private_key_pem, storage_adapter::get_file_size(AWS_PRIVATE_KEY_FILE), NULL, 0);

    mbedtls_ssl_conf_ca_chain(&tls->conf, &cachain, NULL);
    mbedtls_ssl_conf_own_cert(&tls->conf, &srvcert, &pkey);
    mbedtls_ssl_conf_authmode(&tls->conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    
    if(tls != NULL) {
        ESP_LOGI(TAG, "Connection established...");
    } else {
        ESP_LOGE(TAG, "Connection failed...");
    }
    
    size_t written_bytes = 0;

    do {
        ret = esp_tls_conn_write(tls, 
            REQUEST + written_bytes, 
            strlen(REQUEST) - written_bytes);
        if (ret >= 0) {
            ESP_LOGI(TAG, "%d bytes written", ret);
            written_bytes += ret;
        } else if (ret != MBEDTLS_ERR_SSL_WANT_READ  && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            ESP_LOGE(TAG, "esp_tls_conn_write  returned 0x%x", ret);
        }
    } while(written_bytes < strlen(REQUEST));

    ESP_LOGI(TAG, "Reading HTTP response...");

    do
    {
        len = sizeof(buf) - 1;
        bzero(buf, sizeof(buf));
        ret = esp_tls_conn_read(tls, (char *)buf, len);
        
        if(ret == MBEDTLS_ERR_SSL_WANT_WRITE  || ret == MBEDTLS_ERR_SSL_WANT_READ)
            continue;
        
        if(ret < 0)
        {
            ESP_LOGE(TAG, "esp_tls_conn_read  returned -0x%x", -ret);
            break;
        }

        if(ret == 0)
        {
            ESP_LOGI(TAG, "connection closed");
            break;
        }

        len = ret;
        ESP_LOGD(TAG, "%d bytes read", len);
        /* Print response directly to stdout as it is read */
        for(int i = 0; i < len; i++) {
            putchar(buf[i]);
        }
    } while(1);

}

void aws_adapter::ggd2(){
    bool load_certs();
    char buf[512];
    int ret, flags, len; 
    static const char *REQUEST = "GET /greengrass/discover/thing/ESP32_3C-71-BF-96-DF-C0 HTTP/1.1\r\n\r\n";
   

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt client_cert;
    mbedtls_pk_context prvkey;
    mbedtls_ssl_config conf;
    mbedtls_net_context server_fd;

    mbedtls_ssl_init(&ssl);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_x509_crt_init(&client_cert);
    mbedtls_pk_init(&prvkey);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    ESP_LOGI(TAG, "Seeding the random number generator");

    mbedtls_ssl_config_init(&conf);

    mbedtls_entropy_init(&entropy);
    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    NULL, 0)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned %d", ret);
        abort();
    }

    ESP_LOGI(TAG, "Loading the CA root certificate...");
    ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char*)aws_root_ca_pem,
                                 storage_adapter::get_file_size(AWS_ROOT_CA_PEM_FILE));

    if(ret < 0)
    {
        ESP_LOGE(TAG, "mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
        abort();
    }

    ESP_LOGI(TAG, "Loading the client certificate...");
    ret = mbedtls_x509_crt_parse(&client_cert, (const unsigned char*)aws_cert_pem,
                                 storage_adapter::get_file_size(AWS_CERT_PEM_FILE));

    if(ret < 0)
    {
        ESP_LOGE(TAG, "mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
        abort();
    }

    ESP_LOGI(TAG, "Loading the client private key...");
    ret = mbedtls_pk_parse_key(&prvkey, (const unsigned char*)aws_private_key_pem,
                                 storage_adapter::get_file_size(AWS_PRIVATE_KEY_FILE), NULL, 0);

    if(ret < 0)
    {
        ESP_LOGE(TAG, "mbedtls_pk_parse_key returned -0x%x\n\n", -ret);
        abort();
    }

    ESP_LOGI(TAG, "Setting hostname for TLS session...");

    if((ret = mbedtls_ssl_set_hostname(&ssl, WEB_SERVER)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_set_hostname returned -0x%x", -ret);
        abort();
    }

    ESP_LOGI(TAG, "Setting up the SSL/TLS structure...");

    if((ret = mbedtls_ssl_config_defaults(&conf,
                                          MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_config_defaults returned %d", ret);
    }

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_own_cert(&conf, &client_cert, &prvkey);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    mbedtls_esp_enable_debug_log(&conf, 4);

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_setup returned -0x%x\n\n", -ret);
    }

    while(1) {
        vTaskDelay(pdMS_TO_TICKS(10000));
        mbedtls_net_init(&server_fd);
        ESP_LOGI(TAG, "Connecting to %s:%s...", WEB_SERVER, WEB_PORT);

        if ((ret = mbedtls_net_connect(&server_fd, WEB_SERVER,
                                      WEB_PORT, MBEDTLS_NET_PROTO_TCP)) != 0)
        {
            ESP_LOGE(TAG, "mbedtls_net_connect returned -%x", -ret);
        }

        ESP_LOGI(TAG, "Connected.");

        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

        ESP_LOGI(TAG, "Performing the SSL/TLS handshake...");

        while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
        {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            {
                ESP_LOGE(TAG, "mbedtls_ssl_handshake returned -0x%x", -ret);
            }
        }
        
        ESP_LOGI(TAG, "Verifying peer X.509 certificate...");

        if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0)
        {
            /* In real life, we probably want to close connection if ret != 0 */
            ESP_LOGW(TAG, "Failed to verify peer certificate!");
            bzero(buf, sizeof(buf));
            mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
            ESP_LOGW(TAG, "verification info: %s", buf);
        }
        else {
            ESP_LOGI(TAG, "Certificate verified.");
        }

        ESP_LOGI(TAG, "Cipher suite is %s", mbedtls_ssl_get_ciphersuite(&ssl));

        ESP_LOGI(TAG, "Writing HTTP request...");

        size_t written_bytes = 0;
        do {
            ret = mbedtls_ssl_write(&ssl,
                                    (const unsigned char *)REQUEST + written_bytes,
                                    strlen(REQUEST) - written_bytes);
            if (ret >= 0) {
                ESP_LOGI(TAG, "%d bytes written", ret);
                written_bytes += ret;
            } else if (ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret != MBEDTLS_ERR_SSL_WANT_READ) {
                ESP_LOGE(TAG, "mbedtls_ssl_write returned -0x%x", -ret);
            }
        } while(written_bytes < strlen(REQUEST));

        ESP_LOGI(TAG, "Reading HTTP response...");

        do
        {
            len = sizeof(buf) - 1;
            bzero(buf, sizeof(buf));
            ret = mbedtls_ssl_read(&ssl, (unsigned char *)buf, len);

            if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
                continue;

            if(ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                ret = 0;
                break;
            }

            if(ret < 0)
            {
                ESP_LOGE(TAG, "mbedtls_ssl_read returned -0x%x", -ret);
                break;
            }

            if(ret == 0)
            {
                ESP_LOGI(TAG, "connection closed");
                break;
            }

            len = ret;
            ESP_LOGD(TAG, "%d bytes read", len);
            /* Print response directly to stdout as it is read */
            for(int i = 0; i < len; i++) {
                putchar(buf[i]);
            }
        } while(1);

        mbedtls_ssl_close_notify(&ssl);

        mbedtls_ssl_session_reset(&ssl);
        mbedtls_net_free(&server_fd);

        if(ret != 0)
        {
            mbedtls_strerror(ret, buf, 100);
            ESP_LOGE(TAG, "Last error was: -0x%x - %s", -ret, buf);
        }

        putchar('\n'); // JSON output doesn't have a newline at end

        static int request_count;
        ESP_LOGI(TAG, "Completed %d requests", ++request_count);

        for(int countdown = 10; countdown >= 0; countdown--) {
            ESP_LOGI(TAG, "%d...", countdown);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
        }
        ESP_LOGI(TAG, "Starting again!");
        vTaskDelay(pdMS_TO_TICKS(10000));
    }

    //mbedtls_x509_crt_parse(&srvcert, (const unsigned char*)aws_cert_pem, storage_adapter::get_file_size(AWS_CERT_PEM_FILE));
    //mbedtls_pk_parse_key(&pkey, (const unsigned char*)aws_private_key_pem, storage_adapter::get_file_size(AWS_PRIVATE_KEY_FILE), NULL, 0);

    //mbedtls_ssl_conf_ca_chain(&tls->conf, &cachain, NULL);
    //mbedtls_ssl_conf_own_cert(&tls->conf, &srvcert, &pkey);
    //mbedtls_ssl_conf_authmode(&tls->conf, MBEDTLS_SSL_VERIFY_REQUIRED);

}

void aws_task::connect_task(void *param){
    ESP_LOGI(TAG, "Initializing AWS");
    aws_adapter aws;
    aws.load_certs();
    //aws.init();
    //aws.start();
    //aws.send_test_message();
    aws.ggd2();

    while(1);
}

void aws_task::run(){
    TaskHandle_t xHandle = NULL;
    xTaskCreate( connect_task, "AWS TASK", 8196, NULL, tskIDLE_PRIORITY, &xHandle );

}