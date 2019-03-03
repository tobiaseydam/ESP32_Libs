#include "esp32_tls.hpp"
#include "esp32_storage.hpp"


int tls_layer::recv_bytes_avail = 0;

int tls_layer::net_recv( void *ctx, unsigned char *buf, size_t len ){
    param_group_net_rcv_t* p = (param_group_net_rcv_t*) ctx;
    
    ESP_LOGW("test", "server_handle (recv): %p", p->server_fd);

    int ret = mbedtls_net_recv(p->server_fd, buf, len);

    ESP_LOGI("test", "%d bytes recv", ret);
    /*
    ESP_LOGI("test", "------------------------");
    ESP_LOGI("test", "%d bytes available", ret);

    char* line1 = new char[64];
    char* buf1 = new char[64];
    char* line2 = new char[64];
    char* buf2 = new char[64];

    uint16_t i = 0;
    uint16_t i0 = 0;
    uint16_t j = 0;
    
    while(i<len){
        strcpy(line1, "");
        strcpy(line2, "");
        i0 = i;
        while((j<16)&(i<len)){
            sprintf(buf1, " %02x", buf[i]);
            strcat(line1, buf1);
            if((buf[i]>20)&(buf[i]<126)){
                sprintf(buf2, "  %c", buf[i]);
            }else{
                sprintf(buf2, "   ");
            }
            
            strcat(line2, buf2);
            j++;
            i++;
        }
        j = 0;
        ESP_LOGI("test", "Byte %4d - %4d: %s"  , i0, i0+16, line1);
        ESP_LOGI("test", "                  %s", line2);
    
    }
    ESP_LOGI("test", "------------------------");*/
    return ret;
}

int tls_layer::net_send( void *ctx, const unsigned char *buf, size_t len ){
    param_group_net_rcv_t* p = (param_group_net_rcv_t*) ctx;
    
    ESP_LOGW("test", "server_handle (send): %p", p->server_fd);

    int ret = mbedtls_net_send(p->server_fd, buf, len);
    
    ESP_LOGI("test", "%d bytes send", ret);

    return ret;
}

const char* tls_layer::load_cert(std::string filename){
    char* temp = NULL;
    FILE* file = fopen(filename.c_str(), "r");
    if(file){
        uint16_t len = storage_adapter::get_file_size(filename.c_str());
        temp = new char[len+1];
        memset(temp, '\0', len);
        char buf[32];
        while(fgets(buf, 32 , file)){
            strcat(temp, buf);
        }
        temp[len-1] = '\0';
        fclose(file);
        ESP_LOGI(TAG, "ok");
    }else{
        ESP_LOGI(TAG, "failed");
    }
    return temp;
}

void tls_layer::load_certs(){
    if(root_ca_pem != NULL) delete(root_ca_pem);
    if(root_ca_pem != NULL) delete(cert_pem);
    if(root_ca_pem != NULL) delete(private_key_pem);

    ESP_LOGI(TAG, "loading ROOT_CA");
    root_ca_pem = load_cert(root_ca_file);

    ESP_LOGI(TAG, "loading CERT_PEM");
    cert_pem = load_cert(cert_pem_file);
    
    ESP_LOGI(TAG, "loading PRIVATE_KEY");
    private_key_pem = load_cert(private_key_pem_file);
   
    ESP_LOGI(TAG, "loading finished");
}

bool tls_layer::tls_connect(protocol_client* mqtt_cl){
    char buf[512];
    int ret, flags; 

    load_certs();

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
        return false;
        abort();
    }

    ESP_LOGI(TAG, "Parsing the root CA certificate...");
    ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char*)root_ca_pem,
            storage_adapter::get_file_size(get_root_ca_file().c_str()));
        
    if(ret < 0)
    {
        ESP_LOGE(TAG, "mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
        return false;
        abort();
    }

    ESP_LOGI(TAG, "Parsing the client certificate...");
    ret = mbedtls_x509_crt_parse(&client_cert, (const unsigned char*)cert_pem,
                storage_adapter::get_file_size(get_cert_pem_file().c_str()));
    if(ret < 0)
    {
        ESP_LOGE(TAG, "mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
        return false;
        abort();
    }

    ESP_LOGI(TAG, "Parsing the client private key...");
    ret = mbedtls_pk_parse_key(&prvkey, (const unsigned char*)private_key_pem,
                storage_adapter::get_file_size(get_private_key_pem_file().c_str()), NULL, 0);
    if(ret < 0)
    {
        ESP_LOGE(TAG, "mbedtls_pk_parse_key returned -0x%x\n\n", -ret);
        return false;
        abort();
    }

    ESP_LOGI(TAG, "Setting hostname for TLS session...");

    if((ret = mbedtls_ssl_set_hostname(&ssl, NULL)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_set_hostname returned -0x%x", -ret);
        return false;
        abort();
    }

    ESP_LOGI(TAG, "Setting up the SSL/TLS structure...");

    if((ret = mbedtls_ssl_config_defaults(&conf,
                MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_config_defaults returned %d", ret);
    }

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_read_timeout(&conf, 5000);

    mbedtls_ssl_conf_own_cert(&conf, &client_cert, &prvkey);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    mbedtls_esp_enable_debug_log(&conf, 5);

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_setup returned -0x%x\n\n", -ret);
        return false;
    }

    mbedtls_net_init(&server_fd);

    ESP_LOGI(TAG, "Connecting to %s:%s...", hostname.c_str(), port.c_str());
    ret = mbedtls_net_connect(&server_fd, hostname.c_str(), port.c_str(), 
        MBEDTLS_NET_PROTO_TCP);

    if (ret != 0)
    {
        ESP_LOGE(TAG, "mbedtls_net_connect returned -%x", -ret);
        return false;
    }

    ESP_LOGI(TAG, "Connected.");
    param_group_net_rcv_t *p = new param_group_net_rcv_t();
    p->server_fd = &server_fd;
    //mbedtls_ssl_set_bio(&ssl, p, net_send, net_recv, NULL);
    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);

    ESP_LOGI(TAG, "Performing the SSL/TLS handshake...");
    
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            ESP_LOGE(TAG, "mbedtls_ssl_handshake returned -0x%x", -ret);
            return false;
        }
    }
    
    ESP_LOGI(TAG, "Verifying peer X.509 certificate...");

    if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0){
        bzero(buf, sizeof(buf));
        mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
        ESP_LOGW(TAG, "verification info: %s", buf);
        return false;
    }else{
        ESP_LOGI(TAG, "Certificate verified.");
    }

    ESP_LOGI(TAG, "Cipher suite is %s", mbedtls_ssl_get_ciphersuite(&ssl));
    xEventGroupSetBits(tls_event_group, TLS_EG_CONNECTED);
    recv_bytes_avail = 0;

    return true;
}

uint16_t tls_layer::tls_read(uint8_t* buf, uint16_t len){
    int ret; 
    bzero(buf, len);
    
    /*while(recv_bytes_avail==0){
        ESP_LOGE(TAG, ".");
        vTaskDelay(pdMS_TO_TICKS(1000));
    }*/

    ret = mbedtls_ssl_read(&ssl, buf, len);    

    ESP_LOGW(TAG, "read returned: %x", ret);
    if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
        return 0;

    if(ret < 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_read returned -0x%x", -ret);
        return 0;
    }

    if(ret == 0)
    {
        ESP_LOGI(TAG, "connection closed");
        return 0;
    }

    len = ret;
    ESP_LOGI(TAG, "%d bytes read", len);
        
    uint16_t i = 0;
    while(i<len){
        ESP_LOGI("test", "%d - 0x%x - %c", i, buf[i], buf[i]);
        i++;
    }
    return len;
}

void tls_layer::tls_write(uint8_t* buf, uint16_t len){
    ESP_LOGI(TAG, "Writing HTTP request...");
    
    int ret; 

    int i = 0;
    while(i<len){
        ESP_LOGI(TAG, "%d - %02x - %c", i, buf[i], buf[i]);
        i++;
    }
    size_t written_bytes = 0;
    do {
        ret = mbedtls_ssl_write(&ssl,
                                buf + written_bytes,
                                len - written_bytes);
        ESP_LOGW(TAG, "write returned: %x", ret);
        if (ret >= 0) {
            ESP_LOGI(TAG, "%d bytes written", ret);
            written_bytes += ret;
        } else if (ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret != MBEDTLS_ERR_SSL_WANT_READ) {
            ESP_LOGE(TAG, "mbedtls_ssl_write returned -0x%x", -ret);
        }
    } while(written_bytes < len);
}

tls_layer::tls_layer(){
    tls_event_group = xEventGroupCreate();
    xSemaphore = xSemaphoreCreateBinary();
}

