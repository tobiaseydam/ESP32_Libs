#include "esp32_logger.hpp"
#include <iterator> 
#include "esp32_onewire.hpp"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include <lwip/netdb.h>

#include <string.h>

log_element::log_element(std::string a_name, log_element_type_t a_type, void* a_pointer){
    name = a_name;
    type = a_type;
    pointer = a_pointer;
}

cJSON* log_element::to_JSON(){
    cJSON* e = cJSON_CreateObject();
    cJSON_AddItemToObject(e, "name", cJSON_CreateString(name.c_str()));
    switch (type){
        case DS18B20:{
            onewire_device* d = (onewire_device*) pointer;
            cJSON_AddItemToObject(e, "address", cJSON_CreateString(d->addr_to_string().c_str()));
            cJSON_AddItemToObject(e, "data", cJSON_CreateString(d->data_to_string().c_str()));
            cJSON_AddItemToObject(e, "value", cJSON_CreateNumber(d->get_temperature()));
            cJSON_AddItemToObject(e, "readings", cJSON_CreateNumber(d->get_readings()));
            cJSON_AddItemToObject(e, "fails", cJSON_CreateNumber(d->get_fails()));
            break;
        }     
        default:
            break;
    }
    return e;
}

std::string log_element::value_to_string(){
    std::string res = "";
            char buffer[10];
    switch (type){
        case INTEGER:
            //res = std::to_string(*(int*)pointer);
            break;

        case UINT16_T:
            itoa(*(uint16_t*)pointer, buffer, 10);
            res = std::string(buffer);
            break;
    
        default:
            break;
    }
    return res;
}

log_manager::log_manager(log_config alc){
    lc = alc;
}

void log_manager::add_element(log_element* e){
    elements.push_back(e);
}

void log_manager::print_elements(){
    std::list <log_element*>::iterator it;
    for(it = elements.begin(); it != elements.end(); ++it){
        ESP_LOGI(TAG, "%s = %s", (*it)->get_name().c_str() ,(*it)->value_to_string().c_str());
    }
}


std::string log_manager::json_elements_to_string(){
    std::list <log_element*>::iterator it;
    cJSON* e = cJSON_CreateObject();
    cJSON* state = cJSON_CreateObject();
    cJSON_AddItemToObject(e, "state", state);
    cJSON* reported = cJSON_CreateObject();
    cJSON_AddItemToObject(state, "reported", reported);
    cJSON* items = cJSON_CreateArray();
    cJSON_AddItemToObject(reported, "items", items);
    for(it = elements.begin(); it != elements.end(); ++it){
        cJSON *item = (*it)->to_JSON();
        cJSON_AddItemToArray(items, item);
    }
    std::string s = cJSON_Print(e);
    cJSON_Delete(e);
    return s;
}

QueueHandle_t websocket_server::client_queue = NULL;
int websocket_server::port = 0;
vprintf_like_t websocket_server::orig_print_func = NULL;

websocket_server::websocket_server(int a_port){
    port = a_port;
}

void websocket_server::websocket_callback(uint8_t num,WEBSOCKET_TYPE_t type,char* msg,uint64_t len) {
    const static char* TAG = "websocket_callback";
    int value;

    switch(type) {
        case WEBSOCKET_CONNECT:
            ESP_LOGI(TAG,"client %d connected!",num);
            ws_server_send_text_all_from_callback(msg, len);
            break;
        case WEBSOCKET_DISCONNECT_EXTERNAL:
            ESP_LOGI(TAG,"client %d sent a disconnect message",num);
            break;
        case WEBSOCKET_DISCONNECT_INTERNAL:
            ESP_LOGI(TAG,"client %d was disconnected",num);
            break;
        case WEBSOCKET_DISCONNECT_ERROR:
            ESP_LOGI(TAG,"client %d was disconnected due to an error",num);
            break;
        case WEBSOCKET_TEXT:
            if(len) {
                ESP_LOGI(TAG,"%s",msg);
            }
            break;
        case WEBSOCKET_BIN:
            ESP_LOGI(TAG,"client %d sent binary message of size %d:\n%s",num,(uint32_t)len,msg);
            break;
        case WEBSOCKET_PING:
            ESP_LOGI(TAG,"client %d pinged us with message of size %d:\n%s",num,(uint32_t)len,msg);
            break;
        case WEBSOCKET_PONG:
            ESP_LOGI(TAG,"client %d responded to the ping",num);
            break;
    }
}

void websocket_server::http_serve(struct netconn *conn){
    struct netbuf* inbuf;
    static char* buf;
    static uint16_t buflen;
    static err_t err;
    netconn_set_recvtimeout(conn,1000); // allow a connection timeout of 1 second
    ESP_LOGI(TAG,"reading from client...");
    err = netconn_recv(conn, &inbuf);
    ESP_LOGI(TAG,"read from client");
    if(err==ERR_OK) {
        netbuf_data(inbuf, (void**)&buf, &buflen);
        if(buf) {
            if(strstr(buf,"GET / ")
                && strstr(buf,"Upgrade: websocket")) {
                ESP_LOGI(TAG,"Requesting websocket on /");
                ws_server_add_client(conn,buf,buflen,"/",websocket_callback);
                netbuf_delete(inbuf);
            }
        }
    }
}

void websocket_server::server_task(void* pvParameters) {
  const static char* TAG = "server_task";
  struct netconn *conn, *newconn;
  static err_t err;
  client_queue = xQueueCreate(10,sizeof(struct netconn*));

  conn = netconn_new(NETCONN_TCP);
  netconn_bind(conn,NULL,port);
  netconn_listen(conn);
  ESP_LOGI(TAG,"server listening");
  do {
    err = netconn_accept(conn, &newconn);
    ESP_LOGI(TAG,"new client");
    if(err == ERR_OK) {
      xQueueSendToBack(client_queue,&newconn,portMAX_DELAY);
      //http_serve(newconn);
    }
  } while(err == ERR_OK);
  netconn_close(conn);
  netconn_delete(conn);
  ESP_LOGE(TAG,"task ending, rebooting board");
  esp_restart();
}

void websocket_server::server_handle_task(void* pvParameters) {
  const static char* TAG = "server_handle_task";
  struct netconn* conn;
  ESP_LOGI(TAG,"task starting");
  for(;;) {
    xQueueReceive(client_queue,&conn,portMAX_DELAY);
    if(!conn) continue;
    http_serve(conn);
  }
  vTaskDelete(NULL);
}

void websocket_server::run(){
    ws_server_start();
    xTaskCreate(&server_task,"server_task",3000,NULL,tskIDLE_PRIORITY,NULL);
    xTaskCreate(&server_handle_task,"server_handle_task",4000,NULL,tskIDLE_PRIORITY,NULL);
    vTaskDelay(pdMS_TO_TICKS(5000));
    orig_print_func = esp_log_set_vprintf(vprintf);
    esp_log_set_vprintf(ws_vprintf);

}


int websocket_server::ws_vprintf( const char *str, va_list l ) {
    orig_print_func(str, l);
    
    char *buf = new char[256];
    int res = vsprintf(buf, str, l);
    
    ws_server_send_text_all_from_callback(buf, strlen(buf));

    return res;
}