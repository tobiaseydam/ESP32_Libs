#ifndef ESP32_LOGGER_HPP
#define ESP32_LOGGER_HPP

#include <string>
#include <list> 
#include "esp_err.h"
#include "cJSON.h"
#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"

#include "websocket_server.h"
#include "websocket.h"

typedef enum log_element_type{
    INTEGER,
    UINT16_T,
    DOUBLE,
    DS18B20
}log_element_type_t;

class log_element{
    private:
        std::string name;
        log_element_type_t type;
        void* pointer;
    public:
        log_element(std::string a_name, log_element_type_t a_type, void* a_pointer);
        std::string value_to_string();
        std::string get_name(){ return name;};
        cJSON* to_JSON();
};

class log_config{
    private:
        bool log_to_aws = false;
    public:
        void set_log_to_aws(bool value){ log_to_aws = value; };
        bool get_log_to_aws(){ return log_to_aws; };
};

class log_manager{
    private:
        static constexpr char *TAG = (char*)"log_manager";
        std::list <log_element*> elements;
        log_config lc;
    public:
        log_manager(log_config alc);

        void add_element(log_element* e);
        void print_elements();
        std::string json_elements_to_string();
        std::list <log_element*>* get_list(){return &elements;};
};

class websocket_server_task{
    private:
        static constexpr char *TAG = (char*)"websocket_server_task";
    public:
};

class websocket_server{
    private:
        static constexpr char *TAG = (char*)"websocket_server";
        static void server_task(void* pvParameters);
        static void server_handle_task(void* pvParameters);
        static void run_task(void* params);
        static QueueHandle_t client_queue;
        static void http_serve(struct netconn *conn);
        static void websocket_callback(uint8_t num, WEBSOCKET_TYPE_t type,char* msg,uint64_t len);
        static int port;
        static int ws_vprintf( const char *str, va_list l );
        static vprintf_like_t orig_print_func;
    public:
        websocket_server(int a_port);
        void run();
};

#endif