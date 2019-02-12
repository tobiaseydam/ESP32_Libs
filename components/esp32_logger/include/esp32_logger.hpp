#ifndef ESP32_LOGGER_HPP
#define ESP32_LOGGER_HPP

#include <string>
#include <list> 
#include "esp_err.h"
#include "cJSON.h"

using namespace std;

typedef enum log_element_type{
    INTEGER,
    UINT16_T,
    DOUBLE,
    DS18B20
}log_element_type_t;

class log_element{
    private:
        string name;
        log_element_type_t type;
        void* pointer;
    public:
        log_element(string a_name, log_element_type_t a_type, void* a_pointer);
        string value_to_string();
        string get_name(){ return name;};
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
        list <log_element*> elements;
        log_config lc;
    public:
        log_manager(log_config alc);

        void add_element(log_element* e);
        void print_elements();
        string json_elements_to_string();
        list <log_element*>* get_list(){return &elements;};
};


#endif