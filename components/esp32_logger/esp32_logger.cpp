#include "esp32_logger.hpp"
#include <iterator> 
#include "esp_log.h"
#include "esp32_onewire.hpp"

log_element::log_element(string a_name, log_element_type_t a_type, void* a_pointer){
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

string log_element::value_to_string(){
    string res = "";
            char buffer[10];
    switch (type){
        case INTEGER:
            //res = std::to_string(*(int*)pointer);
            break;

        case UINT16_T:
            itoa(*(uint16_t*)pointer, buffer, 10);
            res = string(buffer);
            break;
    
        default:
            break;
    }
    return res;
}



void log_manager::add_element(log_element* e){
    elements.push_back(e);
}

void log_manager::print_elements(){
    list <log_element*>::iterator it;
    for(it = elements.begin(); it != elements.end(); ++it){
        ESP_LOGI(TAG, "%s = %s", (*it)->get_name().c_str() ,(*it)->value_to_string().c_str());
    }
}


string log_manager::json_elements_to_string(){
    list <log_element*>::iterator it;
    cJSON* e = cJSON_CreateObject();
    cJSON* items = cJSON_CreateArray();
    cJSON_AddItemToObject(e, "items", items);
    for(it = elements.begin(); it != elements.end(); ++it){
        cJSON *item = (*it)->to_JSON();
        cJSON_AddItemToArray(items, item);
    }
    string s = cJSON_Print(e);
    cJSON_Delete(e);
    return s;
}