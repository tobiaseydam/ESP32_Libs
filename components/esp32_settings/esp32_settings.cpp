#include "esp32_settings.hpp"
#include <stdio.h>
#include "esp_log.h"
#include "cJSON.h"
#include "esp32_storage.hpp"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

#include <string>


string settings_enum::e_settings_name_to_str(e_settings_name val){
    switch (val){
        case WIFI_ACTIVE:
            return string("active");
            break;
        case WIFI_SSID:
            return string("ssid");
            break;
        case WIFI_PASS:
            return string("pass");
            break;
        case AWS_ENDPOINT:
            return string("endpoint");
            break;
        case AWS_MQTT_PORT:
            return string("mqtt_port");
            break;
        case AWS_GGD_PORT:
            return string("ggd_port");
            break;
        case AWS_GG_ENDPOINT:
            return string("gg_endpoint");
            break;
        case AWS_THING_NAME:
            return string("thing_name");
            break;
        case AWS_ROOT_CA:
            return string("root_ca");
            break;
        case AWS_GROUP_CA:
            return string("group_ca");
            break;
        case AWS_CLIENT_CERT:
            return string("client_cert");
            break;
        case AWS_PRVT_KEY:
            return string("prvt_key");
            break;
        default:
            return string("not implemented");
            break;
    }
}

string settings_enum::e_settings_category_to_str(e_settings_category val){
    switch (val){
        case WIFI:
            return string("wifi_settings");
            break;
        case AWS:
            return string("aws_settings");
            break;
        default:
            return string("not implemented");
            break;
    }
}

string settings_bool_element::get_string_value(){ 
    return value ? string("true") : string("false"); 
}

void settings_bool_element::set_string_value(string val){
    if(val.compare("true") == 0){
        value = true;
    }
} 

string settings_int_element::get_string_value(){ 
    char* intStr = new char[32];
    sprintf(intStr, "%d", value);
    return intStr; 
}

void settings_int_element::set_string_value(string val){
    try{
        value = atoi(val.c_str());
    }catch(...){
        value = 0;
    }
} 

void settings_category::insert(e_settings_name key, settings_element_p value){
    mapOfElements.insert(make_pair(key, value));
}

void settings_manager_heizung::init(){
    ESP_LOGI(TAG, "initializing settings");

    //-------------- WIFI ----------------

    settings_category_p wifi_category = new settings_category;
    mapOfCategories.insert(make_pair(WIFI, wifi_category));
    mapOfNames.insert(make_pair("wifi", WIFI));
    mapOfNames.insert(make_pair("WIFI", WIFI));

    settings_bool_element_p wifi_active = new settings_bool_element;
    wifi_active->set_bool_value(false);
    wifi_category->insert(WIFI_ACTIVE, wifi_active);
    wifi_category->mapOfNames.insert(make_pair("active", WIFI_ACTIVE));
    wifi_category->mapOfNames.insert(make_pair("ACTIVE", WIFI_ACTIVE));

    settings_string_element_p wifi_ssid = new settings_string_element;
    wifi_ssid->set_string_value("");
    wifi_category->insert(WIFI_SSID, wifi_ssid);
    wifi_category->mapOfNames.insert(make_pair("ssid", WIFI_SSID));
    wifi_category->mapOfNames.insert(make_pair("SSID", WIFI_SSID));
    
    settings_string_element_p wifi_pass = new settings_string_element;
    wifi_pass->set_string_value("");
    wifi_category->insert(WIFI_PASS, wifi_pass);
    wifi_category->mapOfNames.insert(make_pair("pass", WIFI_PASS));
    wifi_category->mapOfNames.insert(make_pair("PASS", WIFI_PASS));

    //-------------- AWS ----------------

    settings_category_p aws_category = new settings_category;
    mapOfCategories.insert(make_pair(AWS, aws_category));
    mapOfNames.insert(make_pair("aws", AWS));
    mapOfNames.insert(make_pair("AWS", AWS));

    settings_string_element_p aws_endpoint = new settings_string_element;
    aws_endpoint->set_string_value("");
    aws_category->insert(AWS_ENDPOINT, aws_endpoint);
    aws_category->mapOfNames.insert(make_pair("endpoint", AWS_ENDPOINT));
    aws_category->mapOfNames.insert(make_pair("ENDPOINT", AWS_ENDPOINT));

    settings_int_element_p aws_mqtt_port = new settings_int_element;
    aws_mqtt_port->set_int_value(0);
    aws_category->insert(AWS_MQTT_PORT, aws_mqtt_port);
    aws_category->mapOfNames.insert(make_pair("mqtt_port", AWS_MQTT_PORT));
    aws_category->mapOfNames.insert(make_pair("MQTT_PORT", AWS_MQTT_PORT));
    
    settings_int_element_p aws_ggd_port = new settings_int_element;
    aws_ggd_port->set_int_value(0);
    aws_category->insert(AWS_GGD_PORT, aws_ggd_port);
    aws_category->mapOfNames.insert(make_pair("ggd_port", AWS_GGD_PORT));
    aws_category->mapOfNames.insert(make_pair("GGD_PORT", AWS_GGD_PORT));

    settings_string_element_p aws_gg_endpoint = new settings_string_element;
    aws_gg_endpoint->set_string_value("");
    aws_category->insert(AWS_GG_ENDPOINT, aws_gg_endpoint);
    aws_category->mapOfNames.insert(make_pair("gg_endpoint", AWS_GG_ENDPOINT));
    aws_category->mapOfNames.insert(make_pair("GG_ENDPOINT", AWS_GG_ENDPOINT));
    
    settings_string_element_p aws_thing_name = new settings_string_element;
    aws_thing_name->set_string_value("");
    aws_category->insert(AWS_THING_NAME, aws_thing_name);
    aws_category->mapOfNames.insert(make_pair("thing_name", AWS_THING_NAME));
    aws_category->mapOfNames.insert(make_pair("THING_NAME", AWS_THING_NAME));

    settings_string_element_p aws_root_ca = new settings_string_element;
    aws_root_ca->set_string_value("");
    aws_category->insert(AWS_ROOT_CA, aws_root_ca);
    aws_category->mapOfNames.insert(make_pair("root_ca", AWS_ROOT_CA));
    aws_category->mapOfNames.insert(make_pair("ROOT_CA", AWS_ROOT_CA));

    settings_string_element_p aws_group_ca = new settings_string_element;
    aws_group_ca->set_string_value("");
    aws_category->insert(AWS_GROUP_CA, aws_group_ca);
    aws_category->mapOfNames.insert(make_pair("group_ca", AWS_GROUP_CA));
    aws_category->mapOfNames.insert(make_pair("GROUP_CA", AWS_GROUP_CA));

    settings_string_element_p aws_client_cert = new settings_string_element;
    aws_client_cert->set_string_value("");
    aws_category->insert(AWS_CLIENT_CERT, aws_client_cert);
    aws_category->mapOfNames.insert(make_pair("client_cert", AWS_CLIENT_CERT));
    aws_category->mapOfNames.insert(make_pair("CLIENT_CERT", AWS_CLIENT_CERT));

    settings_string_element_p aws_prvt_key = new settings_string_element;
    aws_prvt_key->set_string_value("");
    aws_category->insert(AWS_PRVT_KEY, aws_prvt_key);
    aws_category->mapOfNames.insert(make_pair("prvt_key", AWS_PRVT_KEY));
    aws_category->mapOfNames.insert(make_pair("PRVT_KEY", AWS_PRVT_KEY));
}

void settings_manager_heizung::load(){
    init();

    ESP_LOGI(TAG, "loading settings");
    FILE* file = fopen(SETTINGS_FILE, "r");
    if(file){
        uint32_t len = storage_adapter::get_file_size(SETTINGS_FILE);
        char *content = new char[len];

        memset(content, '\0', len);
        char buffer[32];
        while(fgets(buffer, 32 , file)){
            strcat(content, buffer);
        }
        ESP_LOGE(TAG, "SETTINGS-DATEI SCHLIESSEN !!!");
        //fclose(file);

        cJSON *cj_settings = cJSON_Parse(content);
        
        for( auto const& cat : mapOfCategories ){ 
            
            cJSON* cj_settings_cat = cJSON_GetObjectItemCaseSensitive(cj_settings, settings_enum::e_settings_category_to_str(cat.first).c_str());
            if(cj_settings_cat != NULL){
                
                for( auto const& elem : cat.second->mapOfElements ){
                    cJSON* cj_settings_elem = cJSON_GetObjectItemCaseSensitive(cj_settings_cat, settings_enum::e_settings_name_to_str(elem.first).c_str());
                    if(cj_settings_elem!=NULL){
                        elem.second->set_string_value(string(cJSON_GetStringValue(cj_settings_elem)));
                    }
                }    
            }
        } 
        cJSON_Delete(cj_settings);
    }
}

void settings_manager_heizung::save(){
    cJSON* cj_settings = cJSON_CreateObject();
    
    for( auto const& cat : mapOfCategories ){ 
        cJSON* cj_settings_cat = cJSON_CreateObject();
        cJSON_AddItemToObject(cj_settings, settings_enum::e_settings_category_to_str(cat.first).c_str(), cj_settings_cat);

        for( auto const& elem : cat.second->mapOfElements ){
            settings_element_p se = elem.second; 
            cJSON* cj_settings_elem = cJSON_CreateString(se->get_string_value().c_str());
            cJSON_AddItemToObject(cj_settings_cat, settings_enum::e_settings_name_to_str(elem.first).c_str(), cj_settings_elem);
        }
    }  

    FILE* f = fopen(SETTINGS_FILE, "w");
    fprintf(f, cJSON_Print(cj_settings));
    fclose(f);
    cJSON_Delete(cj_settings);
}

settings_element_p settings_manager::get(e_settings_category cat, e_settings_name elem){
    return mapOfCategories[cat]->mapOfElements[elem];
}

settings_element_p settings_manager::get(string cat, string elem){
    e_settings_category e_cat = mapOfNames[cat];
    e_settings_name e_elem = mapOfCategories[e_cat]->mapOfNames[elem];
    return get(e_cat, e_elem);
}