#include "esp32_settings.hpp"
#include <stdio.h>
#include "esp_log.h"
#include "cJSON.h"
#include "esp32_storage.hpp"



string settings_enum::e_settings_name_to_str(e_settings_name val){
    switch (val){
        case WIFI_ACTIVE:
            return string("wifi_active");
            break;
        case WIFI_SSID:
            return string("wifi_ssid");
            break;
        case WIFI_PASS:
            return string("wifi_pass");
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

void settings_category::insert(e_settings_name key, settings_element_p value){
    mapOfElements.insert(make_pair(key, value));
}

void settings_manager_heizung::init(){
    ESP_LOGI(TAG, "initializing settings");

    settings_category_p wifi_category = new settings_category;
    mapOfCategories.insert(make_pair(WIFI, wifi_category));
    mapOfNames.insert(make_pair("wifi", WIFI));
    mapOfNames.insert(make_pair("WIFI", WIFI));

    settings_bool_element_p wifi_active = new settings_bool_element;
    wifi_active->set_bool_value(false);
    wifi_category->insert(WIFI_ACTIVE, wifi_active);
    wifi_category->mapOfNames.insert(make_pair("wifi_active", WIFI_ACTIVE));
    wifi_category->mapOfNames.insert(make_pair("WIFI_ACTIVE", WIFI_ACTIVE));

    settings_string_element_p wifi_ssid = new settings_string_element;
    wifi_ssid->set_string_value("ssid");
    wifi_category->insert(WIFI_SSID, wifi_ssid);
    wifi_category->mapOfNames.insert(make_pair("wifi_ssid", WIFI_SSID));
    wifi_category->mapOfNames.insert(make_pair("WIFI_SSID", WIFI_SSID));
    
    settings_string_element_p wifi_pass = new settings_string_element;
    wifi_pass->set_string_value("pass");
    wifi_category->insert(WIFI_PASS, wifi_pass);
    wifi_category->mapOfNames.insert(make_pair("wifi_pass", WIFI_PASS));
    wifi_category->mapOfNames.insert(make_pair("WIFI_PASS", WIFI_PASS));
    
}

void settings_manager_heizung::load(){
    init();

    ESP_LOGI(TAG, "loading settings");
    FILE* file = fopen(SETTINGS_FILE, "r");
    if(file){
        uint16_t len = storage_adapter::get_file_size(SETTINGS_FILE);
        char *content = new char[len]();
        memset(content, '\0', len);
            char buffer[32];
            while(fgets(buffer, 32 , file)){
                strcat(content, buffer);
            }
        fclose(file);

        cJSON *cj_settings = cJSON_Parse(content);
        
        for( auto const& cat : mapOfCategories ){ 
            cJSON* cj_settings_cat = cJSON_GetObjectItemCaseSensitive(cj_settings, settings_enum::e_settings_category_to_str(cat.first).c_str());
            
            for( auto const& elem : cat.second->mapOfElements ){
                cJSON* cj_settings_elem = cJSON_GetObjectItemCaseSensitive(cj_settings_cat, settings_enum::e_settings_name_to_str(elem.first).c_str());
                elem.second->set_string_value(string(cJSON_GetStringValue(cj_settings_elem)));
            }
        } 
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