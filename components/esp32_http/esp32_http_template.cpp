#include "esp32_http_template.hpp"

http_template::http_template(string a_filename){
    filename = a_filename;
    fp = fopen(filename.c_str(), "r");
}

http_template::~http_template(){
    fclose(fp);
}

string http_template::get_first_line(){
    fseek(fp ,0 ,SEEK_SET);
    return get_next_line();
}

string http_template::get_next_line(){
    int c;
    string res = "";
    do{
        c = fgetc(fp);
        res += c;
    }while((c!=EOF)&&(c!='\n'));
    return res;
}


bool http_template::has_next_line(){
    return !feof(fp);
}

http_template_processor::http_template_processor(http_template* templ, settings_manager* a_sm){
    t = templ;
    sm = a_sm;
}

void http_template_processor::begin(){
    next_line = t->get_first_line();
}


uint16_t http_template_processor::process_setting(uint16_t pos){
    ESP_LOGI(TAG, "processing setting: %s", next_line.substr(pos).c_str());
    uint16_t p1 = next_line.find("[", pos);
    uint16_t p2 = next_line.find("]", p1);
    uint16_t p3 = next_line.find("[", p2);
    uint16_t p4 = next_line.find("]", p3);

    string cat  = next_line.substr(p1+1, p2-p1-1);
    string elem = next_line.substr(p3+1, p4-p3-1);

    ESP_LOGI(TAG, "setting: %s -> %s", cat.c_str(), elem.c_str());
    ESP_LOGI(TAG, "setting: %s", sm->get(cat, elem)->get_string_value().c_str());
    
    processed_line += sm->get(cat.c_str(), elem.c_str())->get_string_value();
    
    return p4+1;
}

uint16_t http_template_processor::process_tag(uint16_t pos){
    ESP_LOGI(TAG, "processing tag: %s", next_line.substr(pos).c_str());
    while(pos < next_line.length()){
        if(next_line.substr(pos, 3).compare(" #>")==0){
            return pos + 3;
        }else if(next_line.substr(pos, 7).compare("setting")==0){
            pos = process_setting(pos+7);
        }else{
            processed_line += next_line[pos];
            pos++;
        }
    }
    ESP_LOGI(TAG, "invalid pattern: %s", next_line.c_str());
    return pos;
}

string http_template_processor::process_next_line(){
    processed_line = "";
    uint16_t pos = 0;

    while(pos < next_line.length()){
        if(next_line.substr(pos, 3).compare("<# ")==0){
            pos = process_tag(pos+3);
        }else{
            processed_line += next_line[pos];
            pos++;
        }
    }

    next_line = t->get_next_line();
    return processed_line;
}

bool http_template_processor::finish(){
    return !t->has_next_line();
}