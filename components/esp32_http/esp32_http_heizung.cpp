#include "esp32_http.hpp"
#include "esp32_http_template.hpp"


http_get_query_processor::http_get_query_processor(string buffer, settings_manager* sett_man){ 
    buf = buffer; 
    sm = sett_man;
};

void http_get_query_processor::process(){
    ESP_LOGI(TAG, "parsing %s", buf.c_str());

    uint16_t pos = 0;
    
    string cat  = "";
    string elem = "";
    string val  = "";

    while(pos < buf.length()){
        while((pos < buf.length())&(buf.substr(pos, 1).compare("-")!=0)){
            cat += buf[pos];
            pos++;
        }
        pos ++;
        while((pos < buf.length())&(buf.substr(pos, 1).compare("=")!=0)){
            elem += buf[pos];
            pos++;
        }
        pos++;
        while((pos < buf.length())&(buf.substr(pos, 1).compare("&")!=0)){
            val += buf[pos];
            pos++;
        }
        pos++;

        ESP_LOGI(TAG, "%s / %s : %s", cat.c_str(), elem.c_str(), val.c_str());

        sm->get(cat, elem)->set_string_value(val);

        cat  = "";
        elem = "";
        val  = "";
    }

    sm->save();
    
}

heizung_http_server::heizung_http_server(http_settings* as)
: default_http_server(as){
    ESP_LOGI("test - heizung_http_server", "%p", &as->get_settings_manager()->mapOfCategories);
}

void heizung_http_server::init(){
    default_http_server::init();

    http_uri_handler* h_settings = new http_uri_handler();
    h_settings->set_uri("/settings");
    h_settings->set_method(HTTP_GET);
    h_settings->set_handler((uri_handler_t)settings_handler);
    h_settings->set_user_ctx(s);
    register_uri_handler(*h_settings);
}


esp_err_t* heizung_http_server::settings_handler(httpd_req_t *req){
    http_settings* hs = (http_settings*)req->user_ctx;
    
    httpd_resp_set_type(req, "text/html");

    const uint8_t buf_len = httpd_req_get_url_query_len(req) + 1;
    char* buffer = new char[buf_len]; 

    if (httpd_req_get_url_query_str(req, buffer, buf_len) == ESP_OK) {
        http_get_query_processor p(buffer, hs->get_settings_manager());
        p.process();
    }


    http_template t = http_template("/spiffs/settings.html");
    http_template_processor tp = http_template_processor(&t, hs->get_settings_manager());
    tp.begin();
    ESP_LOGI(TAG, "begin response");
    while(!tp.finish()){
        string line = tp.process_next_line();
        //ESP_LOGI(TAG, "%s", line.c_str());
        httpd_resp_send_chunk(req, line.c_str(), line.length());
    }
    ESP_LOGI(TAG, "done response");
    
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}