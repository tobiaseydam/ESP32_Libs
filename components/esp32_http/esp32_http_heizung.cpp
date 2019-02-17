#include "esp32_http.hpp"
#include "esp32_http_template.hpp"


void http_get_query_processor::replaceAll(string& str, const string& from, const string& to) {
    if(from.empty())
        return;
    size_t start_pos = 0;
    while((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); // In case 'to' contains 'from', like replacing 'x' with 'yx'
    }
}

http_get_query_processor::http_get_query_processor(string buffer, settings_manager* sett_man){ 
    buf = buffer; 
    replaceAll(buf, "%2F", "/");
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

    char* buf = new char[512];
    uint16_t len = 0;

    httpd_req_recv(req, buf, len);
    buf[len] = '\0';
    ESP_LOGI(TAG, "%s", buf);

    const uint8_t buf_len = httpd_req_get_url_query_len(req) + 1;
    char* buffer = new char[buf_len]; 

    if (httpd_req_get_url_query_str(req, buffer, buf_len) == ESP_OK) {
        http_get_query_processor p(buffer, hs->get_settings_manager());
        p.process();
        string line = "Einstellungen gespeichert, starte neu";
        httpd_resp_send_chunk(req, line.c_str(), line.length());
        httpd_resp_send_chunk(req, NULL, 0);
        esp_restart();
    }


    http_template t = http_template("/spiffs/settings.html");
    http_template_processor tp = http_template_processor(&t, hs->get_settings_manager());
    tp.begin();
    ESP_LOGI(TAG, "begin response");
    string line;
    while(!tp.finish()){
        line = tp.process_next_line();
        httpd_resp_send_chunk(req, line.c_str(), line.length());
    }
    ESP_LOGI(TAG, "done response");
    
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}