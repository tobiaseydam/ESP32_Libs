#include "esp32_http.hpp"
#include "esp_log.h"
#include "esp_event_loop.h"
#include "esp32_storage.hpp"
#include "esp_system.h"

default_http_server::default_http_server(http_settings as, string root_folder_name):http_server(as){
    rf = root_folder_name;
}

void default_http_server::init(){
    http_uri_handler* h_spiffs = new http_uri_handler();
    h_spiffs->set_uri("/spiffs");
    h_spiffs->set_method(HTTP_GET);
    h_spiffs->set_handler((uri_handler_t)spiffs_handler);
    h_spiffs->set_user_ctx(&rf);
    register_uri_handler(*h_spiffs);

    http_uri_handler* h_upload = new http_uri_handler();
    h_upload->set_uri("/upload");
    h_upload->set_method(HTTP_POST);
    h_upload->set_handler((uri_handler_t)upload_handler);
    h_upload->set_user_ctx(&rf);
    register_uri_handler(*h_upload);
}



esp_err_t* default_http_server::spiffs_handler(httpd_req_t *req){
    string* rf = (string*)req->user_ctx;
    char* resp = new char[127];

    const uint8_t buf_len = httpd_req_get_url_query_len(req) + 1;
    char* buffer = new char[buf_len]; 

    string action = "";
    string filename = "";

    if (httpd_req_get_url_query_str(req, buffer, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found URL query => %s", buffer);
            char param[32];
            if (httpd_query_key_value(buffer, "action", param, sizeof(param)) == ESP_OK) {
                action = param;
                ESP_LOGI(TAG, "Found URL query parameter => action=%s", param);
            }
            if (httpd_query_key_value(buffer, "file", param, sizeof(param)) == ESP_OK) {
                filename = param;
                ESP_LOGI(TAG, "Found URL query parameter => file=%s", param);
            }
    }

    if(action.compare("open")==0){
        FILE* f = fopen(filename.c_str(),"r");
        if(f != NULL){
            string ext = filename.substr(filename.find_last_of("."));
            if((ext.compare(".htm") == 0) || (ext.compare(".html") == 0)){
                httpd_resp_set_type(req, "text/html");
            }else{
                httpd_resp_set_type(req, "text");
                sprintf(resp, "File: %s \n\n", filename.c_str());
                httpd_resp_send_chunk(req, resp, strlen(resp));
            }
            while(fgets(resp, 127, f)){
                httpd_resp_send_chunk(req, resp, strlen(resp));
            }

            httpd_resp_send_chunk(req, NULL, 0);
            fclose(f);
        }else{
            sprintf(resp, "File not found: %s", filename.c_str());
            httpd_resp_send(req, resp, strlen(resp));
        }
        return ESP_OK;
    }

    if(action.compare("delete")==0){
        FILE* f = fopen(filename.c_str(),"r");
        if(f != NULL){
            fclose(f);
            remove(filename.c_str());
            sprintf(resp, "File deleted: %s<br><a href='/spiffs'>spiffs</a>", filename.c_str());
            httpd_resp_send(req, resp, strlen(resp));
        }else{
            sprintf(resp, "File not found: %s", filename.c_str());
            httpd_resp_send(req, resp, strlen(resp));
        }
        return ESP_OK;
    }

    httpd_resp_set_type(req, "text/html");
    strcpy(resp, "spiffs filesystem: <br>");
    httpd_resp_send_chunk(req, resp, strlen(resp));

    sprintf(resp, "<table>");
    httpd_resp_send_chunk(req, resp, strlen(resp));

    struct dirent *ent;
    DIR* root = opendir(rf->c_str());
    while ((ent = readdir(root)) != NULL) {
        sprintf(resp, "<tr><td>");
        httpd_resp_send_chunk(req, resp, strlen(resp));

        sprintf(resp, "<a href='?file=/spiffs/%s&action=open'>%s</a>", ent->d_name, ent->d_name);
        httpd_resp_send_chunk(req, resp, strlen(resp));
        
        sprintf(resp, "</td><td>");
        httpd_resp_send_chunk(req, resp, strlen(resp));

        char spiffs_filename[64];
        memset(spiffs_filename, '\0', 64);
        strcat(spiffs_filename, "/spiffs/");
        strcat(spiffs_filename, ent->d_name);
        sprintf(resp, "%ld Bytes", storage_adapter::get_file_size(spiffs_filename));
        httpd_resp_send_chunk(req, resp, strlen(resp));

        sprintf(resp, "</td><td>");
        httpd_resp_send_chunk(req, resp, strlen(resp));

        sprintf(resp, "<a href='?file=/spiffs/%s&action=delete'>delete</a>", ent->d_name);
        httpd_resp_send_chunk(req, resp, strlen(resp));
        
        sprintf(resp, "</td></tr>");
        httpd_resp_send_chunk(req, resp, strlen(resp));
    }

    sprintf(resp, "</table>");
    httpd_resp_send_chunk(req, resp, strlen(resp));

    sprintf(resp, "<form action=\"upload\" method=\"post\" enctype=\"multipart/form-data\">");
    httpd_resp_send_chunk(req, resp, strlen(resp));

    sprintf(resp, "<p><input type=\"file\" name=\"uploadfile\"></p>");
    httpd_resp_send_chunk(req, resp, strlen(resp));

    sprintf(resp, "<p><button type=\"submit\">upload</button></p>");
    httpd_resp_send_chunk(req, resp, strlen(resp));
    
    sprintf(resp, "</form>");
    httpd_resp_send_chunk(req, resp, strlen(resp));

    httpd_resp_send_chunk(req, NULL, 0);
    free(resp);
    return ESP_OK;
}

esp_err_t* default_http_server::upload_handler(httpd_req_t *req){
    string* rf = (string*)req->user_ctx;
    const uint8_t buffer_size = 128;
    char buffer[buffer_size];
    int remaining = req->content_len;

    char* resp = new char[127];

    ESP_LOGI(TAG, "content_len: %d", remaining);
    string line = "";
    esp_err_t ret;
    uint8_t i = 0;
    uint8_t sep_pos = 0, p1 = 0, p2 = 0;
    string filename = "";
    bool isHeader = true;
    FILE* f = NULL;
    while (remaining > 0) {
        memset(&buffer, 0, sizeof(buffer));
        if ((ret = httpd_req_recv(req, buffer, MIN(remaining, sizeof(buffer)))) < 0) {
            return ESP_OK;
        }
        i = 0;
        remaining -= ret;
        
        while (i<buffer_size){
            if(buffer[i]=='\n'){
                if((remaining==0)&&(i==ret-1)){
                    break; // letzte Zeile nicht ausgeben
                }
                if(isHeader){
                    ESP_LOGI(TAG, "%s", line.c_str());
                    if (line.length() == 1){   // Letzte Header-Zeile
                        isHeader = false;
                    }else{
                        if ((sep_pos = line.find(":")) != 255){
                            string field = line.substr(0, sep_pos);
                            string value = line.substr(sep_pos+2);
                            ESP_LOGI(TAG, "field: %s; value: %s", field.c_str(), value.c_str());
                            if(field.compare("Content-Disposition") == 0){
                                p1 = value.find("filename=\"") + 10;
                                p2 = value.find("\"", p1);
                                filename = value.substr(p1, p2-p1);
                                filename = *rf + "/" + filename;
                                f = fopen(filename.c_str(), "w");
                            }

                        }
                    }
                }else{
                    if(f){
                        fprintf(f, line.c_str());
                        fprintf(f, "\n");
                    }
                }
                line = "";
            }else{
                line += buffer[i];
            }
            i++;
        }

    }
    if(f){
        fclose(f);
        ESP_LOGI(TAG, "File written");
        sprintf(resp, "File written: %s<br><a href='/spiffs'>spiffs</a>", filename.c_str());
        httpd_resp_send(req, resp, strlen(resp));
        return ESP_OK;
    }
    
    return ESP_OK;
}




