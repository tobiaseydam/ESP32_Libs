#include "esp32_http.hpp"
#include "esp_log.h"
#include "esp_event_loop.h"
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
    strcpy(resp, "spiffs filesystem: <br>");
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
        sprintf(resp, "0 Bytes");
        httpd_resp_send_chunk(req, resp, strlen(resp));

        sprintf(resp, "</td><td>");
        httpd_resp_send_chunk(req, resp, strlen(resp));

        sprintf(resp, "<a href='?file=/spiffs/%s&action=delete'>delete</a>", ent->d_name);
        httpd_resp_send_chunk(req, resp, strlen(resp));
        
        sprintf(resp, "</td></tr>");
        httpd_resp_send_chunk(req, resp, strlen(resp));
    }

    httpd_resp_send_chunk(req, NULL, 0);
    free(resp);
    return ESP_OK;
}

esp_err_t* default_http_server::upload_handler(httpd_req_t *req){
    string* rf = (string*)req->user_ctx;
    const uint8_t buffer_size = 128;
    char buffer[buffer_size];
    int remaining = req->content_len;

    const char* resp = "URI POST Response";

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
    }
    httpd_resp_send(req, resp, strlen(resp));
    return ESP_OK;
}

