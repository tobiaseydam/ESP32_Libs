#ifndef ESP32_HTTP_TEMPLATE
#define ESP32_HTTP_TEMPLATE

#include <stdio.h>
#include <string.h>
#include <esp_log.h>
#include "esp32_settings.hpp"

using namespace std;

class http_template{
    private:
        static constexpr char *TAG = (char*)"http_template";
        FILE* fp;
        string filename;
    public:
        http_template(string a_filename);
        ~http_template();
        string get_next_line();
        string get_first_line();
        bool has_next_line();
};

class http_template_processor{
    private:
        static constexpr char *TAG = (char*)"http_template_processor";
        http_template* t;
        settings_manager* sm;
        string next_line;
        string processed_line;
        uint16_t process_setting(uint16_t idx);
        uint16_t process_if(uint16_t idx);
        uint16_t process_var(uint16_t idx);
        uint16_t process_tag(uint16_t idx);
    public: 
        http_template_processor(http_template* templ, settings_manager* a_sm);
        void begin();
        string process_next_line();
        bool finish();
};

#endif