#include "esp32_time.hpp"

#include <time.h>
#include <sys/time.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event_loop.h"
#include "esp_log.h"
#include "esp_attr.h"
#include "esp_sleep.h"
#include "nvs_flash.h"

#include "lwip/err.h"
#include "lwip/apps/sntp.h"

TaskHandle_t system_clock_task::handle = NULL;

void system_clock_task::set_task(void* param){
    system_clock* cl = (system_clock*)param;
    cl->init();
    vTaskDelete(handle);
}

system_clock_task::system_clock_task(EventGroupHandle_t event_group){
    c = new system_clock();
    c->set_event_group(event_group);
        
    xTaskCreate( set_task, "SYSTEM_CLOCK", 2048, c, tskIDLE_PRIORITY, &handle );
}

system_clock::system_clock(){

}

void system_clock::init(){
    time_t now1;
    struct tm timeinfo1;
    time(&now1);
    localtime_r(&now1, &timeinfo1);
    // Is time set? If not, tm_year will be (1970 - 1900).
    if (timeinfo1.tm_year < (2016 - 1900)) {
        ESP_LOGI(TAG, "Time is not set yet. Connecting to WiFi and getting time over NTP.");
        xEventGroupWaitBits(get_event_group(), GOT_IP_BIT, false, true, portMAX_DELAY);
        ESP_LOGI(TAG, "Initializing SNTP");
        sntp_setoperatingmode(SNTP_OPMODE_POLL);
        sntp_setservername(0, "pool.ntp.org");
        sntp_init();

        time_t now2 = 0;
        struct tm timeinfo2 = { 0 };
        int retry = 0;
        const int retry_count = 10;
        ESP_LOGI(TAG, "Waiting for system time to be set... ");
        while(timeinfo2.tm_year < (2016 - 1900) && ++retry < retry_count) {
            ESP_LOGI(TAG, ".");
            vTaskDelay(2000 / portTICK_PERIOD_MS);
            time(&now2);
            localtime_r(&now2, &timeinfo2);
        }
        // update 'now' variable with current time
        time(&now1);
    }
    setenv("TZ", "CST-1", 1);
    tzset();
    
    char strftime_buf[64];
    localtime_r(&now1, &timeinfo1);
    strftime(strftime_buf, sizeof(strftime_buf), "%c", &timeinfo1);
    ESP_LOGI(TAG, "Deutsche Winterzeit: %s", strftime_buf);
}