#include "esp32_ip.hpp"
#include "esp_log.h"
#include "esp_err.h"
#include "nvs_flash.h"
#include "esp_event_loop.h"
#include "esp_wifi.h"
#include <string.h>

#include "driver/gpio.h"
#include "driver/periph_ctrl.h"
#include "eth_phy/phy_lan8720.h"

esp_err_t layer2_adapter::event_handler(void *ctx, system_event_t *event){
    switch(event->event_id) {
        case SYSTEM_EVENT_WIFI_READY:               /**< ESP32 WiFi ready */
            ESP_LOGI(TAG, "SYSTEM_EVENT_WIFI_READY");
            break;

        case SYSTEM_EVENT_SCAN_DONE:                /**< ESP32 finish scanning AP */
            ESP_LOGI(TAG, "SYSTEM_EVENT_SCAN_DONE");
            break;

        case SYSTEM_EVENT_STA_START:{               /**< ESP32 station start */
            ESP_LOGI(TAG, "SYSTEM_EVENT_STA_START");
            wifi_settings *ws = (wifi_settings*)ctx;
            ESP_ERROR_CHECK(esp_wifi_connect());
            ws->inc_current_try();
            break;
        }

        case SYSTEM_EVENT_STA_STOP:                 /**< ESP32 station stop */
            ESP_LOGI(TAG, "SYSTEM_EVENT_STA_STOP");
            break;

        case SYSTEM_EVENT_STA_CONNECTED:{           /**< ESP32 station connected to AP */
            ESP_LOGI(TAG, "SYSTEM_EVENT_STA_CONNECTED");
            wifi_settings *ws = (wifi_settings*)ctx;
            ws->reset_current_try();
            break;
        }

        case SYSTEM_EVENT_STA_DISCONNECTED:{        /**< ESP32 station disconnected from AP */
            ESP_LOGI(TAG, "SYSTEM_EVENT_STA_DISCONNECTED");
            wifi_settings *ws = (wifi_settings*)ctx;
            if(ws->get_current_try()<ws->get_max_tries()){
                ESP_ERROR_CHECK(esp_wifi_connect());
                ws->inc_current_try();
            }
            break;
        }

        case SYSTEM_EVENT_STA_AUTHMODE_CHANGE:      /**< the auth mode of AP connected by ESP32 station changed */
            ESP_LOGI(TAG, "SYSTEM_EVENT_STA_AUTHMODE_CHANGE");
            break;

        case SYSTEM_EVENT_STA_GOT_IP:               /**< ESP32 station got IP from connected AP */
            ESP_LOGI(TAG, "SYSTEM_EVENT_STA_GOT_IP");
            break;

        case SYSTEM_EVENT_STA_LOST_IP:              /**< ESP32 station lost IP and the IP is reset to 0 */
            ESP_LOGI(TAG, "SYSTEM_EVENT_STA_LOST_IP");
            break;

        case SYSTEM_EVENT_STA_WPS_ER_SUCCESS:       /**< ESP32 station wps succeeds in enrollee mode */
            ESP_LOGI(TAG, "SYSTEM_EVENT_STA_WPS_ER_SUCCESS");
            break;

        case SYSTEM_EVENT_STA_WPS_ER_FAILED:        /**< ESP32 station wps fails in enrollee mode */
            ESP_LOGI(TAG, "SYSTEM_EVENT_STA_WPS_ER_FAILED");
            break;

        case SYSTEM_EVENT_STA_WPS_ER_TIMEOUT:       /**< ESP32 station wps timeout in enrollee mode */
            ESP_LOGI(TAG, "SYSTEM_EVENT_STA_WPS_ER_TIMEOUT");
            break;

        case SYSTEM_EVENT_STA_WPS_ER_PIN:           /**< ESP32 station wps pin code in enrollee mode */
            ESP_LOGI(TAG, "SYSTEM_EVENT_STA_WPS_ER_PIN");
            break;

        case SYSTEM_EVENT_AP_START:                 /**< ESP32 soft-AP start */
            ESP_LOGI(TAG, "SYSTEM_EVENT_AP_START");
            break;

        case SYSTEM_EVENT_AP_STOP:                  /**< ESP32 soft-AP stop */
            ESP_LOGI(TAG, "SYSTEM_EVENT_AP_STOP");
            break;

        case SYSTEM_EVENT_AP_STACONNECTED:          /**< a station connected to ESP32 soft-AP */
            ESP_LOGI(TAG, "SYSTEM_EVENT_AP_STACONNECTED");
            break;

        case SYSTEM_EVENT_AP_STADISCONNECTED:       /**< a station disconnected from ESP32 soft-AP */
            ESP_LOGI(TAG, "SYSTEM_EVENT_AP_STADISCONNECTED");
            break;

        case SYSTEM_EVENT_AP_STAIPASSIGNED:         /**< ESP32 soft-AP assign an IP to a connected station */
            ESP_LOGI(TAG, "SYSTEM_EVENT_AP_STAIPASSIGNED");
            break;

        case SYSTEM_EVENT_AP_PROBEREQRECVED:        /**< Receive probe request packet in soft-AP interface */
            ESP_LOGI(TAG, "SYSTEM_EVENT_AP_PROBEREQRECVED");
            break;

        case SYSTEM_EVENT_GOT_IP6:                  /**< ESP32 station or ap or ethernet interface v6IP addr is preferred */
            ESP_LOGI(TAG, "SYSTEM_EVENT_GOT_IP6");
            break;

        case SYSTEM_EVENT_ETH_START:                /**< ESP32 ethernet start */
            ESP_LOGI(TAG, "SYSTEM_EVENT_ETH_START");
            break;

        case SYSTEM_EVENT_ETH_STOP:                 /**< ESP32 ethernet stop */
            ESP_LOGI(TAG, "SYSTEM_EVENT_ETH_STOP");
            break;

        case SYSTEM_EVENT_ETH_CONNECTED:            /**< ESP32 ethernet phy link up */
            ESP_LOGI(TAG, "SYSTEM_EVENT_ETH_CONNECTED");
            break;

        case SYSTEM_EVENT_ETH_DISCONNECTED:         /**< ESP32 ethernet phy link down */
            ESP_LOGI(TAG, "SYSTEM_EVENT_ETH_DISCONNECTED");
            break;

        case SYSTEM_EVENT_ETH_GOT_IP:{               /**< ESP32 ethernet got IP from connected AP */
            ESP_LOGI(TAG, "SYSTEM_EVENT_ETH_GOT_IP");
            ip_settings* s = (ip_settings*)ctx;
            if(s->is_got_ip_callback_set()){
                ESP_LOGI(TAG, "executing got_ip_callback");
                s->get_got_ip_callback()(s->get_got_ip_callback_ctx());
            }
            break;
        }

        case SYSTEM_EVENT_MAX:
            ESP_LOGI(TAG, "SYSTEM_EVENT_MAX");
            break;
    }
    return ESP_OK;
}

wifi_adapter::wifi_adapter(wifi_settings as){
    s = as;
}

void wifi_adapter::init(){
    ESP_LOGI(TAG, "WiFi initializing...");
    esp_err_t ret = nvs_flash_init();
    if(ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND){
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    tcpip_adapter_init();
    ESP_ERROR_CHECK(esp_event_loop_init(event_handler, &s));
}

void wifi_adapter::start(){
    wifi_init_config_t cfg;
    cfg.event_handler = &esp_event_send;
    cfg.osi_funcs = &g_wifi_osi_funcs;
    cfg.wpa_crypto_funcs = g_wifi_default_wpa_crypto_funcs;
    cfg.static_rx_buf_num = CONFIG_ESP32_WIFI_STATIC_RX_BUFFER_NUM;
    cfg.dynamic_rx_buf_num = CONFIG_ESP32_WIFI_DYNAMIC_RX_BUFFER_NUM;
    cfg.tx_buf_type = CONFIG_ESP32_WIFI_TX_BUFFER_TYPE;
    cfg.static_tx_buf_num = WIFI_STATIC_TX_BUFFER_NUM;
    cfg.dynamic_tx_buf_num = WIFI_DYNAMIC_TX_BUFFER_NUM;
    cfg.csi_enable = WIFI_CSI_ENABLED;
    cfg.ampdu_rx_enable = WIFI_AMPDU_RX_ENABLED;
    cfg.ampdu_tx_enable = WIFI_AMPDU_TX_ENABLED;
    cfg.nvs_enable = WIFI_NVS_ENABLED;
    cfg.nano_enable = WIFI_NANO_FORMAT_ENABLED;
    cfg.tx_ba_win = WIFI_DEFAULT_TX_BA_WIN;
    cfg.rx_ba_win = WIFI_DEFAULT_RX_BA_WIN;
    cfg.wifi_task_core_id = WIFI_TASK_CORE_ID;
    cfg.beacon_max_len = WIFI_SOFTAP_BEACON_MAX_LEN;
    cfg.magic = WIFI_INIT_CONFIG_MAGIC;
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));

    wifi_config_t wifi_config;
    memset(&wifi_config, 0, sizeof(wifi_config));  
    const char* ssid = s.get_ssid().c_str();
    const char* pass = s.get_pass().c_str();

    switch (s.get_l2p()){
        case WIFI_STA:
            ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
            memcpy(wifi_config.sta.ssid, ssid, strlen(ssid));
            memcpy(wifi_config.sta.password, pass, strlen(pass));
            wifi_config.sta.bssid_set = false;
            ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
            ESP_ERROR_CHECK(esp_wifi_start());
            break;
    
        case WIFI_AP:
            ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
            memcpy(wifi_config.ap.ssid, ssid, strlen(ssid));
            wifi_config.ap.ssid_len = strlen(ssid);
            memcpy(wifi_config.ap.password, pass, strlen(pass));
            wifi_config.ap.max_connection = 5;
            wifi_config.ap.authmode = WIFI_AUTH_WPA_WPA2_PSK;
            ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
            ESP_ERROR_CHECK(esp_wifi_start());
            break;

        default:
            break;
    }
}

void wifi_adapter::stop(){
}

eth_adapter::eth_adapter(eth_settings as){
    s = new eth_settings(as);
}

void eth_adapter::eth_gpio_config_rmii(){
    phy_rmii_configure_data_interface_pins();
    phy_rmii_smi_configure_pins(23, 18);
}

void eth_adapter::init(){
    tcpip_adapter_init();
    ESP_ERROR_CHECK(esp_event_loop_init(event_handler, s));
}

void eth_adapter::start(){
    eth_config_t config;
    memset(&config, 0, sizeof(config)); 
    config.phy_addr = (eth_phy_base_t)0;
    config.mac_mode = ETH_MODE_RMII;
    config.clock_mode = ETH_CLOCK_GPIO0_IN;
    config.flow_ctrl_enable = true;
    config.phy_init = phy_lan8720_init;
    config.phy_check_init = phy_lan8720_check_phy_init;
    config.phy_power_enable = phy_lan8720_power_enable;
    config.phy_check_link = phy_mii_check_link_status;
    config.phy_get_speed_mode = phy_lan8720_get_speed_mode;
    config.phy_get_duplex_mode = phy_lan8720_get_duplex_mode;
    config.phy_get_partner_pause_enable = phy_mii_get_partner_pause_enable;
    config.gpio_config = eth_gpio_config_rmii;
    config.tcpip_input = tcpip_adapter_eth_input;
    ESP_ERROR_CHECK(esp_eth_init(&config));
    ESP_ERROR_CHECK(esp_eth_enable()) ;
}

void eth_adapter::stop(){
}