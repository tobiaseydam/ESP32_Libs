#include "esp32_mqtt.hpp"


void mqtt_client::send_task(void* params){
    mqtt_dispatcher* disp = (mqtt_dispatcher*) params;
    
    ESP_LOGI(TAG, "STARTING AWS MQTT SEND TASK");
    while(1){
        if(disp->has_next_outgoing_message()){
            ESP_LOGI(TAG, "outgoing msg");
            disp->send_next_outgoing_message();     
            vTaskDelay(pdMS_TO_TICKS(1000));       
        }
    }
}

void mqtt_client::recv_task(void* params){
    mqtt_dispatcher* disp = (mqtt_dispatcher*) params;
    
    ESP_LOGI(TAG, "STARTING AWS MQTT RECV TASK");
    while(1){
        disp->recv_next_incomming_message();
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

void mqtt_client::handle_task(void* params){
    param_group_handle_task_t* p = (param_group_handle_task_t*) params;
    mqtt_dispatcher* disp = p->disp;
    
    ESP_LOGI(TAG, "STARTING AWS MQTT HANDLE TASK");
    while(1){
        if(disp->has_next_incomming_message()){
            ESP_LOGI(TAG, "incomming msg");
            handle_message(disp->get_next_incomming_message(), p->mqtt_cl);     
        }
    }
}

mqtt_client::mqtt_client(tls_layer *a_tls){
    tls = a_tls;
    mqtt_event_group = xEventGroupCreate();
}

void mqtt_client::init(){
    disp = new mqtt_dispatcher(tls);
    xTaskCreate( recv_task, "AWS MQTT RECV", 16*1024, disp, tskIDLE_PRIORITY, &xRecvHandle );

    param_group_handle_task_t* p = new param_group_handle_task();
    p->disp = disp;
    p->mqtt_cl = this;
    xTaskCreate( handle_task, "AWS HANDLE RECV", 16*1024, p, tskIDLE_PRIORITY, &xHndlHandle );
    xTaskCreate( send_task, "AWS MQTT SEND", 16*1024, disp, tskIDLE_PRIORITY, &xSendHandle );
   
}

bool mqtt_client::connect(){
    
    if(client_name.empty()){
        ESP_LOGI(TAG, "client name not set");
        return false;
    }

    ESP_LOGI(TAG, "creating connect message");

    mqtt_message_connect* m = new mqtt_message_connect(get_client_name(),
        get_will_retain(), get_will_qos(), get_will_flag(), 
        get_clean_session(), get_keep_alive());

    disp->add_outgoing_message(m);

    xEventGroupWaitBits(mqtt_event_group, MQTT_CONNECTED_BIT | MQTT_DISCONNECTED_BIT,
        false, false, portMAX_DELAY);

    return xEventGroupGetBits(mqtt_event_group) & MQTT_CONNECTED_BIT;
}

void mqtt_client::handle_message(protocol_message *msg, mqtt_client* cl){
    e_mqtt_message_type_t t = ((mqtt_message*)msg)->get_message_type();

    switch (t){
        case CONNACK:{
            mqtt_message_connack* m = (mqtt_message_connack*) msg;
            switch(m->get_return_code()){
                case 0:
                    ESP_LOGI(TAG, "Connection accepted");
                    xEventGroupSetBits(cl->mqtt_event_group, MQTT_CONNECTED_BIT);
                    xEventGroupClearBits(cl->mqtt_event_group, MQTT_DISCONNECTED_BIT);
                    break;
                case 1:
                    ESP_LOGI(TAG, "Connection Refused, unacceptable protocol version");
                    xEventGroupClearBits(cl->mqtt_event_group, MQTT_CONNECTED_BIT);
                    xEventGroupSetBits(cl->mqtt_event_group, MQTT_DISCONNECTED_BIT);
                    break;
                case 2:
                    ESP_LOGI(TAG, "Connection Refused, identifier rejected");
                    xEventGroupClearBits(cl->mqtt_event_group, MQTT_CONNECTED_BIT);
                    xEventGroupSetBits(cl->mqtt_event_group, MQTT_DISCONNECTED_BIT);
                    break;
                case 3:
                    ESP_LOGI(TAG, "Connection Refused, Server unavailable");
                    xEventGroupClearBits(cl->mqtt_event_group, MQTT_CONNECTED_BIT);
                    xEventGroupSetBits(cl->mqtt_event_group, MQTT_DISCONNECTED_BIT);
                    break;
                case 4:
                    ESP_LOGI(TAG, "Connection Refused, bad user name or password");
                    xEventGroupClearBits(cl->mqtt_event_group, MQTT_CONNECTED_BIT);
                    xEventGroupSetBits(cl->mqtt_event_group, MQTT_DISCONNECTED_BIT);
                    break;
                case 5:
                    ESP_LOGI(TAG, "Connection Refused, not authorized");
                    xEventGroupClearBits(cl->mqtt_event_group, MQTT_CONNECTED_BIT);
                    xEventGroupSetBits(cl->mqtt_event_group, MQTT_DISCONNECTED_BIT);
                    break;
                default:
                    ESP_LOGI(TAG, "Unknown return code");
                    xEventGroupClearBits(cl->mqtt_event_group, MQTT_CONNECTED_BIT);
                    xEventGroupSetBits(cl->mqtt_event_group, MQTT_DISCONNECTED_BIT);
                    break;
            }
        }
            break;
    
        default:
            break;
    }
}

void mqtt_client::publish(std::string topic, std::string payload, e_mqtt_qos_t qos){
    ESP_LOGI(TAG, "publishing message");
    
    mqtt_message_publish* m = new mqtt_message_publish(false, qos, false, 0,
        topic, payload);

    //mqtt_message_pingreq* m = new mqtt_message_pingreq();

    disp->add_outgoing_message(m);
    //m->explain();
}
