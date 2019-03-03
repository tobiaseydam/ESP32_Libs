#include "esp32_mqtt.hpp"

mqtt_dispatcher::mqtt_dispatcher(tls_layer *a_tls){
    tls = a_tls;
    outgoing_messages = xQueueCreate(10, sizeof(mqtt_message*));
    incomming_messages = xQueueCreate(10, sizeof(mqtt_message*));
}

void mqtt_dispatcher::add_outgoing_message(mqtt_message *msg){
    xQueueSend(outgoing_messages, (void *)&msg, pdMS_TO_TICKS(1000));
    cntr_outgoing_messages++;
}

mqtt_message* mqtt_dispatcher::get_next_outgoing_message(){
    mqtt_message *msg;
    xQueueReceive(outgoing_messages, &msg, pdMS_TO_TICKS(1000));
    cntr_outgoing_messages--;
    return msg;
}

bool mqtt_dispatcher::has_next_outgoing_message(){
    return cntr_outgoing_messages > 0;
}

mqtt_message* mqtt_dispatcher::get_next_incomming_message(){
    mqtt_message *msg;
    xQueueReceive(incomming_messages, &msg, pdMS_TO_TICKS(1000));
    cntr_incomming_messages--;
    return msg;
}

bool mqtt_dispatcher::has_next_incomming_message(){
    return cntr_incomming_messages > 0;
}

void mqtt_dispatcher::send_next_outgoing_message(){
    mqtt_message *msg;
    msg = get_next_outgoing_message();
    msg->explain();
    ESP_LOGI(TAG, "msg_len: %d", msg->get_message_len());
    tls->tls_write(msg->get_message(), msg->get_message_len());
    //delete(msg);
}

void mqtt_dispatcher::recv_next_incomming_message(){
    uint16_t len = 256;
    uint8_t* buf = new uint8_t[len];
    if(tls->tls_read(buf, len)>0){
        mqtt_message *msg = mqtt_message::create_message(buf, len);

        xQueueSend(incomming_messages, (void *)&msg, pdMS_TO_TICKS(1000));
        cntr_incomming_messages++;
        ESP_LOGI(TAG, "msg recv: ");
        msg->explain();
    }
    
}