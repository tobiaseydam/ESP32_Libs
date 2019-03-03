#ifndef ESP32_MQTT_HPP
#define ESP32_MQTT_HPP

#include <string>
#include <string.h>
#include <stdio.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/queue.h"
#include "esp32_tls.hpp"

#define MQTT_CONNECTED_BIT      BIT0
#define MQTT_DISCONNECTED_BIT   BIT1


class mqtt_client;
class mqtt_dispatcher;

typedef enum e_mqtt_message_type{
    CONNECT     =  1,
    CONNACK     =  2,
    PUBLISH     =  3,
    PUBACK      =  4,
    PUBREC      =  5,
    PUBREL      =  6,
    PUBCOMP     =  7,
    SUBSCRIBE   =  8,
    SUBACK      =  9,
    UNSUBSCRIBE = 10,
    UNSUBACK    = 11,
    PINGREQ     = 12,
    PINGRESP    = 13,
    DISCONNECT  = 14,
    ERROR       = 100
}e_mqtt_message_type_t;

typedef enum e_mqtt_qos{
    eQOS0        =  0,
    eQOS1        =  1,
    eQOS2        =  2
}e_mqtt_qos_t;

class mqtt_fixed_header{
    private:
        static constexpr char *TAG = (char*)"mqtt_fixed_header";
        e_mqtt_message_type_t msg_type;
        e_mqtt_qos_t qos;
        bool retain;
        bool dub;
        uint32_t len;
        uint8_t get_byte_1();
        uint8_t header_len;
        uint8_t* encodedData;
    public: 
        mqtt_fixed_header(e_mqtt_message_type_t a_msg_type,
            e_mqtt_qos_t a_qos, bool a_retain, bool a_dub, uint32_t a_len);

        mqtt_fixed_header(uint8_t* msg);

        uint8_t* get_header();
        uint8_t get_length(){ return header_len; };

        e_mqtt_message_type_t get_msg_type(){ return msg_type; };
        e_mqtt_qos_t get_qos(){ return qos; };
        bool get_retain(){ return retain; };
        bool get_dub(){ return dub; };
        uint32_t get_len(){ return len; };

        void explain();
};

class mqtt_payload{
    private:
        static constexpr char *TAG = (char*)"mqtt_payload";
        uint16_t max_len = 256;
        uint8_t* pl = new uint8_t[max_len];
        uint32_t len = 0;
        bool one_string = false;
    public:
        void add_string(std::string str);
        void set_string_no_len(std::string str);
        uint8_t* get_payload(){ return pl; };
        uint32_t get_length(){ return len; };
        void explain();
};

class mqtt_variable_header{
    private:
        static constexpr char *TAG = (char*)"mqtt_variable_header";
    protected:
        uint16_t packet_identifier;
        uint8_t* encodedData;
    public:
        virtual uint8_t* get_variable_header();
        virtual uint32_t get_length();
        virtual void explain();
};

class mqtt_variable_header_connect: public mqtt_variable_header{
    private:
        static constexpr char *TAG = (char*)"mqtt_variable_header_connect";
    protected:
        uint8_t protocol_name[6] = {'\0','\4','M','Q','T','T'};
        uint8_t protocol_level = 4;
        bool user_name_flag = false;
        bool password_flag = false;
        bool will_retain;
        e_mqtt_qos_t will_qos;
        bool will_flag;
        bool clean_session;
        std::string user_name;
        std::string password;
        uint16_t keep_alive;
        mqtt_payload* pl;
    public:
        mqtt_variable_header_connect(std::string a_user_name, 
            std::string a_password, bool a_will_retain, 
            e_mqtt_qos_t a_will_qos, bool a_will_flag, 
            bool a_clean_session, uint16_t a_keep_alive,
            mqtt_payload* a_pl);
        mqtt_variable_header_connect(bool a_will_retain, 
            e_mqtt_qos_t a_will_qos, bool a_will_flag, 
            bool a_clean_session, uint16_t a_keep_alive,
            mqtt_payload* a_pl);
        uint8_t* get_variable_header();
        uint32_t get_length(){ return 10; };
        void explain();
};

class mqtt_variable_header_connack: public mqtt_variable_header{
    private:
        static constexpr char *TAG = (char*)"mqtt_variable_header_connack";
    protected:
        bool session_present = false;
        uint8_t return_code = 0;
    public:
        uint8_t* get_variable_header();
        mqtt_variable_header_connack(uint8_t *msg);
        uint32_t get_length(){ return 2; };
        void explain();

        bool get_session_present(){ return session_present; };
        uint8_t get_return_code(){ return return_code; };
};

class mqtt_variable_header_publish: public mqtt_variable_header{
    private:
        static constexpr char *TAG = (char*)"mqtt_variable_header_publish";
    protected:
        std::string topic;
        uint8_t len = 0;
    public:
        mqtt_variable_header_publish(std::string a_topic, 
            uint16_t a_packed_identifier);

        std::string get_topic(){ return topic; };
        void set_topic(std::string value){ topic = value; };

        uint8_t* get_variable_header();
        uint32_t get_length(){ return len; };
        void explain();
};

class mqtt_message: public protocol_message{
    private:
        static constexpr char *TAG = (char*)"mqtt_message";
    protected:
        mqtt_fixed_header* fh = NULL;
        mqtt_variable_header* vh = NULL;
        mqtt_payload* pl = NULL;
        uint16_t len;
        uint8_t* msg;
    public:
        mqtt_message() {};
        uint32_t get_length(){ return len; };
        virtual void to_string();
        void explain();
        virtual uint8_t* get_message();
        virtual uint16_t get_message_len();
        static mqtt_message* create_message(uint8_t* a_msg, uint16_t a_len);

        e_mqtt_message_type_t get_message_type(){ return fh->get_msg_type(); };
};

class mqtt_message_connect:public mqtt_message{
    private:
        static constexpr char *TAG = (char*)"mqtt_message_connect";
    public:
        mqtt_message_connect(std::string a_client_name,
            std::string a_user_name, std::string a_password, 
            bool a_will_retain, e_mqtt_qos_t a_will_qos, 
            bool a_will_flag, bool a_clean_session, 
            uint16_t a_keep_alive);
        mqtt_message_connect(std::string a_client_name, 
            bool a_will_retain, e_mqtt_qos_t a_will_qos, 
            bool a_will_flag, bool a_clean_session, 
            uint16_t a_keep_alive);
        uint8_t* get_message();
        uint16_t get_message_len();
        void to_string();
};

class mqtt_message_connack:public mqtt_message{
    private:
        static constexpr char *TAG = (char*)"mqtt_message_connect";
        uint16_t len;
        uint8_t* msg;
    public:
        mqtt_message_connack(uint8_t* a_msg, uint16_t a_len);
        uint8_t* get_message();
        uint16_t get_message_len();
        void to_string();
        uint8_t get_return_code(){ 
            return ((mqtt_variable_header_connack*)vh)->get_return_code(); };
};

class mqtt_message_publish:public mqtt_message{
    private:
        static constexpr char *TAG = (char*)"mqtt_message_publish";
    public:
        mqtt_message_publish(bool a_dub_flag, e_mqtt_qos_t a_qos, bool a_retain,
            uint16_t a_packed_identifier, std::string a_topic, 
            std::string payload);
        uint8_t* get_message();
        uint16_t get_message_len();
        void to_string();
};

class mqtt_message_pingreq:public mqtt_message{
    private:
        static constexpr char *TAG = (char*)"mqtt_message_connect";
    public:
        mqtt_message_pingreq();
        uint8_t* get_message();
        uint16_t get_message_len() { return 2; };
        void to_string();
};

typedef struct param_group_handle_task{
    mqtt_dispatcher* disp;
    mqtt_client* mqtt_cl;
}param_group_handle_task_t;

class mqtt_dispatcher{
    private:
        static constexpr char *TAG = (char*)"mqtt_dispatcher";
    protected:
        QueueHandle_t outgoing_messages = NULL;
        uint8_t cntr_outgoing_messages = 0;
        QueueHandle_t incomming_messages = NULL;
        uint8_t cntr_incomming_messages = 0;

        tls_layer* tls;
    public:
        mqtt_dispatcher(tls_layer *a_tls);

        void add_outgoing_message(mqtt_message *msg);
        mqtt_message* get_next_outgoing_message();
        bool has_next_outgoing_message();

        mqtt_message* get_next_incomming_message();
        bool has_next_incomming_message();

        void send_next_outgoing_message();
        void recv_next_incomming_message();
};

class mqtt_client: public protocol_client{
    private:
        static constexpr char *TAG = (char*)"a_mqtt_client";
    protected:
        mqtt_dispatcher* disp = NULL;
        
        std::string client_name = "";
        std::string user_name;
        std::string password;

        bool will_retain = false;
        e_mqtt_qos_t will_qos = eQOS0;
        bool will_flag = false;
        bool clean_session = false;
        uint16_t keep_alive = 0;

        TaskHandle_t xSendHandle = NULL;
        TaskHandle_t xRecvHandle = NULL;
        TaskHandle_t xHndlHandle = NULL;

        static void send_task(void* params);
        static void recv_task(void* params);
        static void handle_task(void* params);

        tls_layer* tls;

        EventGroupHandle_t mqtt_event_group = NULL;
    public:
        mqtt_client(tls_layer *a_tls);
        void init();

        std::string get_client_name(){ return client_name; };
        void set_client_name(std::string value){ client_name = value; };

        std::string get_user_name(){ return user_name; };
        void set_user_name(std::string value){ user_name = value; };

        std::string get_password(){ return password; };
        void set_password(std::string value){ password = value; };

        bool get_will_retain(){ return will_retain; };
        void set_will_retain(bool value){ will_retain = value; };

        bool get_will_flag(){ return will_flag; };
        void set_will_flag(bool value){ will_flag = value; };

        e_mqtt_qos_t get_will_qos(){ return will_qos; };
        void set_will_qos(e_mqtt_qos value){ will_qos = value; };

        bool get_clean_session(){ return clean_session; };
        void set_clean_session(bool value){ clean_session = value; };

        uint16_t get_keep_alive(){ return keep_alive; };
        void set_keep_alive(uint16_t value){ keep_alive = value; };
    
        bool connect();
        static void handle_message(protocol_message *msg, mqtt_client* cl);
        void handle_message(protocol_message *msg) {};   // dummy

        void publish(std::string topic, std::string payload, e_mqtt_qos_t qos);

};


#endif