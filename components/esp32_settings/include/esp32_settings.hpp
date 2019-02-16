#ifndef ESP32_SETTINGS_HPP
#define ESP32_SETTINGS_HPP

#include <string.h>
#include <map>

using namespace std;

#define SETTINGS_FILE   "/spiffs/settings.json"

typedef enum{
    WIFI_ACTIVE,
    WIFI_SSID,
    WIFI_PASS
} e_settings_name;

typedef enum{
    WIFI
} e_settings_category;

class settings_enum{
    public:
        static string e_settings_name_to_str(e_settings_name val);
        static string e_settings_category_to_str(e_settings_category val);
};


class settings_element{
    public:
        virtual string get_string_value() { return string(""); }; 
        virtual void set_string_value(string val) {}; 
};

typedef settings_element* settings_element_p;

class settings_string_element: public settings_element{
    protected:
        string value;
    public:
        string get_string_value(){ return value; };
        void set_string_value(string val){ value = val; };
};

typedef settings_string_element* settings_string_element_p;

class settings_bool_element: public settings_element{
    protected:
        bool value;
    public:
        string get_string_value();
        void set_string_value(string val);
        bool get_bool_value(){ return value; };
        void set_bool_value(bool val){ value = val; };
};

typedef settings_bool_element* settings_bool_element_p;

class settings_category{
        static constexpr char *TAG = (char*)"settings_category";
    public:
        map<e_settings_name, settings_element_p> mapOfElements;
        map<string, e_settings_name> mapOfNames;
        settings_element_p &operator[](const e_settings_name& elem){return mapOfElements[elem];}
        void insert(e_settings_name key, settings_element_p value);
};

typedef settings_category* settings_category_p;

class settings_manager{
        static constexpr char *TAG = (char*)"settings_manager";
    public:
        map<e_settings_category, settings_category_p> mapOfCategories;
        map<string, e_settings_category> mapOfNames;
        settings_category_p &operator[](const e_settings_category& cat){return mapOfCategories[cat];}
        settings_element_p get(e_settings_category cat, e_settings_name elem);
        settings_element_p get(string cat, string elem);
        virtual void init();
        virtual void load();
        virtual void save();
};

class settings_manager_heizung: public settings_manager{
    private:
        static constexpr char *TAG = (char*)"settings_manager_heizung";
    public:
        void init();
        void load();
        void save();
};

#endif