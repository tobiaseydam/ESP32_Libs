#ifndef ESP32_STORAGE_HPP
#define ESP32_STORAGE_HPP

#include <string>
#include <stdio.h>
#include <dirent.h>

using namespace std;

class storage_adapter{
    private:
        static constexpr char *TAG = (char*)"storage_adapter";
        static constexpr char *root_path = (char*)"/spiffs";
    public:
        storage_adapter();
        void init();
        DIR* get_root_folder();
        string get_root_folder_name();

        static long get_file_size(const char* filename);
};

#endif