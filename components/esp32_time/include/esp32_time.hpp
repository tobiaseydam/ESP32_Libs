#ifndef ESP32_TIME_HPP
#define ESP32_TIME_HPP


#include <string.h>

class system_clock{
    private:
        static constexpr char *TAG = (char*)"clock";
        void init();
    public:
        system_clock();
};

#endif