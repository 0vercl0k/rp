#ifndef AUTOROP_HPP
#define AUTOROP_HPP

#include "cpu.hpp"
#include "executable_format.hpp"
#include "gadget.hpp"

#include <vector>
#include <map>
#include <string>

class AutoRop
{
    public:

        explicit AutoRop(void);
        
        ~AutoRop(void);

        void search_specific_gadget(std::map<std::string, Gadget*> &g);

    private:

        std::vector<const char*> m_list;
};

#endif