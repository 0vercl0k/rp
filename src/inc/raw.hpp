#ifndef RAW_HPP
#define RAW_HPP

#include "executable_format.hpp"

class Raw : public ExecutableFormat
{
    public:
        
        explicit Raw(void);

        ~Raw(void);

        CPU* get_cpu(std::ifstream &file)
        {
            /* Don't need this method */
            return NULL;
        }

        std::string get_class_name(void) const;

        std::vector<Section*> get_executables_section(std::ifstream & file);

        unsigned long long raw_offset_to_va(const unsigned long long absolute_raw_offset, const unsigned long long absolute_raw_offset_section) const;
};

#endif
