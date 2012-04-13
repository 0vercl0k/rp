#include "raw.hpp"
#include "rpexception.hpp"

Raw::Raw(void)
{
}

Raw::~Raw(void)
{
}

std::string Raw::get_class_name(void) const
{
    return std::string("raw");
}

std::vector<Section*> Raw::get_executables_section(std::ifstream & file)
{
    std::vector<Section*> executable_sections;

    unsigned long long raw_file_size = get_file_size(file);
    
    /* It is a raw file -> we have only one "virtual" section */
    Section *sect = new (std::nothrow) Section(
        ".raw",
        0,
        0,
        raw_file_size
    );

    if(sect == NULL)
        RAISE_EXCEPTION("Cannot allocate sect");
    
    sect->dump(file);
    sect->set_props(Section::Executable);

    executable_sections.push_back(sect);
    
    return executable_sections;
}

unsigned long long Raw::raw_offset_to_va(const unsigned long long absolute_raw_offset, const unsigned long long absolute_raw_offset_section) const
{
    return absolute_raw_offset;
}