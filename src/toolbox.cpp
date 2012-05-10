#include "toolbox.hpp"
#include "rpexception.hpp"

#include <cstring>
#include <cstdlib>
#include <vector>

std::string verbosity_to_string(const VerbosityLevel lvl)
{
    std::string s("");

    switch(lvl)
    {
        case VERBOSE_LEVEL_1:
        {
            s = "VERBOSE_LEVEL_1";
            break;
        }

        case VERBOSE_LEVEL_2:
        {
            s = "VERBOSE_LEVEL_2";
            break;
        }

        case VERBOSE_LEVEL_3:
        {
            s = "VERBOSE_LEVEL_3";
            break;
        }
    }

    return s;
}

std::streampos get_file_size(std::ifstream &file)
{
    std::streampos backup = file.tellg();

    file.seekg(0, std::ios::beg);
    std::streampos fsize = file.tellg();

    file.seekg(0, std::ios::end );
    fsize = file.tellg() - fsize;
    
    file.seekg(backup);
    return fsize;
}

/* this function is completely inspirated from the previous work of jonathan salwan */
bool is_matching(std::string &str, const char* p)
{
    std::string pattern(p);

    /* we have to check the *entire* pattern */
    if(pattern.size() > str.size())
        return false;

    size_t i = 0, max = (str.length() >= pattern.length()) ? pattern.length() : str.length();
    bool it_matches = true;

    while(i < max)
    {
        if(pattern.at(i) != '?' && pattern.at(i) != str.at(i))
        {
            it_matches = false;
            break;
        }

        ++i;
    }

    return it_matches;
}

bool is_hex_char(char c)
{
    return (
        (c >= '0' && c <= '9') ||
        (c >= 'a' && c <= 'f') ||
        (c >= 'A' && c <= 'F')
    );
}

unsigned char * string_to_hex(const char* hex, unsigned int * size)
{
    unsigned int len = (unsigned int)std::strlen(hex), i = 0, byte = 0;
    std::vector<unsigned char> bytes;

    if(len == 0)
    {
        *size = 0;
        return NULL;
    }

    while(i < len)
    {
        //not printable
        if(hex[i] == '\\' && hex[i + 1] == 'x')
        {
            if(is_hex_char(hex[i + 2]) && is_hex_char(hex[i + 3]))
            {
                char str_byte[3] = {
                    hex[i + 2],
                    hex[i + 3],
                    0
                };

                byte = strtoul(str_byte, NULL, 16);
                i += 4;
            }
            else
                RAISE_EXCEPTION("Your hex values aren't formated correctly");
        }
        //printable
        else
        {
            byte = hex[i];
            i++;
        }
        
        bytes.push_back((unsigned char)byte);
    }

    *size = (unsigned int)bytes.size();

    unsigned char *buffer = new (std::nothrow) unsigned char[*size];
    if(buffer == NULL)
        RAISE_EXCEPTION("Cannot allocate buffer");

    unsigned int j = 0;
    for(std::vector<unsigned char>::iterator it = bytes.begin(); it != bytes.end(); ++it, j++)
        buffer[j] = *it;

    return buffer;
}

std::map<std::string, Gadget*> only_unique_gadgets(std::list<Gadget*> &list_gadgets)
{
	std::map<std::string, Gadget*> ret;

	 /* Now we have a list of gadget, cool, but we want to keep only the unique! */
        for(std::list<Gadget*>::const_iterator it_g = list_gadgets.begin(); it_g != list_gadgets.end(); ++it_g)
        {
            /* If a gadget, with the same disassembly, has already been found ; just add its offset in the existing one */
            if(ret.count((*it_g)->get_disassembly()))
            {
                std::map<std::string, Gadget*>::iterator g = ret.find((*it_g)->get_disassembly());
                
                /*
                    we have found the same gadget in memory, so we just store its offset & its va section 
                    maybe you can ask yourself 'Why do we store its va section ?' and the answer is:
                    because you can find the same gadget in another executable sections!
                */
                g->second->add_new_one((*it_g)->get_first_offset(),
                    (*it_g)->get_first_va_section()
                );

                /* in this case the gadget must be freed */
                delete *it_g;
            }
            else
            {
                ret.insert(std::make_pair(
                    (*it_g)->get_disassembly(),
                    (*it_g)
                ));
            }
        }

	return ret;
}