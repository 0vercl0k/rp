/*
    This file is part of rp++.

    Copyright (C) 2013, Axel "0vercl0k" Souchet <0vercl0k at tuxfamily.org>
    All rights reserved.

    rp++ is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    rp++ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with rp++.  If not, see <http://www.gnu.org/licenses/>.
*/
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

std::vector<unsigned char> string_to_hex(const char* hex)
{
    unsigned int len = (unsigned int)std::strlen(hex), i = 0, byte = 0;
    std::vector<unsigned char> bytes;

    if(len == 0)
        return bytes;

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

    return bytes;
}

std::map<std::string, std::shared_ptr<Gadget>> only_unique_gadgets(std::multiset<std::shared_ptr<Gadget>, Gadget::Sort> &list_gadgets)
{
    std::map<std::string, std::shared_ptr<Gadget>> ret;

     /* Now we have a list of gadget, cool, but we want to keep only the unique! */
    for(std::multiset<std::shared_ptr<Gadget>, Gadget::Sort>::const_iterator it_g = list_gadgets.begin(); it_g != list_gadgets.end(); ++it_g)
    {
        /* If a gadget, with the same disassembly, has already been found ; just add its offset in the existing one */
        if(ret.count((*it_g)->get_disassembly()))
        {
            std::map<std::string, std::shared_ptr<Gadget>>::iterator g = ret.find((*it_g)->get_disassembly());
                
            /*
                we have found the same gadget in memory, so we just store its offset & its va section 
                maybe you can ask yourself 'Why do we store its va section ?' and the answer is:
                because you can find the same gadget in another executable sections!
            */
            g->second->add_new_one((*it_g)->get_first_offset(),
                (*it_g)->get_first_va_section()
            );
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