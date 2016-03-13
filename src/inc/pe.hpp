/*
    This file is part of rp++.

    Copyright (C) 2014, Axel "0vercl0k" Souchet <0vercl0k at tuxfamily.org>
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
#ifndef PE_H
#define PE_H

#include "executable_format.hpp"
#include "pe_struct.hpp"
#include "rpexception.hpp"

class PE : public ExecutableFormat
{
    public:

        std::shared_ptr<CPU> get_cpu(std::ifstream &file) override;

        void display_information(const VerbosityLevel lvl) const override;

        std::string get_class_name(void) const override;

        std::vector<std::shared_ptr<Section>> get_executables_section(std::ifstream & file) const override;

        uint64_t get_image_base_address(void) const override;

    private:

        CPU::E_CPU extract_information_from_binary(std::ifstream &file) override;
        
        template<class T>
        void init_properly_PELayout()
        {
            m_pPELayout = std::make_shared<PELayout<T>>();
            if(m_pPELayout == nullptr)
                RAISE_EXCEPTION("m_PELayout allocation failed");
        }

        std::shared_ptr<PortableExecutableLayout> m_pPELayout;
};

#endif
