/*
    This file is part of rp++.

    Copyright (C) 2012, Axel "0vercl0k" Souchet <0vercl0k at tuxfamily.org>
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
#include "rpexception.hpp"

#include <sstream>

RpException::RpException(const char *filename, unsigned int line, const char* funct, const char* msg)
: m_filename(filename), m_msg(msg), m_function_name(funct), m_line(line)
{
    std::ostringstream oss;
    oss << "[EXCEPTION REPORT]:" << std::endl;
    oss << "\t Raised in " << m_filename << ":" << m_line << std::endl;
    oss << "\t More precisely in " << m_function_name << std::endl;
    oss << "\t Further infos: " << m_msg;

    m_report = oss.str();
}

RpException::~RpException(void) throw()
{
}

const char* RpException::what(void) const throw()
{
    return m_report.c_str();
}
