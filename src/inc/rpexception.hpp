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
#ifndef EXCEPTION_HPP
#define EXCEPTION_HPP

#include <exception>
#include <string>

/**
 * \def RAISE_EXCEPTION(msg)
 *  It raises an exception with a detailed explanation in "msg"
 *
 * \param msg: The message that will be associated to the exeception raised
 */
#define RAISE_EXCEPTION(msg) throw RpException(__FILE__,  __LINE__, __FUNCTION__, msg)

/*! \class RpException
 *
 *  RpException is there to have a simple exception report ; easier to corret bugs
 */
class RpException : public std::exception
{
    public:
        
        /*!
         *  \brief Build an RpException
         *   
         *  \param filename: The name of the file where the exception has been raised
         *  \param line: The line where the exception has been raised
         *  \param funct: The function name where the exception has been raised
         *  \param msg: It is a message that describes the reason of the exception
         */
        explicit RpException(const char *filename, unsigned int line, const char* funct, const char* msg);

        ~RpException(void) throw();

        /*!
         *  \brief Obtain the reason the exception
         *   
         *  \return A message describing the exception
         */
        const char* what(void) const throw();

    private:

        std::string m_filename, /*!< the name of the file where the exception has been raised */
            m_msg, /*!< the message that describes the reason of the exception */
            m_function_name, /*!< the function name where the exception has been raised */
            m_report; /*!< the name of the file where the exception has been raised */

        unsigned int m_line; /*!< the line where the exception has been raised */
};

#endif
