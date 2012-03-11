#ifndef EXCEPTION_HPP
#define EXCEPTION_HPP

#include <exception>
#include <string>

#define RAISE_EXCEPTION(msg) throw RpException(__FILE__,  __LINE__, __FUNCTION__, msg)

/* RpException is there to have a proper exception report ; easier to corret bugs */
class RpException : public std::exception
{
    public:
        explicit RpException(const char *filename, unsigned int line, const char* funct, const char* msg);
        ~RpException(void) throw();

        const char* what(void) const throw();

    private:
        std::string m_filename, m_msg, m_function_name, m_report;
        unsigned int m_line;
};

#endif