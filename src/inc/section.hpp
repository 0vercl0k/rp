#ifndef SECTION_HPP
#define SECTION_HPP

#include <string>
#include <list>
#include <fstream>

/*! \class Section
 *
 *   Each binary is divided in section, actually it is a chunk of the binary of a specific size which contains code or data
 */
class Section
{
    public:
        
        /*! The different rights a section can have ; those rights are usually combined by an OR operation */
        enum Properties
        {
            Readable, /*!< the section is readable*/
            Writeable, /*!< the section is writeable*/
            Executable /*!< the section is executable*/
        };

        /*!
         *  \brief The constructor will make a copy of the memory in its own buffer
         *   
         *  \param file: The file to analyze (in order to dump the raw section)
         *  \param name: The name of the section
         *  \param offset: It is the offset in file where you can find the section
         *  \param size: It is the size of the section
         *  \param props: It describes the rights you will have on this section in memory
         */
        explicit Section(std::ifstream &file, const char *name, const unsigned long long offset, const unsigned long long size, const Properties props);
        
        ~Section(void);
        
        /*!
         *  \brief Get the name of the section
         *   
         *  \return the name of the section
         */
        std::string get_name(void) const;

        /*!
         *  \brief Get the size of the section
         *   
         *  \return the size of the section
         */
        unsigned long long get_size(void) const;

        /*!
         *  \brief Get the content of the section (it's the internal copy)
         *   
         *  \return a pointer on the buffer
         */
        unsigned char *get_section_buffer(void) const;

        /*!
         *  \brief Get the (raw) offset of the section ; in other word, where it was found in the binary
         *   
         *  \return the offset where the section was found in the binary
         */
        const unsigned long long get_offset(void) const;

        /*!
         *  \brief Search in memory a sequence of bytes
         *   
         *  \param val: A pointer on the bytes you want to search
         *  \param size: The size of the buffer
         *
         *  \return a list of offset (relative to the section) where it found the sequence of bytes
         */
        std::list<unsigned long long> search_in_memory(const unsigned char *val, const unsigned int size);
        
    private:

        std::string m_name; /*!< the name of the section*/
        
        const unsigned long long m_offset; /*!< the raw offset of the section*/
        
        const unsigned long long m_size; /*!< the size of the section of the section*/
        
        const Properties m_props; /*!< the properties of the section*/
        
        unsigned char *m_section; /*!< the pointer on the section content*/
};

#endif