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
#ifndef PE_STRUCT_H
#define PE_STRUCT_H

#include "platform.h"
#include "toolbox.hpp"
#include "coloshell.hpp"
#include "rpexception.hpp"

#include <fstream>
#include <iostream>
#include <iomanip>
#include <vector>
#include <cstring>

/* Information extracted from winnt.h ; a bit of template-kung-fu and here it goes ! */

/*
 * BTW, do not forget that :
 * -> On Win x64 compiled by VC : sizeof(long) = 4
 * -> On Unix x64 compiled by G++ : sizeof(long) = 8
 * Thus, in order to have the same size on both VS & Gcc, we'll
 * use only unsigned int for 32bits fields and unsigned long long for 64bits.
 * 
 * I've cleaned all the fields using the long type
 */

//
// Calculate the byte offset of a field in a structure of type type.
//

#define RP_FIELD_OFFSET(type, field)    ((unsigned int)(ptr_t)&(((type *)0)->field))


#define RP_IMAGE_DOS_SIGNATURE                 0x5A4D      // MZ
#define RP_IMAGE_NT_SIGNATURE                  0x00004550  // PE00

#ifdef WINDOWS
#pragma pack(push)
#pragma pack(1)
#endif

struct RP_IMAGE_DOS_HEADER {      // DOS .EXE header
    unsigned short e_magic;       // Magic number
    unsigned short e_cblp;        // Bytes on last page of file
    unsigned short e_cp;          // Pages in file
    unsigned short e_crlc;        // Relocations
    unsigned short e_cparhdr;     // Size of header in paragraphs
    unsigned short e_minalloc;    // Minimum extra paragraphs needed
    unsigned short e_maxalloc;    // Maximum extra paragraphs needed
    unsigned short e_ss;          // Initial (relative) SS value
    unsigned short e_sp;          // Initial SP value
    unsigned short e_csum;        // Checksum
    unsigned short e_ip;          // Initial IP value
    unsigned short e_cs;          // Initial (relative) CS value
    unsigned short e_lfarlc;      // File address of relocation table
    unsigned short e_ovno;        // Overlay number
    unsigned short e_res[4];      // Reserved words
    unsigned short e_oemid;       // OEM identifier (for e_oeminfo)
    unsigned short e_oeminfo;     // OEM information; e_oemid specific
    unsigned short e_res2[10];    // Reserved words
    unsigned int   e_lfanew;      // File address of new exe header

    void display(VerbosityLevel lvl =  VERBOSE_LEVEL_1) const
    {
        w_yel_lf("-> IMAGE_DOS_HEADER:");

        if(lvl > VERBOSE_LEVEL_1)
        {
            display_hex_2fields_lf(e_magic, e_cblp);
            display_hex_2fields_lf(e_cp, e_crlc);
            display_hex_field_lf(e_cparhdr);
        }

        if(lvl > VERBOSE_LEVEL_2)
        {
            display_hex_2fields_lf(e_minalloc, e_maxalloc);
            display_hex_2fields_lf(e_ss, e_sp);
            display_hex_2fields_lf(e_csum, e_ip);
            display_hex_2fields_lf(e_cs, e_lfarlc);
            display_hex_2fields_lf(e_oemid, e_oeminfo);
        }

        display_hex_field_lf(e_lfanew);
    }
} 
#ifdef LINUX
__attribute__((packed))
#endif
;

#define RP_IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
#define RP_IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b

struct RP_IMAGE_FILE_HEADER {
    unsigned short Machine;
    unsigned short NumberOfSections;
    unsigned int   TimeDateStamp;
    unsigned int   PointerToSymbolTable;
    unsigned int   NumberOfSymbols;
    unsigned short SizeOfOptionalHeader;
    unsigned short Characteristics;

    unsigned short get_size_of_optionnal_header(void) const
    {
        return SizeOfOptionalHeader;
    }

    void display(VerbosityLevel lvl = VERBOSE_LEVEL_1) const
    {
        w_yel_lf("-> IMAGE_FILE_HEADER:");

        if(lvl > VERBOSE_LEVEL_1)
        {
            display_hex_2fields_lf(Machine, SizeOfOptionalHeader);
            display_hex_field_lf(PointerToSymbolTable);
        }

        if(lvl > VERBOSE_LEVEL_2)
        {
            display_hex_2fields_lf(TimeDateStamp, Characteristics);
        }

        display_hex_field_lf(NumberOfSections);
    }
}
#ifdef LINUX
__attribute__((packed))
#endif
;

//
// Directory format.
//

struct RP_IMAGE_DATA_DIRECTORY {
    unsigned int VirtualAddress;
    unsigned int Size;
}
#ifdef LINUX
__attribute__((packed))
#endif
;

#define RP_IMAGE_NUMBEROF_DIRECTORY_ENTRIES       16

//
// Optional header format.
//

#define RP_IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE 0x40
#define RP_IMAGE_DLL_CHARACTERISTICS_NX_COMPAT    0x100

template<class T>
struct RP_IMAGE_OPTIONAL_HEADER
{
};

template<>
struct RP_IMAGE_OPTIONAL_HEADER<x86Version> {
    unsigned short          Magic;
    unsigned char           MajorLinkerVersion;
    unsigned char           MinorLinkerVersion;
    unsigned int            SizeOfCode;
    unsigned int            SizeOfInitializedData;
    unsigned int            SizeOfUninitializedData;
    unsigned int            AddressOfEntryPoint;
    unsigned int            BaseOfCode;
    unsigned int            BaseOfData;
    unsigned int            ImageBase;
    unsigned int            SectionAlignment;
    unsigned int            FileAlignment;
    unsigned short          MajorOperatingSystemVersion;
    unsigned short          MinorOperatingSystemVersion;
    unsigned short          MajorImageVersion;
    unsigned short          MinorImageVersion;
    unsigned short          MajorSubsystemVersion;
    unsigned short          MinorSubsystemVersion;
    unsigned int            Win32VersionValue;
    unsigned int            SizeOfImage;
    unsigned int            SizeOfHeaders;
    unsigned int            CheckSum;
    unsigned short          Subsystem;
    unsigned short          DllCharacteristics;
    unsigned int            SizeOfStackReserve;
    unsigned int            SizeOfStackCommit;
    unsigned int            SizeOfHeapReserve;
    unsigned int            SizeOfHeapCommit;
    unsigned int            LoaderFlags;
    unsigned int            NumberOfRvaAndSizes;
    RP_IMAGE_DATA_DIRECTORY DataDirectory[RP_IMAGE_NUMBEROF_DIRECTORY_ENTRIES];

    void display(VerbosityLevel lvl = VERBOSE_LEVEL_1) const
    {
        w_yel_lf("-> IMAGE_OPTIONAL_HEADER32:");
        
        std::cout << " ASLR: ";
        w_red_lf((DllCharacteristics & RP_IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE) ? "Yes" : "No");

        std::cout << " NX: ";
        w_red_lf((DllCharacteristics & RP_IMAGE_DLL_CHARACTERISTICS_NX_COMPAT) ? "Yes" : "No");

        if(lvl > VERBOSE_LEVEL_1)
        {
            display_hex_2fields_lf(SectionAlignment, FileAlignment);
        }

        if(lvl > VERBOSE_LEVEL_2)
        {
            display_hex_2fields_lf(SizeOfInitializedData, SizeOfUninitializedData);
            display_hex_field_lf(Magic);
        }

        display_hex_2fields_lf(SizeOfCode, AddressOfEntryPoint);
        display_hex_2fields_lf(BaseOfCode, BaseOfCode);
        display_hex_field_lf(ImageBase);
    }
}
#ifdef LINUX
__attribute__((packed))
#endif
;

template<>
struct RP_IMAGE_OPTIONAL_HEADER<x64Version> {
    unsigned short          Magic;
    unsigned char           MajorLinkerVersion;
    unsigned char           MinorLinkerVersion;
    unsigned int            SizeOfCode;
    unsigned int            SizeOfInitializedData;
    unsigned int            SizeOfUninitializedData;
    unsigned int            AddressOfEntryPoint;
    unsigned int            BaseOfCode;
    unsigned long long      ImageBase;
    unsigned int            SectionAlignment;
    unsigned int            FileAlignment;
    unsigned short          MajorOperatingSystemVersion;
    unsigned short          MinorOperatingSystemVersion;
    unsigned short          MajorImageVersion;
    unsigned short          MinorImageVersion;
    unsigned short          MajorSubsystemVersion;
    unsigned short          MinorSubsystemVersion;
    unsigned int            Win32VersionValue;
    unsigned int            SizeOfImage;
    unsigned int            SizeOfHeaders;
    unsigned int            CheckSum;
    unsigned short          Subsystem;
    unsigned short          DllCharacteristics;
    unsigned long long      SizeOfStackReserve;
    unsigned long long      SizeOfStackCommit;
    unsigned long long      SizeOfHeapReserve;
    unsigned long long      SizeOfHeapCommit;
    unsigned int            LoaderFlags;
    unsigned int            NumberOfRvaAndSizes;
    RP_IMAGE_DATA_DIRECTORY DataDirectory[RP_IMAGE_NUMBEROF_DIRECTORY_ENTRIES];

    void display(VerbosityLevel lvl = VERBOSE_LEVEL_1) const
    {
        w_yel_lf("-> IMAGE_OPTIONAL_HEADERS64:");

        std::cout << " ASLR: ";
        w_red_lf((DllCharacteristics & RP_IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE) ? "Yes" : "No");

        std::cout << " NX: ";
        w_red_lf((DllCharacteristics & RP_IMAGE_DLL_CHARACTERISTICS_NX_COMPAT) ? "Yes" : "No");

        if(lvl > VERBOSE_LEVEL_1)
        {
            display_hex_2fields_lf(SizeOfInitializedData, SizeOfUninitializedData);
        }

        if(lvl > VERBOSE_LEVEL_2)
        {
            display_hex_2fields_lf(SectionAlignment, FileAlignment);
            display_hex_field_lf(Magic);
        }

        display_hex_2fields_lf(SizeOfCode, AddressOfEntryPoint);
        display_hex_field_lf(BaseOfCode);
        display_hex_field_lf(ImageBase);
    }
}
#ifdef LINUX
__attribute__((packed))
#endif
;

typedef RP_IMAGE_OPTIONAL_HEADER<x86Version> RP_IMAGE_OPTIONAL_HEADER32;
typedef RP_IMAGE_OPTIONAL_HEADER<x64Version> RP_IMAGE_OPTIONAL_HEADER64;

//
// Section header format.
//

#define RP_IMAGE_SIZEOF_SHORT_NAME 8
#define RP_IMAGE_SCN_MEM_EXECUTE   0x00000020

struct RP_IMAGE_SECTION_HEADER {
    unsigned char    Name[RP_IMAGE_SIZEOF_SHORT_NAME];
    union {
        unsigned int PhysicalAddress;
        unsigned int VirtualSize;
    } Misc;
    unsigned int   VirtualAddress;
    unsigned int   SizeOfRawData;
    unsigned int   PointerToRawData;
    unsigned int   PointerToRelocations;
    unsigned int   PointerToLinenumbers;
    unsigned short NumberOfRelocations;
    unsigned short NumberOfLinenumbers;
    unsigned int   Characteristics;

    std::string get_name(void) const
    {
        unsigned char name_null_terminated[RP_IMAGE_SIZEOF_SHORT_NAME + 1] = {0};
        /* Yeah sometimes you don't have null byte after the name -- I try to be clean */
        memcpy(name_null_terminated, Name, RP_IMAGE_SIZEOF_SHORT_NAME * sizeof(unsigned char));

        return std::string((char*)name_null_terminated);
    }

    void display(VerbosityLevel lvl = VERBOSE_LEVEL_1) const
    {
        w_yel_lf("-> IMAGE_SECTION_HEADER");
        
        std::cout << "    " << get_name() << std::endl;

        if(lvl > VERBOSE_LEVEL_1)
        {
            display_hex_field_lf(Characteristics);
        }

        display_hex_2fields_lf(Misc.PhysicalAddress, VirtualAddress);
        display_hex_2fields_lf(SizeOfRawData, PointerToRawData);
    }
} 
#ifdef LINUX
__attribute__((packed))
#endif
;

template<class T>
struct RP_IMAGE_NT_HEADERS {
    unsigned int                Signature;
    RP_IMAGE_FILE_HEADER        FileHeader;
    RP_IMAGE_OPTIONAL_HEADER<T> OptionalHeader;

    /* Keep in mind this offset is relative to the NT Header ! 
     * So if you want the PA of the first section: get_offset_first_section() + IMAGE_DOS_HEADER.e_lfanew
     */
    ptr_t get_offset_first_section() const
    {
        return (ptr_t)(RP_FIELD_OFFSET(RP_IMAGE_NT_HEADERS<T>, OptionalHeader) + FileHeader.SizeOfOptionalHeader);
    }

    void display(VerbosityLevel lvl = VERBOSE_LEVEL_1) const
    {
        w_yel_lf("-> IMAGE_NT_HEADERS:");

        if(lvl > VERBOSE_LEVEL_1)
        {
            /* Yeah. I know I'm not supposed to do that this way */
            if(FileHeader.get_size_of_optionnal_header() >= sizeof(OptionalHeader))
                OptionalHeader.display(lvl);
        }

        if(lvl > VERBOSE_LEVEL_2)
        {
            display_hex_field_lf(Signature);
        }

        FileHeader.display(lvl);
    }
}
#ifdef LINUX
__attribute__((packed))
#endif
;

typedef RP_IMAGE_NT_HEADERS<x86Version> RP_IMAGE_NT_HEADERS32;
typedef RP_IMAGE_NT_HEADERS<x64Version> RP_IMAGE_NT_HEADERS64;

#ifdef WINDOWS
#pragma pack(pop)
#endif

struct PortableExecutableLayout
{
    RP_IMAGE_DOS_HEADER                   imgDosHeader;
    std::vector<RP_IMAGE_SECTION_HEADER*> imgSectionHeaders;

    typedef std::vector<RP_IMAGE_SECTION_HEADER*>::const_iterator iter_sect_header;

    virtual ~PortableExecutableLayout(void)
    {
        for(iter_sect_header it = imgSectionHeaders.begin(); it != imgSectionHeaders.end(); ++it)
            delete *it;
    }

    virtual void display(VerbosityLevel lvl = VERBOSE_LEVEL_1) const
    {
        imgDosHeader.display(lvl);
    }


    unsigned int get_image_dos_header_size(void) const
    {
        return sizeof(RP_IMAGE_DOS_HEADER);
    }

    unsigned int get_image_section_header_size(void) const
    {
        return sizeof(RP_IMAGE_SECTION_HEADER);
    }

    virtual unsigned int get_nt_headers_size(void) const  = 0;
    virtual void fill_nt_structures(std::ifstream &file)  = 0;
    virtual unsigned long long get_image_base(void) const = 0;
};

/* Some magic..and ABSTRACTION */
template<class T>
struct PELayout : public PortableExecutableLayout
{
    RP_IMAGE_NT_HEADERS<T> imgNtHeaders;
       
    unsigned int get_nt_headers_size(void) const
    {
        return sizeof(RP_IMAGE_NT_HEADERS<T>);
    }

    void display(VerbosityLevel lvl = VERBOSE_LEVEL_1) const
    {
        PortableExecutableLayout::display(lvl);
        imgNtHeaders.display(lvl);
        if(lvl > VERBOSE_LEVEL_1)
        {
            for(iter_sect_header it = imgSectionHeaders.begin();
                it != imgSectionHeaders.end();
                ++it)
                (*it)->display();
        }
    }

    void fill_nt_structures(std::ifstream &file)
    {
        /* Remember where the caller was in the file */
        std::streampos off = file.tellg();
        
        file.seekg(imgDosHeader.e_lfanew, std::ios::beg);
        file.read((char*)&imgNtHeaders, get_nt_headers_size());
        
        file.seekg(imgDosHeader.e_lfanew, std::ios::beg);
        /* This offset is relative to the NT Header, do not forget to move the file pointer on it */
        file.seekg(imgNtHeaders.get_offset_first_section(), std::ios::cur);

        for(unsigned int i = 0; i < imgNtHeaders.FileHeader.NumberOfSections; ++i)
        {
            RP_IMAGE_SECTION_HEADER* pImgSectionHeader = new (std::nothrow) RP_IMAGE_SECTION_HEADER;
            if(pImgSectionHeader == NULL)
                RAISE_EXCEPTION("Cannot allocate memory for pImgSectionHeader");
            
            file.read((char*)pImgSectionHeader, get_image_section_header_size());
            imgSectionHeaders.push_back(pImgSectionHeader);
        }

        file.seekg(off);
    }

    unsigned long long get_image_base(void) const
    {
        return imgNtHeaders.OptionalHeader.ImageBase;
    }
};

typedef PELayout<x86Version> PELayout32;
typedef PELayout<x64Version> PELayout64;

#endif
