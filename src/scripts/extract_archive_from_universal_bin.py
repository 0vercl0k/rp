#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
#    extract_archives_from_universal_bin.py - It extracts the binaries embeded into a Universal Binary Mach-o
#    Copyright (C) 2012 Axel "0vercl0k" Souchet - http://www.twitter.com/0vercl0k
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import sys
from struct import unpack

# http://hohle.net/scrap_post.php?post=197

def u(r):
    return unpack('>I', r)[0]

def dump_archive(f, offset, size, name):
    f.seek(offset)
    data = f.read(size)
    hfile = open(name, 'wb')
    hfile.write(data)
    hfile.close()

def main(argc, argv):
    if argc != 2:
            print './dump <bin>'
            return -1
    
    f = open(argv[1], 'rb')

    magic = f.read(4)
    if u(magic) != 0xcafebabe:
        print "Your file doesn't seem to be a universal binary: %#.8x" % u(magic)
        return -1

    nb_archive = u(f.read(4))
    for i in range(nb_archive):
        f.read(4) #cputype
        f.read(4) #cpusubtype
       
        offset = u(f.read(4))
        size = u(f.read(4))
        print 'Dumping %#.8x bytes @%#.8x ' % (size, offset)
        
        b = f.tell()

        dump_archive(f, offset, size, 'dumpz/bin%d' % i)
        
        f.seek(b)
        
        f.read(4) #alignement

    print 'eof'
    return 1

if __name__ == '__main__':
    sys.exit(main(len(sys.argv), sys.argv))