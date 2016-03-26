#
#    Dockerfile rp++ - Set up everything you need to compile rp++-v1 in a vanilla ubuntu 14.04 x64
#    Prefer an x64 based Host/Container to have both the x86/x64 versions compiled & ready to go.
#    Copyright (C) 2015 Axel "0vercl0k" Souchet - http://www.twitter.com/0vercl0k
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

FROM ubuntu:14.04
MAINTAINER Axel "0vercl0k" Souchet <0vercl0k[at]tuxfamily[dot]org>

# Install basic stuff we might need
RUN apt-get update && apt-get install -y git wget g++ zlib1g-dev g++-multilib cmake libboost-dev libboost-dbg

# Setup a dummy user
RUN echo 'root:root' | chpasswd
RUN adduser --quiet --disabled-password over

USER over

WORKDIR /home/over
RUN mkdir dev

WORKDIR /home/over/dev
RUN git clone https://github.com/0vercl0k/rp.git --recursive

WORKDIR /home/over/dev/rp
RUN mkdir buildx86 buildx64

WORKDIR /home/over/dev/rp/buildx86
RUN cmake .. -DoptX86BUILD=ON && make

WORKDIR /home/over/dev/rp/buildx64
RUN cmake .. && make

WORKDIR /home/over/dev/rp/bin
RUN mv rp-lin-x86 rp.v1-lin-x86 && mv rp-lin-x64 rp.v1-lin-x64
RUN rm -rf /home/over/dev/rp/buildx86 && rm -rf /home/over/dev/rp/buildx64

WORKDIR /home/over/dev/rp
RUN git checkout next
RUN git submodule update --init --recursive
RUN mkdir buildx86 buildx64

WORKDIR /home/over/dev/rp/buildx86
RUN cmake .. -DoptX86BUILD=ON && make

WORKDIR /home/over/dev/rp/buildx64
RUN cmake .. && make
RUN rm -rf /home/over/dev/rp/buildx86 && rm -rf /home/over/dev/rp/buildx64

WORKDIR /home/over/dev/rp/bin
RUN mv rp-lin-x86 rp.v2-lin-x86 && mv rp-lin-x64 rp.v2-lin-x64
