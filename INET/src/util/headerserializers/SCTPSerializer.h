//
// Copyright (C) 2005 Christian Dankbar, Irene Ruengeler, Michael Tuexen
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
//

#ifndef __INET_SCTPSERIALIZER_H
#define __INET_SCTPSERIALIZER_H

#include "SCTPMessage.h"

//#include "Checksum.h"
/**
 * Converts between IPDatagram and binary (network byte order) IP header.
 */
class SCTPSerializer
{
    public:
        SCTPSerializer() {}
	
        /**
         * Serializes an SCTPMessage for transmission on the wire.
         * The checksum is NOT filled in. (The kernel does that when sending
         * the frame over a raw socket.)
         * Returns the length of data written into buffer.
         */
       // int32 serialize(IPDatagram *dgram, uint8 *buf, uint32 bufsize);
	int32 serialize(SCTPMessage *msg, uint8 *buf, uint32 bufsize);
        /**
         * Puts a packet sniffed from the wire into an SCTPMessage. 
         */
        //void parse(uint8 *buf, uint32 bufsize, IPDatagram *dest);
	void parse(uint8 *buf, uint32 bufsize, SCTPMessage *dest);
	
	static uint32 checksum(uint8 *buf, register uint32 len);	
};

#endif
