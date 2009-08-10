//
// Copyright (C) 2009 Thomas Reschka
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program; if not, see <http://www.gnu.org/licenses/>.
//

#ifndef __INET_TCPVIRTUALDATAREXMITQUEUE_H
#define __INET_TCPVIRTUALDATAREXMITQUEUE_H

#include "TCPRexmitQueue.h"

/**
 * Rexmit queue that manages "virtual bytes", that is, byte counts only.
 */
class INET_API TCPVirtualDataRexmitQueue : public TCPRexmitQueue
{
  public:
    struct Region
    {
        uint32 beginSeqNum;
        uint32 endSeqNum;
        bool sacked;      // indicates whether region has already been sacked by data receiver
        bool rexmitted;   // indicates whether region has already been retransmitted by data sender
    };
    typedef std::list<Region> RexmitQueue;
    RexmitQueue rexmitQueue;

    uint32 begin;  // 1st sequence number stored
    uint32 end;    // last sequence number stored +1

  public:
    /**
     * Ctor
     */
    TCPVirtualDataRexmitQueue();

    /**
     * Virtual dtor.
     */
    virtual ~TCPVirtualDataRexmitQueue();

    /**
     *
     */
    virtual void init(uint32 seqNum);

    /**
     *
     */
    virtual std::string info() const;

    /**
     *
     */
    virtual uint32 getBufferEndSeq();

    /**
     *
     */
    virtual void discardUpTo(uint32 seqNum);

    /**
     *
     */
    virtual void enqueueSentData(uint32 fromSeqNum, uint32 toSeqNum);

    /**
     *
     */
    virtual void setSackedBit(uint32 fromSeqNum, uint32 toSeqNum);

    /**
     *
     */
    virtual uint32 getQueueLength();

    /**
     *
     */
    virtual uint32 getNumRexmittedRegions();

    /**
     *
     */
    virtual uint32 getHighestSackedSeqNum();

    /**
     *
     */
    virtual uint32 getNumSndGaps(uint32 toSeqNum);

    /**
     *
     */
    virtual uint32 checkRexmitQueueForSackedOrRexmittedSegments(uint32 fromSeq);

    /**
     *
     */
    virtual void resetSackedBit();

    /**
     *
     */
    virtual void resetRexmittedBit();
};
#endif
