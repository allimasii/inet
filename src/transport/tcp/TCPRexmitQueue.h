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

#ifndef __INET_TCPREXMITQUEUE_H
#define __INET_TCPREXMITQUEUE_H

#include <omnetpp.h>
#include "TCPConnection.h"
#include "TCPSegment.h"


/**
 * Abstract base class for TCP rexmit queues.
 * This class is based on TCPSendQueue and will only be used if sack_enabled is set to TRUE.
 */
class INET_API TCPRexmitQueue : public cPolymorphic
{
  protected:
    TCPConnection *conn; // the connection that owns this queue

  public:
    /**
     * Ctor.
     */
    TCPRexmitQueue()  {conn=NULL;}

    /**
     * Virtual dtor.
     */
    virtual ~TCPRexmitQueue() {}

    /**
     * Set the connection that owns this queue.
     */
    virtual void setConnection(TCPConnection *_conn)  {conn = _conn;}

    /**
     * Initialize the object. The startSeq parameter tells what sequence number the first
     * byte of app data should get. This is usually ISS+1 because SYN consumes
     * one byte in the sequence number space.
     *
     * init() may be called more than once; every call flushes the existing contents
     * of the queue.
     */
    virtual void init(uint32 seqNum) = 0;

    /**
     * Returns the sequence number of the last byte stored in the buffer plus one.
     * (The first byte of the next send operation would get this sequence number.)
     */
    virtual uint32 getBufferEndSeq() = 0;

    /**
     * Tells the queue that bytes up to (but NOT including) seqNum have been
     * transmitted and ACKed, so they can be removed from the queue.
     */
    virtual void discardUpTo(uint32 seqNum) = 0;

    /**
     * Inserts sent data to the rexmit queue.
     */
    virtual void enqueueSentData(uint32 fromSeqNum, uint32 toSeqNum) = 0;

    /**
     * Called when data sender received selective acknowledgments.
     * Tells the queue which bytes have been transmitted and SACKed,
     * so they can be skipped if retransmitting segments as long as
     * REXMIT timer did not expired.
     */
    virtual void setSackedBit(uint32 fromSeqNum, uint32 toSeqNum) = 0;

    /**
     * Returns the number of blocks currently buffered in queue.
     */
    virtual uint32 getQueueLength() = 0;

    /**
     * Returns the number of rexmitted regions and lists them in tcpEV.
     */
    virtual uint32 getNumRexmittedRegions() = 0;

    /**
     * Returns the highest sequence number sacked by data receiver.
     */
    virtual uint32 getHighestSackedSeqNum() = 0;

    /**
     * Returns the number of gaps seen by sender
     * (up to highest sacked sequence number).
     */
    virtual uint32 getNumSndGaps(uint32 toSeqNum) = 0;

    /**
     * Checks rexmit queue for sacked of rexmitted segments and returns a certain offset
     * (contiguous sacked or rexmitted region) to forward snd->nxt.
     * It is called before retransmitting data.
     */
    virtual uint32 checkRexmitQueueForSackedOrRexmittedSegments(uint32 fromSeqNum) = 0;

    /**
     * Called when REXMIT timer expired.
     * Resets sacked bit of all segments in rexmit queue.
     */
    virtual void resetSackedBit() = 0;

    /**
     * Called when REXMIT timer expired.
     * Resets rexmitted bit of all segments in rexmit queue.
     */
    virtual void resetRexmittedBit() = 0;
};

#endif
