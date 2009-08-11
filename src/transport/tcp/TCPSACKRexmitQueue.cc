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


#include "TCPSACKRexmitQueue.h"


TCPSACKRexmitQueue::TCPSACKRexmitQueue()
{
    conn = NULL;
    begin = end = 0;
}

TCPSACKRexmitQueue::~TCPSACKRexmitQueue()
{
    while (!rexmitQueue.empty())
        rexmitQueue.pop_front(); // TODO rexmit warnings (delete operator) are still present
}

void TCPSACKRexmitQueue::init(uint32 seqNum)
{
    begin = seqNum;
    end = seqNum;
}

std::string TCPSACKRexmitQueue::str() const
{
    std::stringstream out;
    out << "[" << begin << ".." << end << ")";
    return out.str();
}

uint32 TCPSACKRexmitQueue::getBufferEndSeq()
{
    return end;
}

void TCPSACKRexmitQueue::discardUpTo(uint32 seqNum)
{
    if (rexmitQueue.empty())
        return;

    ASSERT(seqLE(begin,seqNum) && seqLE(seqNum,end));
    begin = seqNum;

    RexmitQueue::iterator i = rexmitQueue.begin();
    while (i!=rexmitQueue.end()) // discard/delete regions from rexmit queue, which have been acked
    {
        if (seqLess(i->beginSeqNum,begin))
            i = rexmitQueue.erase(i);
        else
            i++;
    }

    // update begin and end of rexmit queue
    if (rexmitQueue.empty())
        begin = end = 0;
    else
    {
        i = rexmitQueue.begin();
        begin = i->beginSeqNum;
        i = rexmitQueue.end();
        end = i->endSeqNum;
    }
}

void TCPSACKRexmitQueue::enqueueSentData(uint32 fromSeqNum, uint32 toSeqNum)
{
    bool found = false;

    tcpEV << "rexmitQ: " << str() << " enqueueSentData [" << fromSeqNum << ".." << toSeqNum << ")\n";

    Region region;
    region.beginSeqNum = fromSeqNum;
    region.endSeqNum = toSeqNum;
    region.sacked = false;
    region.rexmitted = false;

    if (getQueueLength()==0)
    {
        begin = fromSeqNum;
        end = toSeqNum;
        rexmitQueue.push_back(region);
        tcpEV << "rexmitQ: rexmitQLength=" << getQueueLength() << "\n";
        return;
    }

    if (seqLE(begin,fromSeqNum) && seqLE(toSeqNum,end))
    {
        // Search for region in queue!
        RexmitQueue::iterator i = rexmitQueue.begin();
        while (i!=rexmitQueue.end())
        {
            if (i->beginSeqNum == fromSeqNum && i->endSeqNum == toSeqNum)
            {
                i->rexmitted=true; // set rexmitted bit
                found = true;
            }
            i++;
        }
    }

    if (!found)
    {
        end = toSeqNum;
        rexmitQueue.push_back(region);
    }
    tcpEV << "rexmitQ: rexmitQLength=" << getQueueLength() << "\n";
}

void TCPSACKRexmitQueue::setSackedBit(uint32 fromSeqNum, uint32 toSeqNum)
{
    bool found = false;

    if (seqLE(begin,fromSeqNum) && seqLE(toSeqNum,end))
    {
        RexmitQueue::iterator i = rexmitQueue.begin();
        while (i!=rexmitQueue.end())
        {
            if (i->beginSeqNum == fromSeqNum && i->endSeqNum == toSeqNum) // Search for region in queue!
            {
                i->sacked=true; // set sacked bit
                found = true;
            }
            i++;
        }
    }

    if (!found)
        tcpEV << "FAILED to set sacked bit for region: [" << fromSeqNum << ".." << toSeqNum << "). Not found in retransmission queue.\n";
}

uint32 TCPSACKRexmitQueue::getQueueLength()
{
    return rexmitQueue.size();
}

uint32 TCPSACKRexmitQueue::getNumRexmittedRegions()
{
    uint32 counter = 0;

    RexmitQueue::iterator i = rexmitQueue.begin();
    while (i!=rexmitQueue.end())
    {
        if (i->rexmitted)
        {
            counter++;
            tcpEV << counter << ". rexmitted region: [" << i->beginSeqNum << ".." << i->endSeqNum << ")\n";
        }
        i++;
    }
    return counter;
}

uint32 TCPSACKRexmitQueue::getHighestSackedSeqNum()
{
    uint32 tmp_highest_sacked = 0;

    RexmitQueue::iterator i = rexmitQueue.begin();
    while (i!=rexmitQueue.end())
    {
        if (i->sacked)
            tmp_highest_sacked = i->endSeqNum;
        i++;
    }
    return tmp_highest_sacked;
}

uint32 TCPSACKRexmitQueue::getNumSndGaps(uint32 toSeqNum)
{
    uint32 counter = 0;

    if (toSeqNum==0 || rexmitQueue.empty() || !(seqLE(begin,toSeqNum) && seqLE(toSeqNum,end)))
        return counter;

    RexmitQueue::iterator i = rexmitQueue.begin();
    while (i!=rexmitQueue.end())
    {
        if (i->endSeqNum > toSeqNum)
            break;
        if (!i->sacked)
            counter++;
        i++;
    }
    return counter;
}

uint32 TCPSACKRexmitQueue::checkRexmitQueueForSackedOrRexmittedSegments(uint32 fromSeqNum)
{
    uint32 counter = 0;

    if (fromSeqNum==0 || rexmitQueue.empty() || !(seqLE(begin,fromSeqNum) && seqLE(fromSeqNum,end)))
        return counter;

    RexmitQueue::iterator i = rexmitQueue.begin();
    while (i!=rexmitQueue.end())
    {
        // search for fromSeqNum (snd_nxt)
        if (i->beginSeqNum == fromSeqNum)
            break;
        else
            i++;
    }

    // search for adjacent sacked/rexmitted regions
    while (i!=rexmitQueue.end())
    {
        if (i->sacked || i->rexmitted)
        {
            counter = counter + (i->endSeqNum - i->beginSeqNum);

            // adjacent regions?
            uint32 tmp = i->endSeqNum;
            i++;
            if (i->beginSeqNum != tmp)
                break;
        }
        else
            break;
    }
    return counter;
}

void TCPSACKRexmitQueue::resetSackedBit()
{
    RexmitQueue::iterator i = rexmitQueue.begin();
    while (i!=rexmitQueue.end())
    {
        i->sacked=false; // reset sacked bit
        i++;
    }
}

void TCPSACKRexmitQueue::resetRexmittedBit()
{
    RexmitQueue::iterator i = rexmitQueue.begin();
    while (i!=rexmitQueue.end())
    {
        i->rexmitted=false; // reset rexmitted bit
        i++;
    }
}
