//
// Copyright (C) 2004 Andras Varga
//               2009 Thomas Reschka
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


#include <string.h>
#include <algorithm>   // min,max
#include "TCP.h"
#include "TCPConnection.h"
#include "TCPSegment.h"
#include "TCPCommand_m.h"
#include "IPControlInfo.h"
#include "IPv6ControlInfo.h"
#include "TCPSendQueue.h"
#include "TCPSACKRexmitQueue.h"
#include "TCPReceiveQueue.h"
#include "TCPAlgorithm.h"

//
// helper functions
//

const char *TCPConnection::stateName(int state)
{
#define CASE(x) case x: s=#x+6; break
    const char *s = "unknown";
    switch (state)
    {
        CASE(TCP_S_INIT);
        CASE(TCP_S_CLOSED);
        CASE(TCP_S_LISTEN);
        CASE(TCP_S_SYN_SENT);
        CASE(TCP_S_SYN_RCVD);
        CASE(TCP_S_ESTABLISHED);
        CASE(TCP_S_CLOSE_WAIT);
        CASE(TCP_S_LAST_ACK);
        CASE(TCP_S_FIN_WAIT_1);
        CASE(TCP_S_FIN_WAIT_2);
        CASE(TCP_S_CLOSING);
        CASE(TCP_S_TIME_WAIT);
    }
    return s;
#undef CASE
}

const char *TCPConnection::eventName(int event)
{
#define CASE(x) case x: s=#x+6; break
    const char *s = "unknown";
    switch (event)
    {
        CASE(TCP_E_IGNORE);
        CASE(TCP_E_OPEN_ACTIVE);
        CASE(TCP_E_OPEN_PASSIVE);
        CASE(TCP_E_SEND);
        CASE(TCP_E_CLOSE);
        CASE(TCP_E_ABORT);
        CASE(TCP_E_STATUS);
        CASE(TCP_E_RCV_DATA);
        CASE(TCP_E_RCV_ACK);
        CASE(TCP_E_RCV_SYN);
        CASE(TCP_E_RCV_SYN_ACK);
        CASE(TCP_E_RCV_FIN);
        CASE(TCP_E_RCV_FIN_ACK);
        CASE(TCP_E_RCV_RST);
        CASE(TCP_E_RCV_UNEXP_SYN);
        CASE(TCP_E_TIMEOUT_2MSL);
        CASE(TCP_E_TIMEOUT_CONN_ESTAB);
        CASE(TCP_E_TIMEOUT_FIN_WAIT_2);
    }
    return s;
#undef CASE
}

const char *TCPConnection::indicationName(int code)
{
#define CASE(x) case x: s=#x+6; break
    const char *s = "unknown";
    switch (code)
    {
        CASE(TCP_I_DATA);
        CASE(TCP_I_URGENT_DATA);
        CASE(TCP_I_ESTABLISHED);
        CASE(TCP_I_PEER_CLOSED);
        CASE(TCP_I_CLOSED);
        CASE(TCP_I_CONNECTION_REFUSED);
        CASE(TCP_I_CONNECTION_RESET);
        CASE(TCP_I_TIMED_OUT);
        CASE(TCP_I_STATUS);
    }
    return s;
#undef CASE
}

void TCPConnection::printConnBrief()
{
    tcpEV << "Connection ";
    tcpEV << localAddr << ":" << localPort << " to " << remoteAddr << ":" << remotePort;
    tcpEV << "  on app[" << appGateIndex << "],connId=" << connId;
    tcpEV << "  in " << stateName(fsm.getState());
    tcpEV << "  (ptr=0x" << this << ")\n";
}

void TCPConnection::printSegmentBrief(TCPSegment *tcpseg)
{
    tcpEV << "." << tcpseg->getSrcPort() << " > ";
    tcpEV << "." << tcpseg->getDestPort() << ": ";

    if (tcpseg->getSynBit())  tcpEV << (tcpseg->getAckBit() ? "SYN+ACK " : "SYN ");
    if (tcpseg->getFinBit())  tcpEV << "FIN(+ACK) ";
    if (tcpseg->getRstBit())  tcpEV << (tcpseg->getAckBit() ? "RST+ACK " : "RST ");
    if (tcpseg->getPshBit())  tcpEV << "PSH ";

    if (tcpseg->getPayloadLength()>0 || tcpseg->getSynBit())
    {
        tcpEV << "[" << tcpseg->getSequenceNo() << ".." << (tcpseg->getSequenceNo()+tcpseg->getPayloadLength()) << ") ";
        tcpEV << "(l=" << tcpseg->getPayloadLength() << ") ";
    }
    if (tcpseg->getAckBit())  tcpEV << "ack " << tcpseg->getAckNo() << " ";
    tcpEV << "win " << tcpseg->getWindow() << "\n";
    if (tcpseg->getUrgBit())  tcpEV << "urg " << tcpseg->getUrgentPointer() << " ";
}

TCPConnection *TCPConnection::cloneListeningConnection()
{
    TCPConnection *conn = new TCPConnection(tcpMain,appGateIndex,connId);

    // following code to be kept consistent with initConnection()
    const char *sendQueueClass = sendQueue->getClassName();
    conn->sendQueue = check_and_cast<TCPSendQueue *>(createOne(sendQueueClass));
    conn->sendQueue->setConnection(conn);

    const char *receiveQueueClass = receiveQueue->getClassName();
    conn->receiveQueue = check_and_cast<TCPReceiveQueue *>(createOne(receiveQueueClass));
    conn->receiveQueue->setConnection(conn);

    const char *tcpAlgorithmClass = tcpAlgorithm->getClassName();
    conn->tcpAlgorithm = check_and_cast<TCPAlgorithm *>(createOne(tcpAlgorithmClass));
    conn->tcpAlgorithm->setConnection(conn);

    conn->state = conn->tcpAlgorithm->getStateVariables();
    configureStateVariables();
    conn->tcpAlgorithm->initialize();

    // put it into LISTEN, with our localAddr/localPort
    conn->state->active = false;
    conn->state->fork = true;
    conn->localAddr = localAddr;
    conn->localPort = localPort;
    FSM_Goto(conn->fsm, TCP_S_LISTEN);

    return conn;
}

void TCPConnection::sendToIP(TCPSegment *tcpseg)
{
    // record seq (only if we do send data) and ackno
    if (sndNxtVector && tcpseg->getPayloadLength()!=0)
        sndNxtVector->record(tcpseg->getSequenceNo());
    if (sndAckVector)
        sndAckVector->record(tcpseg->getAckNo());

    // final touches on the segment before sending
    tcpseg->setSrcPort(localPort);
    tcpseg->setDestPort(remotePort);
    ASSERT(tcpseg->getHeaderLength() >= TCP_HEADER_OCTETS);     // TCP_HEADER_OCTETS = 20 (without options)
    ASSERT(tcpseg->getHeaderLength() <= TCP_MAX_HEADER_OCTETS); // TCP_MAX_HEADER_OCTETS = 60
    tcpseg->setByteLength(tcpseg->getHeaderLength() + tcpseg->getPayloadLength());


    tcpEV << "Sending: ";
    printSegmentBrief(tcpseg);

    // TBD reuse next function for sending

    if (!remoteAddr.isIPv6())
    {
        // send over IPv4
        IPControlInfo *controlInfo = new IPControlInfo();
        controlInfo->setProtocol(IP_PROT_TCP);
        controlInfo->setSrcAddr(localAddr.get4());
        controlInfo->setDestAddr(remoteAddr.get4());
        tcpseg->setControlInfo(controlInfo);

        tcpMain->send(tcpseg,"ipOut");
    }
    else
    {
        // send over IPv6
        IPv6ControlInfo *controlInfo = new IPv6ControlInfo();
        controlInfo->setProtocol(IP_PROT_TCP);
        controlInfo->setSrcAddr(localAddr.get6());
        controlInfo->setDestAddr(remoteAddr.get6());
        tcpseg->setControlInfo(controlInfo);

        tcpMain->send(tcpseg,"ipv6Out");
    }
}

void TCPConnection::sendToIP(TCPSegment *tcpseg, IPvXAddress src, IPvXAddress dest)
{
    tcpEV << "Sending: ";
    printSegmentBrief(tcpseg);

    if (!dest.isIPv6())
    {
        // send over IPv4
        IPControlInfo *controlInfo = new IPControlInfo();
        controlInfo->setProtocol(IP_PROT_TCP);
        controlInfo->setSrcAddr(src.get4());
        controlInfo->setDestAddr(dest.get4());
        tcpseg->setControlInfo(controlInfo);

        check_and_cast<TCP *>(simulation.getContextModule())->send(tcpseg,"ipOut");
    }
    else
    {
        // send over IPv6
        IPv6ControlInfo *controlInfo = new IPv6ControlInfo();
        controlInfo->setProtocol(IP_PROT_TCP);
        controlInfo->setSrcAddr(src.get6());
        controlInfo->setDestAddr(dest.get6());
        tcpseg->setControlInfo(controlInfo);

        check_and_cast<TCP *>(simulation.getContextModule())->send(tcpseg,"ipv6Out");
    }
}

TCPSegment *TCPConnection::createTCPSegment(const char *name)
{
    return new TCPSegment(name);
}

void TCPConnection::signalConnectionTimeout()
{
    sendIndicationToApp(TCP_I_TIMED_OUT);
}

void TCPConnection::sendIndicationToApp(int code)
{
    tcpEV << "Notifying app: " << indicationName(code) << "\n";
    cMessage *msg = new cMessage(indicationName(code));
    msg->setKind(code);
    TCPCommand *ind = new TCPCommand();
    ind->setConnId(connId);
    msg->setControlInfo(ind);
    tcpMain->send(msg, "appOut", appGateIndex);
}

void TCPConnection::sendEstabIndicationToApp()
{
    tcpEV << "Notifying app: " << indicationName(TCP_I_ESTABLISHED) << "\n";
    cMessage *msg = new cMessage(indicationName(TCP_I_ESTABLISHED));
    msg->setKind(TCP_I_ESTABLISHED);

    TCPConnectInfo *ind = new TCPConnectInfo();
    ind->setConnId(connId);
    ind->setLocalAddr(localAddr);
    ind->setRemoteAddr(remoteAddr);
    ind->setLocalPort(localPort);
    ind->setRemotePort(remotePort);

    msg->setControlInfo(ind);
    tcpMain->send(msg, "appOut", appGateIndex);
}

void TCPConnection::sendToApp(cMessage *msg)
{
    tcpMain->send(msg, "appOut", appGateIndex);
}

void TCPConnection::initConnection(TCPOpenCommand *openCmd)
{
    // create send queue
    const char *sendQueueClass = openCmd->getSendQueueClass();
    if (!sendQueueClass || !sendQueueClass[0])
        sendQueueClass = tcpMain->par("sendQueueClass");
    sendQueue = check_and_cast<TCPSendQueue *>(createOne(sendQueueClass));
    sendQueue->setConnection(this);

    // create receive queue
    const char *receiveQueueClass = openCmd->getReceiveQueueClass();
    if (!receiveQueueClass || !receiveQueueClass[0])
        receiveQueueClass = tcpMain->par("receiveQueueClass");
    receiveQueue = check_and_cast<TCPReceiveQueue *>(createOne(receiveQueueClass));
    receiveQueue->setConnection(this);

    // create SACK retransmit queue
    rexmitQueue = new TCPSACKRexmitQueue();
    rexmitQueue->setConnection(this);

    // create algorithm
    const char *tcpAlgorithmClass = openCmd->getTcpAlgorithmClass();
    if (!tcpAlgorithmClass || !tcpAlgorithmClass[0])
        tcpAlgorithmClass = tcpMain->par("tcpAlgorithmClass");
    tcpAlgorithm = check_and_cast<TCPAlgorithm *>(createOne(tcpAlgorithmClass));
    tcpAlgorithm->setConnection(this);

    // create state block
    state = tcpAlgorithm->getStateVariables();
    configureStateVariables();
    tcpAlgorithm->initialize();
}

void TCPConnection::configureStateVariables()
{
    state->delayed_acks_enabled = tcpMain->par("delayedAcksEnabled"); // delayed ACKs enabled/disabled
    state->nagle_enabled = tcpMain->par("nagleEnabled"); // Nagle's algorithm enabled/disabled
    state->rcv_wnd = tcpMain->par("advertisedWindow"); // advertisedWindow/maxRcvBuffer is used as initial value for rcv_wnd
    state->maxRcvBuffer = tcpMain->par("advertisedWindow"); // advertisedWindow/maxRcvBuffer is used as initial value for rcv_wnd
    state->snd_mss = tcpMain->par("mss").longValue(); // maximum segment siz
    state->sack_support = tcpMain->par("sackSupport"); // if set, this means that current host supports SACK
}

void TCPConnection::selectInitialSeqNum()
{
    // set the initial send sequence number
    state->iss = (unsigned long)fmod(SIMTIME_DBL(simTime())*250000.0, 1.0+(double)(unsigned)0xffffffffUL) & 0xffffffffUL;

    state->snd_una = state->snd_nxt = state->snd_max = state->iss;

    sendQueue->init(state->iss+1); // +1 is for SYN
    rexmitQueue->init(state->iss + 1); // +1 is for SYN
}

bool TCPConnection::isSegmentAcceptable(TCPSegment *tcpseg)
{
    // check that segment entirely falls in receive window
    // RFC 793, page 69:
    // There are four cases for the acceptability test for an incoming segment:
    uint32 seg_len = tcpseg->getPayloadLength();
    uint32 seqNo = tcpseg->getSequenceNo();

    if (seg_len == 0 && state->rcv_wnd == 0) {
        return (seqNo == state->rcv_nxt);
    }

    else if (seg_len == 0 && state->rcv_wnd > 0) {
        return (seqLE(state->rcv_nxt, seqNo) && seqLess(seqNo, state->rcv_nxt
                + state->rcv_wnd));
    }

    else if (seg_len > 0 && state->rcv_wnd == 0) {
        return false; // not acceptable
    }

    else if (seg_len > 0 && state->rcv_wnd > 0) {
        return ((seqLE(state->rcv_nxt, seqNo) && seqLess(seqNo, state->rcv_nxt
                + state->rcv_wnd)) || (seqLE(state->rcv_nxt, seqNo + seg_len
                - 1) && seqLess(seqNo + seg_len - 1, state->rcv_nxt
                + state->rcv_wnd)));
    } else
        return false;
}

void TCPConnection::sendSyn()
{
    if (remoteAddr.isUnspecified() || remotePort==-1)
        opp_error("Error processing command OPEN_ACTIVE: foreign socket unspecified");
    if (localPort==-1)
        opp_error("Error processing command OPEN_ACTIVE: local port unspecified");

    // create segment
    TCPSegment *tcpseg = createTCPSegment("SYN");
    tcpseg->setSequenceNo(state->iss);
    tcpseg->setSynBit(true);
    updateRcvWnd();
    tcpseg->setWindow(state->rcv_wnd);
    if (rcvWndVector)
        {rcvWndVector->record(state->rcv_wnd);}

    state->snd_max = state->snd_nxt = state->iss+1;

    // write header options
    writeHeaderOptions(tcpseg);

    // send it
    sendToIP(tcpseg);
}

void TCPConnection::sendSynAck()
{
    // create segment
    TCPSegment *tcpseg = createTCPSegment("SYN+ACK");
    tcpseg->setSequenceNo(state->iss);
    tcpseg->setAckNo(state->rcv_nxt);
    tcpseg->setSynBit(true);
    tcpseg->setAckBit(true);
    updateRcvWnd();
    tcpseg->setWindow(state->rcv_wnd);
    if (rcvWndVector)
        {rcvWndVector->record(state->rcv_wnd);}

    state->snd_max = state->snd_nxt = state->iss+1;

    // write header options
    writeHeaderOptions(tcpseg);

    // send it
    sendToIP(tcpseg);
}

void TCPConnection::sendRst(uint32 seqNo)
{
    sendRst(seqNo, localAddr, remoteAddr, localPort, remotePort);
}

void TCPConnection::sendRst(uint32 seq, IPvXAddress src, IPvXAddress dest, int srcPort, int destPort)
{
    TCPSegment *tcpseg = createTCPSegment("RST");

    tcpseg->setSrcPort(srcPort);
    tcpseg->setDestPort(destPort);

    tcpseg->setRstBit(true);
    tcpseg->setSequenceNo(seq);

    // send it
    sendToIP(tcpseg, src, dest);
}

void TCPConnection::sendRstAck(uint32 seq, uint32 ack, IPvXAddress src, IPvXAddress dest, int srcPort, int destPort)
{
    TCPSegment *tcpseg = createTCPSegment("RST+ACK");

    tcpseg->setSrcPort(srcPort);
    tcpseg->setDestPort(destPort);

    tcpseg->setRstBit(true);
    tcpseg->setAckBit(true);
    tcpseg->setSequenceNo(seq);
    tcpseg->setAckNo(ack);

    // send it
    sendToIP(tcpseg, src, dest);
}

void TCPConnection::sendAck()
{
    TCPSegment *tcpseg = createTCPSegment("ACK");

    tcpseg->setAckBit(true);
    tcpseg->setSequenceNo(state->snd_nxt);
    tcpseg->setAckNo(state->rcv_nxt);
    updateRcvWnd();
    tcpseg->setWindow(state->rcv_wnd);
    if (rcvWndVector)
        {rcvWndVector->record(state->rcv_wnd);}

    // write header options
    writeHeaderOptions(tcpseg);

    // send it
    sendToIP(tcpseg);

    // notify
    tcpAlgorithm->ackSent();
}

void TCPConnection::sendFin()
{
    TCPSegment *tcpseg = createTCPSegment("FIN");

    // Note: ACK bit *must* be set for both FIN and FIN+ACK. What makes
    // the difference for FIN+ACK is that its ackNo acks the remote TCP's FIN.
    tcpseg->setFinBit(true);
    tcpseg->setAckBit(true);
    tcpseg->setAckNo(state->rcv_nxt);
    tcpseg->setSequenceNo(state->snd_nxt);
    updateRcvWnd();
    tcpseg->setWindow(state->rcv_wnd);
    if (rcvWndVector)
        {rcvWndVector->record(state->rcv_wnd);}

    // send it
    sendToIP(tcpseg);

    // notify
    tcpAlgorithm->ackSent();
}

void TCPConnection::sendSegment(uint32 bytes)
{
    uint32 forward = 0;
    uint32 old_snd_nxt = state->snd_nxt;

    if (state->sack_enabled)
    {
        // update highest_sack and snd_gaps
        state->highest_sack = rexmitQueue->getHighestSackedSeqNum();
        state->snd_gaps = rexmitQueue->getNumSndGaps(state->highest_sack);
        if (sndGapsVector)
            {sndGapsVector->record(state->snd_gaps);}

        // is sender able to see snd_gaps (snd_gaps>0)?
        if (state->snd_gaps > 0  && seqLess(state->snd_nxt, state->snd_max))
        {
            // try to forward snd_nxt before sending new data
            state->snd_nxt = state->snd_una;
            // check rexmitQ
            forward = rexmitQueue->checkRexmitQueueForSackedOrRexmittedSegments(state->snd_nxt);
            state->snd_nxt = state->snd_nxt + forward;

            // if forward is 0, reset snd_nxt to old_snd_nxt
            if (forward == 0)
                {state->snd_nxt = old_snd_nxt;}

            // avoid to resend a segment until it is not clear it has been lost (seqNum <= highestSackedSegNum)
            else if (seqGE(state->snd_nxt, state->highest_sack) && !state->recovery_after_rto)
                {state->snd_nxt = old_snd_nxt;}
        }
    }

    // send one segment of 'bytes' bytes from snd_nxt, and advance snd_nxt
    TCPSegment *tcpseg = sendQueue->createSegmentWithBytes(state->snd_nxt, bytes);

    // if sack_enabled copy region of tcpseg to rexmitQueue
    if (state->sack_enabled)
        {rexmitQueue->enqueueSentData(state->snd_nxt, state->snd_nxt+bytes);}

    tcpseg->setAckNo(state->rcv_nxt);
    tcpseg->setAckBit(true);
    updateRcvWnd();
    tcpseg->setWindow(state->rcv_wnd);
    if (rcvWndVector)
        {rcvWndVector->record(state->rcv_wnd);}
    // TBD when to set PSH bit?
    // TBD set URG bit if needed
    ASSERT(bytes==tcpseg->getPayloadLength());

    state->snd_nxt += bytes;

    if (state->send_fin && state->snd_nxt==state->snd_fin_seq)
    {
        tcpEV << "Setting FIN on segment\n";
        tcpseg->setFinBit(true);
        state->snd_nxt = state->snd_fin_seq+1;
    }

    sendToIP(tcpseg);
}

bool TCPConnection::sendData(bool fullSegmentsOnly, uint32 congestionWindow) // changed from int congestionWindow to uint32 congestionWindow 2009-08-05 by T.R.
{
    uint32 old_rexmitted_gaps = 0;
    if (state->sack_enabled)
        {old_rexmitted_gaps = rexmitQueue->getNumRexmittedRegions();}

    // we'll start sending from snd_max
    state->snd_nxt = state->snd_max;

    // check how many bytes we have
    ulong buffered = sendQueue->getBytesAvailable(state->snd_nxt);
    if (buffered==0)
        return false;

    // maxWindow is minimum of snd_wnd and congestionWindow (snd_cwnd)
    ulong maxWindow = std::min(state->snd_wnd, congestionWindow);

    // effectiveWindow: number of bytes we're allowed to send now
    long effectiveWin = maxWindow - (state->snd_nxt - state->snd_una);
    if (effectiveWin <= 0)
    {
        tcpEV << "Effective window is zero (advertised window " << state->snd_wnd <<
                 ", congestion window " << congestionWindow << "), cannot send.\n";
        return false;
    }

    ulong bytesToSend = effectiveWin;

    if (bytesToSend > buffered)
        bytesToSend = buffered;

    if (fullSegmentsOnly && bytesToSend < state->snd_mss)
    {
        tcpEV << "Cannot send, not enough data for a full segment (SMSS=" << state->snd_mss
              << ", in buffer " << buffered << ")\n";
        return false;
    }

    // start sending 'bytesToSend' bytes
    tcpEV << "Will send " << bytesToSend << " bytes (effectiveWindow " << effectiveWin
          << ", in buffer " << buffered << " bytes)\n";

    uint32 old_snd_nxt = state->snd_nxt;
    ASSERT(bytesToSend>0);

#ifdef TCP_SENDFRAGMENTS  /* normally undefined */
    // make agressive use of the window until the last byte
    while (bytesToSend>0)
    {
        ulong bytes = std::min(bytesToSend, state->snd_mss);
        sendSegment(bytes);
        bytesToSend -= bytes;
    }
#else
    // send <MSS segments only if it's the only segment we can send now
    // FIXME this should probably obey Nagle's alg -- to be checked
    if (bytesToSend <= state->snd_mss)
    {
        sendSegment(bytesToSend);
    }
    else
    {
        // send whole segments only (nagle_enabled)
        while (bytesToSend>=state->snd_mss)
        {
            sendSegment(state->snd_mss);
            bytesToSend -= state->snd_mss;
        }
        if (bytesToSend>0)
           tcpEV << bytesToSend << " bytes of space left in effectiveWindow\n";
    }
#endif

    // remember highest seq sent (snd_nxt may be set back on retransmission,
    // but we'll need snd_max to check validity of ACKs -- they must ack
    // something we really sent)
    state->snd_max = std::max (state->snd_nxt, state->snd_max);
    if (unackedVector) unackedVector->record(state->snd_max - state->snd_una);

    // notify (once is enough)
    tcpAlgorithm->ackSent();
    if (old_rexmitted_gaps == state->rexmitted_gaps) // don't measure RTT for retransmitted packets
        {tcpAlgorithm->dataSent(old_snd_nxt);}

    return true;
}

bool TCPConnection::sendProbe()
{
    // we'll start sending from snd_max
    state->snd_nxt = state->snd_max;

    // check we have 1 byte to send
    if (sendQueue->getBytesAvailable(state->snd_nxt)==0)
    {
        tcpEV << "Cannot send probe because send buffer is empty\n";
        return false;
    }

    uint32 old_snd_nxt = state->snd_nxt;

    tcpEV << "Sending 1 byte as probe, with seq=" << state->snd_nxt << "\n";
    sendSegment(1);

    // remember highest seq sent (snd_nxt may be set back on retransmission,
    // but we'll need snd_max to check validity of ACKs -- they must ack
    // something we really sent)
    state->snd_max = state->snd_nxt;
    if (unackedVector) unackedVector->record(state->snd_max - state->snd_una);

    // notify
    tcpAlgorithm->ackSent();
    tcpAlgorithm->dataSent(old_snd_nxt);

    return true;
}

void TCPConnection::retransmitOneSegment()
{
    // retransmit one segment at snd_una, and set snd_nxt accordingly
    state->snd_nxt = state->snd_una;

    ulong bytes = std::min(state->snd_mss, state->snd_max - state->snd_nxt);
    ASSERT(bytes!=0);

    sendSegment(bytes);

    // notify
    tcpAlgorithm->ackSent();
}

void TCPConnection::retransmitData()
{
    // retransmit everything from snd_una
    state->snd_nxt = state->snd_una;

    ulong bytesToSend = state->snd_max - state->snd_nxt;
    ASSERT(bytesToSend!=0);

    // TBD - avoid to send more than allowed - check cwnd and rwnd before retransmitting data!
    while (bytesToSend>0)
    {
        ulong bytes = std::min(bytesToSend, (ulong)state->snd_mss);
        bytes = std::min(bytes, sendQueue->getBytesAvailable(state->snd_nxt));
        sendSegment(bytes);
        // Do not send packets after the FIN.
        // fixes bug that occurs in examples/inet/bulktransfer at event #64043  T=13.861159213744
        if (state->send_fin && state->snd_nxt==state->snd_fin_seq+1)
            break;
        bytesToSend -= bytes;
    }
}

void TCPConnection::retransmitDataAfterRto(uint32 congestionWindow)
{
    // sendWindow is minimum of snd_wnd and congestionWindow (snd_cwnd)
    ulong sendWindow = std::min(state->snd_wnd, congestionWindow);
    ASSERT(sendWindow!=0);

    ulong bytesToSend = state->snd_max - state->snd_nxt;
    ASSERT(bytesToSend!=0);

    while (bytesToSend>0 && sendWindow>0)
    {
        if (state->nagle_enabled && (bytesToSend < state->snd_mss || sendWindow < state->snd_mss))
            {break;}

        ulong bytes = std::min(bytesToSend, (ulong) state->snd_mss);
        bytes = std::min(bytes, sendQueue->getBytesAvailable(state->snd_nxt));
        sendSegment(bytes);

        bytesToSend = bytesToSend - bytes;
        sendWindow = sendWindow - bytes;

        // check if recovery_after_rto bit can be reset
        uint32 snd_nxt_tmp = state->snd_nxt;
        if (state->sack_enabled)
        {
            uint32 forward = rexmitQueue->checkRexmitQueueForSackedOrRexmittedSegments(state->snd_nxt);
            snd_nxt_tmp = state->snd_nxt + forward;
        }

        if (seqGE(snd_nxt_tmp, state->snd_max))
        {
            state->recovery_after_rto = false;
            state->snd_nxt = snd_nxt_tmp;
            break;
        }
    }
}

void TCPConnection::readHeaderOptions(TCPSegment *tcpseg)
{
    tcpEV << "TCP Header Option(s) received:\n";

    for (uint i=0; i<tcpseg->getOptionsArraySize(); i++)
    {
        TCPOption option = tcpseg->getOptions(i);
        short kind = option.getKind();
        short length = option.getLength();
        tcpEV << "Received option of kind " << kind << " with length " << length << "\n";
        bool lengthMatched = false;

        switch(kind)
        {
            case 0: // EOL
            {
                if (length == 1)
                {
                    lengthMatched = true;
                    tcpEV << "TCP Header Option EOL received\n";
                }
                break;
            }
            case 1: // NOP
            {
                if (length == 1)
                {
                    lengthMatched = true;
                    tcpEV << "TCP Header Option NOP received\n";
                }
                break;
            }
            case 2: // MSS
            {
                if (length == 4)
                {
                    lengthMatched = true;
                    if (option.getValuesArraySize()!=0)
                    {
                        if (fsm.getState() == TCP_S_LISTEN || fsm.getState() == TCP_S_SYN_SENT)
                        {
                            // RFC 2581, page 1:
                            // "The SMSS is the size of the largest segment that the sender can transmit.
                            // This value can be based on the maximum transmission unit of the network,
                            // the path MTU discovery [MD90] algorithm, RMSS (see next item), or other
                            // factors.  The size does not include the TCP/IP headers and options."
                            //
                            // "The RMSS is the size of the largest segment the receiver is willing to accept.
                            // This is the value specified in the MSS option sent by the receiver during
                            // connection startup.  Or, if the MSS option is not used, 536 bytes [Bra89].
                            // The size does not include the TCP/IP headers and options."
                            //
                            //
                            // The value of snd_mss (SMSS) is set to the minimum of snd_mss (local parameter) and
                            // the value specified in the MSS option received during connection startup.
                            state->snd_mss = std::min(state->snd_mss, (uint32) option.getValues(0));
                            if(state->snd_mss==0)
                                {state->snd_mss = 536;}
                            tcpEV << "TCP Header Option MSS received, SMSS is set to: " << state->snd_mss << "\n";
                        }
                        else
                            {tcpEV << "ERROR: TCP Header Option MSS received, but in unexpected state\n";}
                    }
                    else
                        {tcpEV << "ERROR: TCP Header Option MSS received, but no SMSS value present\n";}
                }
                break;
            }
            case 4: // SACK_PERMITTED
            {
                if (length == 2)
                {
                    lengthMatched = true;
                    if (fsm.getState() == TCP_S_LISTEN || fsm.getState() == TCP_S_SYN_SENT)
                    {
                        state->rcv_sack_perm = true;
                        state->sack_enabled = state->sack_support && state->snd_sack_perm && state->rcv_sack_perm;
                        tcpEV << "TCP Header Option SACK_PERMITTED received, SACK is set to: " << state->sack_enabled << "\n";
                    }
                    else
                        {tcpEV << "ERROR: TCP Header Option SACK_PERMITTED received, but in unexpected state\n";}
                }
                break;
            }
            case 5: // SACK
            {
                if (length%8 == 2)
                {
                    lengthMatched = true;
                    if (state->sack_enabled) // not need to check the state here?
                    {
                        // temporary variable
                        int n = option.getValuesArraySize()/2;
                        if (n>0) // sacks present?
                        {
                            tcpEV << n << " SACK(s) received:\n";
                            uint count=0;
                            for (int i=0; i<n; i++)
                            {
                                Sack tmp;
                                tmp.setStart(option.getValues(count));
                                count++;
                                tmp.setEnd(option.getValues(count));
                                count++;

                                uint32 sack_range = tmp.getEnd() - tmp.getStart();
                                tcpEV << (i+1) << ". SACK:" << " [" << tmp.getStart() << ".." << tmp.getEnd() << ")\n";

                                // check for D-SACK
                                if (i==0 && seqLess(tmp.getEnd(), tcpseg->getAckNo()))
                                {
                                    // RFC 2883, page 8:
                                    // "In order for the sender to check that the first (D)SACK block of an
                                    // acknowledgement in fact acknowledges duplicate data, the sender
                                    // should compare the sequence space in the first SACK block to the
                                    // cumulative ACK which is carried IN THE SAME PACKET.  If the SACK
                                    // sequence space is less than this cumulative ACK, it is an indication
                                    // that the segment identified by the SACK block has been received more
                                    // than once by the receiver.  An implementation MUST NOT compare the
                                    // sequence space in the SACK block to the TCP state variable snd.una
                                    // (which carries the total cumulative ACK), as this may result in the
                                    // wrong conclusion if ACK packets are reordered."
                                    tcpEV << "Received D-SACK below cumulative ACK=" << tcpseg->getAckNo() << " D-SACK:" << " [" << tmp.getStart() << ".." << tmp.getEnd() << ")\n";
                                }
                                else if (i==0 && seqGE(tmp.getEnd(), tcpseg->getAckNo()) && n>1)
                                {
                                    // RFC 2883, page 8:
                                    // "If the sequence space in the first SACK block is greater than the
                                    // cumulative ACK, then the sender next compares the sequence space in
                                    // the first SACK block with the sequence space in the second SACK
                                    // block, if there is one.  This comparison can determine if the first
                                    // SACK block is reporting duplicate data that lies above the cumulative
                                    // ACK."
                                    Sack tmp2;
                                    tmp2.setStart(option.getValues(2));
                                    tmp2.setEnd(option.getValues(3));

                                    if (seqGE(tmp.getStart(), tmp2.getStart()) && seqLE(tmp.getEnd(), tmp2.getEnd()))
                                        {tcpEV << "Received D-SACK above cumulative ACK=" << tcpseg->getAckNo() << " D-SACK:" << " [" << tmp.getStart() << ".." << tmp.getEnd() << ") SACK:" << " [" << tmp2.getStart() << ".." << tmp2.getEnd() << ")\n";}
                                }

                                // splitt sack_range to smss_sized pieces
                                uint32 tmp_sack_range = sack_range;
                                uint32 counter = 1; // at least one piece has been received

                                while (tmp_sack_range > state->snd_mss) // to check how many smss_sized pieces are covered by this single sack_range
                                {
                                    tmp_sack_range = tmp_sack_range - state->snd_mss;
                                    counter++;
                                }

                                // find smss_sized_sack in send queue and set "sacked" bit
                                uint32 mss_sized_sack = tmp.getStart();
                                for (uint j=0;j<counter;j++)
                                {
                                    if (j+1==counter) // the last part does not need to be smss_sized (nagle off)
                                    {
                                        if (seqGE(mss_sized_sack,state->snd_una))
                                            {rexmitQueue->setSackedBit(mss_sized_sack,mss_sized_sack+tmp_sack_range);}
                                        else
                                            {tcpEV << "Received old sack. Sacked segment number is below snd_una\n";}
                                    }
                                    else
                                    {
                                        if (seqGE(mss_sized_sack,state->snd_una))
                                            {rexmitQueue->setSackedBit(mss_sized_sack,mss_sized_sack+state->snd_mss);}
                                        else
                                            {tcpEV << "Received old sack. Sacked segment number is below snd_una\n";}
                                    }
                                    mss_sized_sack = mss_sized_sack + state->snd_mss;
                                }
                            }
                            state->rcv_sacks = state->rcv_sacks + n; // total counter, no current number
                            if (rcvSacksVector)
                                {rcvSacksVector->record(state->rcv_sacks);}
                        }
                    }
                    else
                        {tcpEV << "ERROR: " << (length/2) << ". SACK(s) received, but sack_enabled is set to " << state->sack_enabled << "\n";}
                }
                break;
            }

            // TODO add new TCPOptions here once they are implemented

            default:
            {
                lengthMatched = true;
                tcpEV << "ERROR: Received option of kind " << kind << " with length " << length << " which is currently not supported\n";
                break;
            }
        }

        if (!lengthMatched)
            {tcpEV << "ERROR: Received option of kind " << kind << " with incorrect length " << length << "\n";}
    }
}

TCPSegment TCPConnection::writeHeaderOptions(TCPSegment *tcpseg)
{
    TCPOption option;
    int t = 0;

    if (tcpseg->getSynBit() && (fsm.getState() == TCP_S_INIT || fsm.getState() == TCP_S_LISTEN || ((fsm.getState()==TCP_S_SYN_SENT || fsm.getState()==TCP_S_SYN_RCVD) && state->syn_rexmit_count>0))) // SYN flag set and connetion in INIT or LISTEN state (or after synRexmit timeout)
    {
        // MSS header option
        if (state->snd_mss > 0)
        {
            option.setKind(2);
            option.setLength(4);
            option.setValuesArraySize(1);

            // Update MSS
            option.setValues(0,state->snd_mss);
            tcpEV << "TCP Header Option MSS(=" << state->snd_mss << ") sent\n";
            tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize()+1);
            tcpseg->setOptions(t,option);
            t++;
        }

        // SACK_PERMITTED header option
        if (state->sack_support) // Is SACK supported by host?
        {
            // 2 padding bytes
            option.setKind(1); // NOP
            option.setLength(1);
            option.setValuesArraySize(0);
            tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize()+2);
            tcpseg->setOptions(t,option);
            t++;
            tcpseg->setOptions(t,option);
            t++;

            option.setKind(4);
            option.setLength(2);
            option.setValuesArraySize(0);

            // Update SACK variable
            state->snd_sack_perm = true;
            state->sack_enabled = state->sack_support && state->snd_sack_perm && state->rcv_sack_perm;
            tcpEV << "TCP Header Option SACK_PERMITTED sent, SACK is set to: " << state->sack_enabled << "\n";
            tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize()+1);
            tcpseg->setOptions(t,option);
            t++;
        }

        // TODO add new TCPOptions here once they are implemented
    }
    else if (fsm.getState()==TCP_S_SYN_RCVD || fsm.getState()==TCP_S_ESTABLISHED || fsm.getState()==TCP_S_FIN_WAIT_1 || fsm.getState()==TCP_S_FIN_WAIT_2) // connetion is not in INIT or LISTEN state
    {
        // SACK header option

        // RFC 2018, page 4:
        // "If sent at all, SACK options SHOULD be included in all ACKs which do
        // not ACK the highest sequence number in the data receiver's queue.  In
        // this situation the network has lost or mis-ordered data, such that
        // the receiver holds non-contiguous data in its queue.  RFC 1122,
        // Section 4.2.2.21, discusses the reasons for the receiver to send ACKs
        // in response to additional segments received in this state.  The
        // receiver SHOULD send an ACK for every valid segment that arrives
        // containing new data, and each of these "duplicate" ACKs SHOULD bear a
        // SACK option."
        if (state->sack_enabled && (state->snd_sack || state->snd_dsack))
        {
            // 2 padding bytes
            option.setKind(1); // NOP
            option.setLength(1);
            option.setValuesArraySize(0);
            tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize()+2);
            tcpseg->setOptions(t,option);
            t++;
            tcpseg->setOptions(t,option);
            t++;

            addSacks(tcpseg);
            t++;
        }

        // TODO add new TCPOptions here once they are implemented
    }

    if (tcpseg->getOptionsArraySize() != 0)
    {
        uint options_len = 0;
        for (uint i=0; i<tcpseg->getOptionsArraySize(); i++)
            {options_len = options_len + tcpseg->getOptions(i).getLength();}

        if (options_len <= 40) // Options length allowed? - maximum: 40 Bytes
            {tcpseg->setHeaderLength(TCP_HEADER_OCTETS+options_len);} // TCP_HEADER_OCTETS = 20
        else
        {
            tcpseg->setHeaderLength(TCP_HEADER_OCTETS); // TCP_HEADER_OCTETS = 20
            tcpseg->setOptionsArraySize(0); // drop all options
            tcpEV << "ERROR: Options length exceeded! Segment will be sent without options" << "\n";
        }
    }

    return *tcpseg;
}

TCPSegment TCPConnection::addSacks(TCPSegment *tcpseg)
{
    TCPOption option;
    uint options_len = 0;
    uint used_options_len = 0;
    uint n = 0;
    bool skip_sacks_array = false;

    uint32 start = state->start_seqno;
    uint32 end = state->end_seqno;

    ASSERT(start!=0 || end!=0);

    n = receiveQueue->getQueueLength();
    if (state->snd_dsack)
        {n++;}

    // 2 padding bytes are prefixed
    if (tcpseg->getOptionsArraySize()>0)
    {
        for (uint i=0; i<tcpseg->getOptionsArraySize(); i++)
            {used_options_len = used_options_len + tcpseg->getOptions(i).getLength();}
        if (used_options_len>30)
        {
            tcpEV << "ERROR: Failed to addSacks - at least 10 free bytes needed for SACK - used_options_len=" << used_options_len << "\n";
            //reset flags:
            skip_sacks_array = false;
            state->snd_sack  = false;
            state->snd_dsack = false;
            state->start_seqno = 0;
            state->end_seqno = 0;
            return *tcpseg;
        }
        else
        {
            n = std::min (n, (((40-used_options_len)-2)/8));
            option.setValuesArraySize(n*2);
        }
    }
    else
    {
        n = std::min (n, MAX_SACK_ENTRIES);
        option.setValuesArraySize(n*2);
    }

    // before adding a new sack move old sacks by one to the right
    for (int a=(MAX_SACK_BLOCKS-1); a>=0; a--) // MAX_SACK_BLOCKS is set to 60
        {state->sacks_array[a+1] = state->sacks_array[a];}

    if (state->snd_dsack) // SequenceNo < rcv_nxt
    {
        // RFC 2883, page 3:
        // "(3) The left edge of the D-SACK block specifies the first sequence
        // number of the duplicate contiguous sequence, and the right edge of
        // the D-SACK block specifies the sequence number immediately following
        // the last sequence in the duplicate contiguous sequence."
        if (seqLess(start, state->rcv_nxt) && seqLess(state->rcv_nxt, end))
            {end = state->rcv_nxt;}
    }
    else if (start==0 && end==0) // rcv_nxt_old != rcv_nxt
    {
        // RFC 2018, page 4:
        // "* The first SACK block (i.e., the one immediately following the
        // kind and length fields in the option) MUST specify the contiguous
        // block of data containing the segment which triggered this ACK,
        // unless that segment advanced the Acknowledgment Number field in
        // the header.  This assures that the ACK with the SACK option
        // reflects the most recent change in the data receiver's buffer
        // queue."
        start = state->sacks_array[0].getStart();
        end = state->sacks_array[0].getEnd();
    }
    else // rcv_nxt_old == rcv_nxt
    {
        // RFC 2018, page 4:
        // "* The first SACK block (i.e., the one immediately following the
        // kind and length fields in the option) MUST specify the contiguous
        // block of data containing the segment which triggered this ACK,"
        start = receiveQueue->getLE(start);
        end = receiveQueue->getRE(end);
    }

    state->sacks_array[0].setStart(start);
    state->sacks_array[0].setEnd(end);

    // RFC 2883, page 3:
    // "(4) If the D-SACK block reports a duplicate contiguous sequence from
    // a (possibly larger) block of data in the receiver's data queue above
    // the cumulative acknowledgement, then the second SACK block in that
    // SACK option should specify that (possibly larger) block of data.
    //
    // (5) Following the SACK blocks described above for reporting duplicate
    // segments, additional SACK blocks can be used for reporting additional
    // blocks of data, as specified in RFC 2018."
    if (state->snd_dsack)
    {
        uint32 start_new = receiveQueue->getLE(start);
        uint32 end_new = receiveQueue->getRE(end);
        if (start_new != start || end_new != end)
        {
            skip_sacks_array = true;
            for (int a=(MAX_SACK_BLOCKS-1); a>=1; a--) // MAX_SACK_BLOCKS is set to 60
                {state->sacks_array[a+1] = state->sacks_array[a];}
            state->sacks_array[1].setStart(start_new); // specifies larger block of data
            state->sacks_array[1].setEnd(end_new);     // specifies larger block of data
        }
    }

    // RFC 2018, page 4:
    // "* The SACK option SHOULD be filled out by repeating the most
    // recently reported SACK blocks (based on first SACK blocks in
    // previous SACK options) that are not subsets of a SACK block
    // already included in the SACK option being constructed."

    // check if recently reported SACK blocks are subsets of "sacks_array[0]"
    for (uint a=0; a<MAX_SACK_BLOCKS-1; a++)
    {
        uint i = 1;
        bool matched = false;

        if (a==0 && skip_sacks_array)
            {a=1;}

        if (state->sacks_array[a+i].getStart() == 0)
            {break;}

        while ((state->sacks_array[a].getStart() == state->sacks_array[a+i].getStart() ||
                state->sacks_array[a].getEnd() == state->sacks_array[a+i].getStart() ||
                state->sacks_array[a].getEnd() == state->sacks_array[a+i].getEnd())
                && a+i < MAX_SACK_BLOCKS && state->sacks_array[a].getStart()!=0) // MAX_SACK_BLOCKS is set to 60
        {
            matched = true;
            i++;
        }
        if (matched)
            {state->sacks_array[a+1] = state->sacks_array[a+i];}
    }

    option.setKind(5); // SACK
    option.setLength(8*n+2);
    option.setValuesArraySize(2*n);

    // write sacks from sacks_array to options
    uint counter = 0;
    for (uint a=0; a<n; a++)
    {
        option.setValues(counter,state->sacks_array[a].getStart());
        counter++;
        option.setValues(counter,state->sacks_array[a].getEnd());
        counter++;
    }

    // independent of "n" we always need 2 padding bytes (NOP) to make: (used_options_len % 4 == 0)
    options_len = used_options_len + 8*n + 2; // 8 bytes for each SACK (n) + 2 bytes for kind&length

    if (options_len <= 40) // Options length allowed? - maximum: 40 Bytes
    {
        tcpseg->setOptionsArraySize(tcpseg->getOptionsArraySize()+1);
        tcpseg->setOptions((tcpseg->getOptionsArraySize()-1),option);

        // update number of sent sacks
        state->snd_sacks = state->snd_sacks+n;
        if (sndSacksVector)
            {sndSacksVector->record(state->snd_sacks);}

        uint counter = 0;
        tcpEV << n << " SACK(s) added to header: rcv_nxt=" << state->rcv_nxt << "\n";
        for (uint t=0; t<(n*2); t++)
        {
            counter++;
            tcpEV << counter << ". SACK:" << " [" << option.getValues(t);
            t++;
            tcpEV << ".." << option.getValues(t) << ")";
            if (t==1 && state->snd_dsack)
                {tcpEV << " (D-SACK)";}
            tcpEV << "\n";
        }
    }
    else
        {tcpEV << "ERROR: Option length exceeded! Segment will be sent without SACK(s)" << "\n";}

    // RFC 2883, page 3:
    // "(1) A D-SACK block is only used to report a duplicate contiguous
    // sequence of data received by the receiver in the most recent packet.
    //
    // (2) Each duplicate contiguous sequence of data received is reported
    // in at most one D-SACK block.  (I.e., the receiver sends two identical
    // D-SACK blocks in subsequent packets only if the receiver receives two
    // duplicate segments.)//
    //
    // In case of d-sack: delete first sack (d-sack) and move old sacks by one to the left
    if (state->snd_dsack)
    {
        for (int a=1; a<MAX_SACK_BLOCKS; a++) // MAX_SACK_BLOCKS is set to 60
            {state->sacks_array[a-1] = state->sacks_array[a];}

        // delete/reset last sack to avoid duplicates
        state->sacks_array[MAX_SACK_BLOCKS-1].setStart(0);
        state->sacks_array[MAX_SACK_BLOCKS-1].setEnd(0);
    }

    // delete old sacks (below rcv_nxt), delete duplicates and print status of sacks_array:
    tcpEV << "Status of sacks_array:\n";
    for (int a=0; a<MAX_SACK_BLOCKS; a++) // MAX_SACK_BLOCKS is set to 60
    {
        if (state->sacks_array[a].getStart()!=0 && seqLE(state->sacks_array[a].getEnd(), state->rcv_nxt))
        {
            state->sacks_array[a].setStart(0);
            state->sacks_array[a].setEnd(0);
        }
        if (state->sacks_array[a].getStart()!=0 && state->sacks_array[a].getEnd()!=0) // do not print empty entries
            {tcpEV << (a+1) << ". sack in sacks_array:" << " [" << state->sacks_array[a].getStart() << ".." << state->sacks_array[a].getEnd() << ")\n";}
        else
            {break;}
    }

    // reset flags:
    skip_sacks_array = false;
    state->snd_sack  = false;
    state->snd_dsack = false;
    state->start_seqno = 0;
    state->end_seqno = 0;

    return *tcpseg;
}

void TCPConnection::updateRcvQueueVars()
{
    // update receive queue related state variables
    state->freeRcvBuffer = receiveQueue->getAmountOfFreeBytes(state->maxRcvBuffer);
    state->usedRcvBuffer = state->maxRcvBuffer - state->freeRcvBuffer;

    // update receive queue related statistics
    if (tcpRcvQueueBytesVector)
        {tcpRcvQueueBytesVector->record(state->usedRcvBuffer);}

    tcpEV << "receiveQ: receiveQLength=" << receiveQueue->getQueueLength() << " maxRcvBuffer=" << state->maxRcvBuffer << " usedRcvBuffer=" << state->usedRcvBuffer << " freeRcvBuffer=" << state->freeRcvBuffer << "\n";
}

void TCPConnection::updateRcvWnd()
{
    uint32 win = 0;

    // update receive queue related state variables and statistics
    updateRcvQueueVars();
    win = state->freeRcvBuffer;
    state->rcv_wnd = win;

    // Following lines are based on [Stevens, W.R.: TCP/IP Illustrated, Volume 2, pages 878-879]:
    // Don't advertise less than one full-sized segment to avoid SWS
    if (win < (state->maxRcvBuffer / 4) && win < state->snd_mss)
        {win = 0;}
    // Oberserve upper limit for advertised window on this connection
    if (win > state->maxRcvBuffer) // TODO maxRcvBuffer should be replaced by TCP_MAXWIN
        {win = state->maxRcvBuffer;}
    /***    // Do not shrink window
     // (rcv_adv minus rcv_nxt) is the amount of space still available to the sender that was previously advertised
     if (win < state->rcv_adv - state->rcv_nxt)
     {win = state->rcv_adv - state->rcv_nxt;}
     ***/// TODO commented out because state variable rcv_adv is currently missing

    state->rcv_wnd = win;
}

void TCPConnection::updateWndInfo(TCPSegment *tcpseg)
{
    // Following lines are based on [Stevens, W.R.: TCP/IP Illustrated, Volume 2, page 982]:
    if (tcpseg->getAckBit()
        && (seqLess(state->snd_wl1, tcpseg->getSequenceNo()) ||
        (state->snd_wl1 == tcpseg->getSequenceNo()&& seqLE(state->snd_wl2, tcpseg->getAckNo())) ||
        (state->snd_wl2 == tcpseg->getAckNo()&& tcpseg->getWindow() > state->snd_wnd)))
    {
        // send window should be updated
        tcpEV << "Updating send window from segment: new wnd=" << tcpseg->getWindow() << "\n";
        state->snd_wnd = tcpseg->getWindow();
        state->snd_wl1 = tcpseg->getSequenceNo();
        state->snd_wl2 = tcpseg->getAckNo();
        if (sndWndVector)
            {sndWndVector->record(state->snd_wnd);}
    }
}
