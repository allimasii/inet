//
// Copyright (C) 2004-2005 Andras Varga
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

#include <algorithm>   // min,max
#include "TCPReno.h"
#include "TCP.h"


Register_Class(TCPReno);


TCPReno::TCPReno() : TCPTahoeRenoFamily(),
  state((TCPRenoStateVariables *&)TCPAlgorithm::state)
{
}

void TCPReno::recalculateSlowStartThreshold()
{
// RFC 2581, page 4:
// "When a TCP sender detects segment loss using the retransmission
// timer, the value of ssthresh MUST be set to no more than the value
// given in equation 3:
//
//   ssthresh = max (FlightSize / 2, 2*SMSS)            (3)
//
// As discussed above, FlightSize is the amount of outstanding data in
// the network."

    // set ssthresh to flight size/2, but at least 2 SMSS
    // (the formula below practically amounts to ssthresh=cwnd/2 most of the time)
    uint32 flight_size = std::min(state->snd_cwnd, state->snd_wnd);
    state->ssthresh = std::max(flight_size/2, 2*state->snd_mss);
    if (ssthreshVector) ssthreshVector->record(state->ssthresh);
}

void TCPReno::processRexmitTimer(TCPEventCode& event)
{
    TCPTahoeRenoFamily::processRexmitTimer(event);
    if (event==TCP_E_ABORT)
        return;

    // begin Slow Start (RFC2001)
    recalculateSlowStartThreshold();
    state->snd_cwnd = state->snd_mss;
    if (cwndVector) cwndVector->record(state->snd_cwnd);
    tcpEV << "Begin Slow Start: resetting cwnd to " << state->snd_cwnd
          << ", ssthresh=" << state->ssthresh << "\n";

    state->recovery_after_rto = true;

    conn->retransmitOneSegment(); // FIXED 2009-08-05 by T.R.
    // After REXMIT timeout TCP Reno should start slow start with snd_cwnd = snd_mss.
    //
    // If calling "retransmitData();" there is no rexmit limitation (bytesToSend > snd_cwnd)
    // therefore "retransmitOneSegment();" needs to be used. After receiving ACK
    // "retransmitDataAfterRto(state->snd_cwnd);" will be called to rexmit outstanding data.
    //
    // RFC 2001, page 2:
    // "3.  When congestion occurs (indicated by a timeout or the reception
    //      of duplicate ACKs), one-half of the current window size (the
    //      minimum of cwnd and the receiver's advertised window, but at
    //      least two segments) is saved in ssthresh.  Additionally, if the
    //      congestion is indicated by a timeout, cwnd is set to one segment
    //      (i.e., slow start)."
}

void TCPReno::receivedDataAck(uint32 firstSeqAcked)
{
    TCPTahoeRenoFamily::receivedDataAck(firstSeqAcked);

    if (state->dupacks>=3)
    {
        //
        // Perform Fast Recovery: set cwnd to ssthresh (deflating the window).
        //
        tcpEV << "Fast Recovery: setting cwnd to ssthresh=" << state->ssthresh << "\n";
        state->snd_cwnd = state->ssthresh;
        if (cwndVector) cwndVector->record(state->snd_cwnd);
    }
    else
    {
        //
        // Perform slow start and congestion avoidance.
        //
        if (state->snd_cwnd < state->ssthresh)
        {
            tcpEV << "cwnd<=ssthresh: Slow Start: increasing cwnd by one segment, to ";

            // perform Slow Start. rfc 2581: "During slow start, a TCP increments cwnd
            // by at most SMSS bytes for each ACK received that acknowledges new data."
            state->snd_cwnd += state->snd_mss;

            // NOTE: we could increase cwnd based on the number of bytes being
            // acknowledged by each arriving ACK, rather than by the number of ACKs
            // that arrive. This is called "Appropriate Byte Counting" (ABC) and is
            // described in rfc 3465. This rfc is experimental and probably not
            // implemented in real-life TCPs, hence it's commented out. Also, the ABC
            // rfc would require other modifications as well in addition to the
            // two lines below.
            //
            // int bytesAcked = state->snd_una - firstSeqAcked;
            // state->snd_cwnd += bytesAcked*state->snd_mss;

            if (cwndVector) cwndVector->record(state->snd_cwnd);

            tcpEV << "cwnd=" << state->snd_cwnd << "\n";
        }
        else
        {
            // perform Congestion Avoidance (rfc 2581)
            int incr = state->snd_mss * state->snd_mss / state->snd_cwnd;
            if (incr==0)
                incr = 1;
            state->snd_cwnd += incr;
            if (cwndVector) cwndVector->record(state->snd_cwnd);

            //
            // NOTE: some implementations use extra additive constant mss/8 here
            // which is known to be incorrect (rfc 2581 p5)
            //
            // NOTE 2: rfc 3465 (experimental) "Appropriate Byte Counting" (ABC)
            // would require maintaining a bytes_acked variable here which we don't do
            //

            tcpEV << "cwnd>ssthresh: Congestion Avoidance: increasing cwnd linearly, to " << state->snd_cwnd << "\n";
        }
    }

    if (state->recovery_after_rto)
        conn->retransmitDataAfterRto(state->snd_cwnd);
    else
        sendData();
}

void TCPReno::receivedDuplicateAck()
{
    TCPTahoeRenoFamily::receivedDuplicateAck();

    if (state->dupacks==3)
    {
        tcpEV << "Reno on dupAck=3: perform Fast Retransmit, and enter Fast Recovery:";

        // Fast Retransmission: retransmit missing segment without waiting
        // for the REXMIT timer to expire
        conn->retransmitOneSegment();
        // RFC 2581, page 5:
        // "After the fast retransmit algorithm sends what appears to be the
        // missing segment, the "fast recovery" algorithm governs the
        // transmission of new data until a non-duplicate ACK arrives.
        // (...) the TCP sender can continue to transmit new
        // segments (although transmission must continue using a reduced cwnd)."

        // enter slow start
        // "set cwnd to ssthresh plus 3 times the segment size." (rfc 2001)
        recalculateSlowStartThreshold();
        state->snd_cwnd = state->ssthresh + 3*state->snd_mss;  // 20051129 (1)
        if (cwndVector) cwndVector->record(state->snd_cwnd);

        tcpEV << "set cwnd=" << state->snd_cwnd << ", ssthresh=" << state->ssthresh << "\n";

        // restart retransmission timer (with rexmit_count=0), and cancel round-trip time measurement
        // (see p972 "29.4 Fast Retransmit and Fast Recovery Algorithms" of
        // TCP/IP Illustrated, Vol2) -- but that's probably New Reno
        cancelEvent(rexmitTimer);
        startRexmitTimer();
        state->rtseq_sendtime = 0;
    }
    else if (state->dupacks > 3)
    {
        //
        // Reno: For each additional duplicate ACK received, increment cwnd by SMSS.
        // This artificially inflates the congestion window in order to reflect the
        // additional segment that has left the network
        //
        state->snd_cwnd += state->snd_mss;
        tcpEV << "Reno on dupAck>3: Fast Recovery: inflating cwnd by SMSS, new cwnd=" << state->snd_cwnd << "\n";
        if (cwndVector) cwndVector->record(state->snd_cwnd);

        // sendData() changes snd_nxt (to snd_max), therefore is should not be called if recovery_after_rto is set
        if (!state->recovery_after_rto)
            sendData();
    }
}
