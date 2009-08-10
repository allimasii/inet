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


package inet.transport.tcp;

//
// \TCP protocol implementation. Supports RFC 793, RFC 1122, RFC 2001.
// Compatible with both IPv4 and IPv6.
//
// A \TCP segment is represented by the class TCPSegment.
//
// <b>Communication with clients</b>
//
// For communication between client applications and TCP, the TcpCommandCode
// and TcpStatusInd enums are used as message kinds, and TCPCommand
// and its subclasses are used as control info.
//
// To open a connection from a client app, send a cMessage to TCP with
// TCP_C_OPEN_ACTIVE as message kind and a TCPOpenCommand object filled in
// and attached to it as control info. (The peer TCP will have to be LISTENing;
// the server app can achieve this with a similar cMessage but TCP_C_OPEN_PASSIVE
// message kind.) With passive open, there's a possibility to cause the connection
// "fork" on an incoming connection, leaving the original connection LISTENing
// on the port (see the fork field in TCPOpenCommand).
//
// The client app can send data by assigning the TCP_C_SEND message kind
// and attaching a TCPSendCommand control info object to the data packet,
// and sending it to TCP. The server app will receive data as messages
// with the TCP_I_DATA message kind and TCPSendCommand control info.
// (Whether you'll receive the same or identical messages, or even whether
// you'll receive data in the same sized chunks as sent depends on the
// sendQueueClass and receiveQueueClass used, see below. With
// TCPVirtualDataSendQueue and TCPVirtualDataRcvQueue set, message objects
// and even message boundaries are not preserved.)
//
// To close, the client sends a cMessage to TCP with the TCP_C_CLOSE message kind
// and TCPCommand control info.
//
// TCP sends notifications to the application whenever there's a significant
// change in the state of the connection: established, remote TCP closed,
// closed, timed out, connection refused, connection reset, etc. These
// notifications are also cMessages with message kind TCP_I_xxx
// (TCP_I_ESTABLISHED, etc.) and TCPCommand as control info.
//
// One TCP module can serve several application modules, and several
// connections per application. The <i>k</i>th application connects to TCP's
// appIn[k] and appOut[k] ports. When talking to applications, a
// connection is identified by the (application port index, connId) pair,
// where connId is assigned by the application in the OPEN call.
//
// <b>Sockets</b>
//
// The TCPSocket C++ class is provided to simplify managing \TCP connections
// from applications. TCPSocket handles the job of assembling and sending
// command messages (OPEN, CLOSE, etc) to TCP, and it also simplifies
// the task of dealing with packets and notification messages coming from TCP.
//
// <b>Communication with the \IP layer</b>
//
// The TCP model relies on sending and receiving IPControlInfo objects
// attached to \TCP segment objects as control info
// (see cMessage::setControlInfo()).
//
// <b>Configuring TCP</b>
//
// The module parameters sendQueueClass and receiveQueueClass should be
// set the names of classes that manage the actual send and receive queues.
// Currently you have two choices:
//
//   -# set them to "TCPVirtualDataSendQueue" and "TCPVirtualDataRcvQueue".
//      These classes manage "virtual bytes", that is, only byte counts are
//      transmitted over the \TCP connection and no actual data. cMessage
//      contents, and even message boundaries are not preserved with these
//      classes: for example, if the client sends a single cMessage with
//      length = 1 megabyte over TCP, the receiver-side client will see a
//      sequence of MSS-sized messages.
//
//   -# use "TCPMsgBasedSendQueue" and "TCPMsgBasedRcvQueue", which transmit
//      cMessage objects (and subclasses) over a \TCP connection. The same
//      message object sequence that was sent by the client to the
//      sender-side TCP entity will be reproduced on the receiver side.
//      If a client sends a cMessage with length = 1 megabyte, the
//      receiver-side client will receive the same message object (or a clone)
//      after the TCP entities have completed simulating the transmission
//      of 1 megabyte over the connection. This is a different behaviour
//      from TCPVirtualDataSendQueue/RcvQueue.
//
// It depends on the client (app) modules which sendQueue/rcvQueue they require.
// For example, TCPGenericSrvApp needs message-based sendQueue/rcvQueue,
// while TCPEchoApp or TCPSinkApp can work with any (but TCPEchoApp will
// display different behaviour with both!)
//
// In the future, other send queue and receive queue classes may be
// implemented, e.g. to allow transmission of "raw bytes" (actual byte arrays).
//
// The \TCP flavour supported depends on the value of the tcpAlgorithmClass
// module parameters, e.g. "TCPTahoe" or "TCPReno". In the future, other
// classes can be written which implement New Reno, Vegas, LinuxTCP (which
// differs from others) or other variants.
//
// Note that TCPOpenCommand allows sendQueueClass, receiveQueueClass and
// tcpAlgorithmClass to be chosen per-connection.
//
// Notes:
//  - if you do active OPEN, then send data and close before the connection
//    has reached ESTABLISHED, the connection will go from SYN_SENT to CLOSED
//    without actually sending the buffered data. This is consistent with
//    rfc 763 but may not be what you'd expect.
//  - handling segments with SYN+FIN bits set (esp. with data too) is
//    inconsistent across TCPs, so check this one if it's of importance
//
// <b>Standards</b>
//
// The TCP module itself implements the following:
//  - all RFC793 \TCP states and state transitions
//  - connection setup and teardown as in RFC793
//  - generally, RFC793 compliant segment processing
//  - all socked commands (except RECEIVE) and indications
//  - receive buffer to cache above-sequence data and data not yet forwarded
//    to the user
//  - CONN-ESTAB timer, SYN-REXMIT timer, 2MSL timer, FIN-WAIT-2 timer
//
// The TCPTahoe and TCPReno algorithms implement:
//  - delayed acks, with 200ms timeout (optional)
//  - Nagle's algorithm (optional)
//  - Jacobson's and Karn's algorithms for round-trip time measurement and
//    adaptive retransmission
//  - \TCP Tahoe (Fast Retransmit), \TCP Reno (Fast Retransmit and Fast Recovery)
//
// Missing bits:
//  - URG and PSH bits not handled. Receiver always acts as if PSH was set
//    on all segments: always forwards data to the app as soon as possible.
//  - no RECEIVE command. Received data are always forwarded to the app as
//    soon as possible, as if the app issued a very large RECEIVE request
//    at the beginning. This means there's currently no flow control
//    between TCP and the app.
//  - all timeouts are precisely calculated: timer granularity (which is caused
//    by "slow" and "fast" i.e. 500ms and 200ms timers found in many *nix \TCP
//    implementations) is not simulated
//  - new ECN flags (CWR and ECE). Need to be added to header by [RFC 3168].
//
// TCPTahoe/TCPReno issues and missing features:
//  - KEEPALIVE not implemented (idle connections never time out)
//  - Nagle's algorithm possibly not precisely implemented
//
// The above problems are relatively easy to fix, and will be resolved in the
// next iteration. Also, other TCPAlgorithms will be added.
//
// <b>Tests</b>
//
// There are automated test cases (*.test files) for TCP -- see the Test
// directory in the source distribution.
//
//
// Enhancements by Thomas Reschka (2009-08-05):
//
//  - first TCP header options implemented (optional). Structure of TCPSegment slightly CHANGED.
//    The use of header options increases overhead (HeaderLength and ByteLength) appropriately.
//      - EOL: End of option list.
//      - NOP: Padding bytes, currently needed for SACK_PERMITTED and SACK.
//      - MSS: The value of snd_mss (SMSS) is set to the minimum of snd_mss (local parameter) and
//             the value specified in the MSS option received during connection startup. Based on [RFC 2581, page 1].
//      - SACK_PERMITTED: SACK can only be used if both nodes sent SACK_PERMITTED during connection startup.
//      - SACK: RFC 2018 and RFC 2883 are implemented but SACK (RFC 3517) is not yet implemented!
//              Added new queue (TCPRexmitQueue based on TCPSendQueue) to manage bits (sacked and rexmitted) for retransmissions.
//              Current SACK implementation is located to TCP main (and not to flavours) therefore all existing
//              TCP algorithm classes may be used with SACK, however only TCPReno and TCPTahoe make sense.
//  - flow control implemented.
//      - finite receive buffer size (initiated by parameter: advertisedWindow) implemented.
//        If receive buffer is exhausted (by out-of-order segments) and the payload length of a
//        new received segment is higher than free receiver buffer, new segment will be dropped,
//        what is monitored by tcpRcvQueueDropsVector.
//      - Update receive window. Data receiver updates all receiver queue relevant variables
//        before sending (ACK/SACK or DATA) to advertise the currently free amount of bytes of
//        his finite receive buffer, therefore data receiver is able to advertise a zero window.
//        Based on [Stevens, W.R.: TCP/IP Illustrated, Volume 2, pages 878-879].
//      - Slightly CHANGED update of window information (snd_wnd, snd_wl1, snd_wl2).
//        Based on [Stevens, W.R.: TCP/IP Illustrated, Volume 2, page 982].
//      - PERSIST timer implemented. If data sender receives a zero window and the REXMIT timer
//        is not running, the PERSIST timer is started.
//      - sending window probes. If PERSIST timer is expired a window probe is send to request a window update.
//  - other changes:
//      - new module parameter 'delayedAcksEnabled' added to enable/disable (optional) delayed ACKs.
//        CHANGED implementation of delayed ACKs.
//        Full sized segments are counted and ack_now bit is set to generate immediate ACK in certain cases.
//        Based on [Stevens, W.R.: TCP/IP Illustrated, Volume 2, page 861].
//      - new module parameter 'nagleEnabled' added to enable/disable (optional) Nagle's algorithm.
//        The Nagle's algorithm is unchanged and is possibly not precisely implemented.
//      - FIXED behavior of TCPReno after RTO. After REXMIT timeout TCP Reno should start slow start with
//        snd_cwnd = snd_mss. If calling "retransmitData();" there is no rexmit limitation (bytesToSend > snd_cwnd)
//        therefore "retransmitOneSegment();" needs to be used. After receiving ACK
//        "retransmitDataAfterRto(state->snd_cwnd);" will be called to rexmit outstanding data.
//      - Slightly CHANGED utility function "isSegmentAcceptable" (check that segment entirely falls in receive window).
//        Based on [RFC 793, page 69].
//      - CHANGED data type of some state variables (e.g. snd_wnd, snd_mss) from int/uint to uint32 to
//        simplify use of standard functions (e.g. std::min).
//      - CHANGED TCPDumb and ExtInterface to convert TCPSegments (including implemented TCP header options) from/to
//        binary (network byte order) TCPSegments.
//        This allows interoperability of simulation's TCP implementation with TCPs from real systems.
//  Please also see ChangeLog.
//
simple TCP
{
    parameters:
        int advertisedWindow = default(14*this.mss); // in bytes, corresponds with the maximal receiver buffer capacity (Note: normally, NIC queues should be at least this size)
        bool delayedAcksEnabled = default (false); // delayed ACKs enabled/disabled
        bool nagleEnabled = default (true); // Nagle's algorithm enabled/disabled
        int mss = default(536); // maximum segment size (header option)
        bool sackSupport = default(false); // selective acknowledgment (header option) enabled/disabled
        string tcpAlgorithmClass = default("TCPReno"); // TCPTahoe/TCPReno/TCPNoCongestionControl/DumbTCP
        string sendQueueClass = default("TCPVirtualDataSendQueue"); // TCPVirtualDataSendQueue/TCPMsgBasedSendQueue
        string receiveQueueClass = default("TCPVirtualDataRcvQueue"); // TCPVirtualDataRcvQueue/TCPMsgBasedRcvQueue
        bool recordStats = default(true); // recording seqNum etc. into output vectors on/off
        @display("i=block/wheelbarrow");
    gates:
        input appIn[];
        input ipIn;
        input ipv6In;
        output appOut[];
        output ipOut;
        output ipv6Out;
}
