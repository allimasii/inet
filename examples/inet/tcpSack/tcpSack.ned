///////////////////////////////////////////////////////////////////////
//  filename: tcpSack.ned
//  author: Thomas Reschka
//  network description for tcp example "tcpSack"
///////////////////////////////////////////////////////////////////////

package inet.examples.inet.tcpSack;

import inet.nodes.inet.Router;
import inet.nodes.inet.StandardHostWithULDropsGenerator;
import inet.nodes.inet.StandardHostWithDLDuplicatesGenerator;
import ned.DatarateChannel;

network tcpSack {
    @display("bgb=400,200");
    submodules:
        router1: Router {
            parameters:
                @display("p=200,100;i=abstract/router");
            gates:
                pppg[2];
        }
        client1: StandardHostWithULDropsGenerator {
            parameters:
                @display("p=50,100");
            gates:
                pppg[1];
        }
        server1: StandardHostWithULDropsGenerator { // for config 1-5
//        server1: StandardHostWithDLDuplicatesGenerator { // for config 6
            parameters:
                @display("p=350,100;i=device/server");
            gates:
                pppg[1];
        }
    connections allowunconnected:
        router1.pppg[0] <--> NormalPath <--> client1.pppg[0];
        router1.pppg[1] <--> BottleneckPath <--> server1.pppg[0];
}

channel NormalPath extends DatarateChannel {
    parameters:
        delay = 0.0565us; // 10m
        datarate = 100Mbps;
        ber = 0;
}

channel BottleneckPath extends DatarateChannel {
    parameters:
        delay = 0.565us; // 100m
        datarate = 10Mbps; // bottleneck
        ber = 0;
}
