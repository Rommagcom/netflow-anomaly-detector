#!/usr/bin/python
import collections
import csv
import datetime
import ipaddr
import sys

from pandas_analysis import get_attributes_from_flow_list

_FLOW_FIELDS = [
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "ip_protocol",
    "l7_proto",
    "in_bytes",
    "out_bytes",
    "in_pkts",
    "out_pkts",
    "tcp_flags",
    "duration",
    "label"
]


class Flow(collections.namedtuple("Flow", _FLOW_FIELDS)):
    __slots__ = ()

    @staticmethod
    def from_csv(e):
        """
        Factory method.

        Construct Flow instances from a CSV-representation of a flow.
        """
        return Flow(src_ip=ipaddr.IPAddress(e[0]),
                    src_port=int(e[1]),
                    dst_ip=ipaddr.IPAddress(e[2]),
                    dst_port=int(e[3]),
                    ip_protocol =int(e[4]),
                    l7_proto=int(e[5]),
                    in_bytes=int(e[6]),
                    out_bytes = int(e[7]),
                    in_pkts=int(e[8]),
                    out_pkts=int(e[9]),
                    tcp_flags=int(e[10]),
                    duration=int(e[11]),
                    label =int(e[12]))

_ALERT_FIELDS = [
    "name",
    "evidence",
]

Alert = collections.namedtuple("Alert", _ALERT_FIELDS)


class Analyzer(object):

    def __init__(self):
        self.__num_flows = 0

        self.__T = 10  # seconds to aggregate and load in memory
        self.flow_list = []

        self.__alerts = []

    def process(self, flow):
        """
        Process a flow.

        :param Flow flow: a data flow record
        """
        self.__num_flows += 1

        self.alert_flow_statistics(flow)

        # counter print
        if (self.__num_flows % 10000) == 0:
            print("done flows", self.__num_flows)

    def alert_flow_statistics(self, flow):
        """Checks if T time passed. Passes batch list_of_flows to outlier detection and flushes it."""
        self.flow_list.append(flow)
        if int(flow.ts.strftime('%s')) % self.__T == 0:
            self.outlier_flow_detection()
            self.flow_list = []

    def outlier_flow_detection(self):
        """
        Aggregate flow counters when called every T=10 seconds.
        Input: self.flow_list

        Outlier detection by calculating IQR of histograms of counters in pandas.

        Features extracted:
        int: number of packets/entries in T sec
        int: bytes_up, bytes_dw in T sec
        int: number of current dst_ports: len (dst_ports_used for (src_ip, dst_ip) pair)
        """
        for src_ip, dst_ip in get_attributes_from_flow_list(self.flow_list):
            for flow in self.flow_list:
                if (flow.src_ip.exploded == src_ip) and (flow.dst_ip.exploded == dst_ip):
                    # print("add alert")
                    self.__alerts.append(Alert(name="Flagged by IQR based outlier detection for ports or connections",
                                               evidence=[flow]))

    @property
    def alerts(self):
        """
        Return the alerts that were generated during the processing of flows.

        :return: a list of alerts
        :rtype: List[Alert]
        """
        return self.__alerts


def main(argv):
    analyzer = Analyzer()

    fin = csv.reader(sys.stdin)
    for e in fin:
        flow = Flow.from_csv(e)
        analyzer.process(flow)

    for alert in analyzer.alerts:
        print(alert.name)
        print("\n".join("\t{}".format(e) for e in alert.evidence))

    return 0

def main2(argv):
    analyzer = Analyzer()

    # pass input data stream as open("data.csv", "r") for quick testing
    with open('data.csv', 'r') as csvfile:
        fin = csv.reader(csvfile)
        for e in fin:
            flow = Flow.from_csv(e)
            analyzer.process(flow)

        for alert in analyzer.alerts:
            print(alert.name)
            print("\n".join("\t{}".format(e) for e in alert.evidence))

    print("Total Number of Alerts: "+str(len(analyzer.alerts)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
