from subprocess import check_call
import os
import json

class Analyzer(object):
    """
    Analyzer is a base class to execute Linux/Unix command which 
    retrieve the network attributes.
    """

    def __init__(self, _dict):
        """
        Analyzer instance consists of a dict with keys:
        * name      analyzer name
        * type      analyzer type
        * cmd       command
        * cmdinfo   brief description of cmd
        * logdir    log directory
        * logfile   log file name
        """
        self.__dict__.update( _dict)
        self.logfile = self.name + ".log"
        self.logdir = "./"

    def start(self):
        """
        Execute command line with output:
        * Process standard output
        * Result file output
        """
        print "Testing " + self.cmdinfo
        print "="*40 
        f = open(os.path.join(self.logdir, self.logfile), "w")
        return check_call(self.cmd, stdout=f, shell=True)

class PacketLossAnalyzer(Analyzer):
    """
    PacketLossAnalyzer is a sub class of Analyzer, execute Linux/Unix command to test network packet loss to a URL.
    """
    def __init__(self, _dict):
        super(PacketLossAnalyzer, self).__init__(_dict)
        self.cmd = "mtr --report --report-cycles 10 " + self.url
        self.cmdinfo = "Packet loss to " + self.name
        self.name = "PacketLossTo" + self.name
        self.logfile = self.name + ".log"

    def start(self):
        super(PacketLossAnalyzer, self).start()

class SpeedAnalyzer(Analyzer):
    """
    SpeedAnalyzer is a sub class of Analyzer, execute Linux/Unix command to test network speed to a URL.
    """
    def __init__(self, _dict):
        super(SpeedAnalyzer, self).__init__(_dict)
        __format = "\"remote: %{remote_ip}:%{remote_port}\nsize_download: %{size_download} B\nspeed_download: %{speed_download} B/s\ntime_total: %{time_total}s\ntime_namelookup: %{time_namelookup}s\ntime_pretransfer: %{time_pretransfer}s\ntime_redirect: %{time_redirect}s\ntime_start_transfer_first_byte: %{time_starttransfer}s\n\""
        self.cmd = "curl -s -m 10 -w "+ __format + " " + self.url + " -o /dev/null"
        self.cmdinfo = "Network speed to " + self.name
        self.name = "SpeedTo" + self.name
        self.logfile = self.name + ".log"
    
    def start(self):
        super(SpeedAnalyzer, self).start()

class BandwidthAnalyzer(Analyzer):
    """
    BandwidthAnalyzer is a sub class of Analyzer, execute Linux/Unix command to test network download and upload bandwidth.
    """
    def __init__(self, _dict):
        super(BandwidthAnalyzer, self).__init__(_dict)
        self.cmd = "speedtest.py --server " + self.server + " | grep -E \"Hosted|load:\""
        self.cmdinfo = self.name + " download and upload bandwidth"
        self.name = self.name + "Bandwidth"
        self.logfile = self.name + ".log"
    
    def start(self):
        super(BandwidthAnalyzer, self).start()

class Monitor:
    """
    Monitor is a collection of analyzers, which can be appended after monitor initialized.
    It is created by processor to monitor the network status, by calling analyzer.start().
    """
    def __init__(self, logdir):
        """
        * A list of analyzers
        * Log directory
        """
        self.analyzers = []
        self.logdir = logdir

    def appendAnalyzer(self, analyzer):
        """
        Append analyzers as monitor tool
        """
        analyzer.logdir = self.logdir
        self.analyzers.append(analyzer)
        return self

    def run(self):
        """
        Execute each analyzer
        """
        if not os.path.exists(self.logdir):
            os.makedirs(self.logdir)
        for zer in self.analyzers:
            zer.start()


class Processor:
    """
    Processor is the controller, in charge of creating monitor and analyzers, as
    well as starting monitor.
    """
    def __init__(self, configfile):
        """
        Read from analyzer configfile to create monitor and analyzers 
        """
        with open(configfile) as data_file:
            data = json.load(data_file)

        self.monitor = Monitor(data["logdir"])
        for zerconf in data["analyzers"]:
            if zerconf.has_key("type") == True:
                if zerconf["type"] == "SiteAnalyzer":
                    self.monitor.appendAnalyzer(SpeedAnalyzer(zerconf))
                    self.monitor.appendAnalyzer(PacketLossAnalyzer(zerconf))
                elif zerconf["type"] == "BandwidthAnalyzer":
                    self.monitor.appendAnalyzer(BandwidthAnalyzer(zerconf))
            else:
                self.monitor.appendAnalyzer(Analyzer(zerconf))

    def run(self):
        self.monitor.run()

class Report:
    pass


if __name__=='__main__':
    cwd = os.path.dirname(os.path.realpath(__file__))
    p = Processor(os.path.join(cwd,"analyzers.json"))
    p.run()
