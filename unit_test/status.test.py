import unittest
from src.status import *

from subprocess import check_call

class TestAnalyzer(unittest.TestCase):

    def setUp(self):
        config = {
                "name": "dns",
                "cmd": "nmcli device show wlan0",
                "cmdinfo": "Current DNS and Gateway"}
        self.analyzer = Analyzer(config)

    def tearDown(self):
        check_call("rm dns.log", shell=True)

    def test_start(self):
        self.analyzer.start()
        self.assertEqual('foo'.upper(), 'FOO')

class TestMonitor(unittest.TestCase):

    def setUp(self):
        self.cwd = os.path.dirname(os.path.realpath(__file__))

        config1 = {
          "name": "dns",
          "cmd": "nmcli device show wlan0",
          "cmdinfo":"Current DNS and Gateway"
        }
        config2 = {
          "name": "dhcp",
          "cmd": "grep dhcp-server-identifier /var/lib/**/*.leases",
          "cmdinfo":"Current dhcp server"
        }
        config3 = {
          "name": "ToBing",
          "cmd": "mtr --report --report-cycles 20 www.bing.com",
          "cmdinfo":"Packet loss to Bing"
        }

        self.ana1 = Analyzer(config1)
        self.ana2 = Analyzer(config2)
        self.ana3 = Analyzer(config3)

        self.monitor = Monitor(self.cwd)
        self.monitor.appendAnalyzer(self.ana1).appendAnalyzer(self.ana2).appendAnalyzer(self.ana3)

    def tearDown(self):
        check_call("rm " + os.path.join(self.cwd, "*.log"), shell=True)

    def test_run(self):
        self.monitor.run()
        self.assertEqual('foo'.upper(), 'FOO')


class TestSample(unittest.TestCase):

    def test_upper(self):
        self.assertEqual('foo'.upper(), 'FOO')

    def test_isupper(self):
        self.assertTrue('FOO'.isupper())
        self.assertFalse('Foo'.isupper())

    def test_split(self):
        s = 'hello world'
        self.assertEqual(s.split(), ['hello', 'world'])
        # check that s.split fails when the separator is not a string
        with self.assertRaises(TypeError):
            s.split(2)


if __name__ == '__main__':
    unittest.main()
