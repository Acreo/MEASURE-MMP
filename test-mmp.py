#!/usr/bin/python3
# -*- coding: utf-8 -*-
__license__ = """
  Copyright (c) 2015 Pontus Sköldström, Bertrand Pechenot

  This file is part of libdd, the DoubleDecker hierarchical
  messaging system DoubleDecker is free software; you can
  redistribute it and/or modify it under the terms of the GNU Lesser
  General Public License (LGPL) version 2.1 as published by the Free
  Software Foundation.

  As a special exception, the Authors give you permission to link this
  library with independent modules to produce an executable,
  regardless of the license terms of these independent modules, and to
  copy and distribute the resulting executable under terms of your
  choice, provided that you also meet, for each linked independent
  module, the terms and conditions of the license of that module. An
  independent module is a module which is not derived from or based on
  this library.  If you modify this library, you must extend this
  exception to your version of the library.  DoubleDecker is
  distributed in the hope that it will be useful, but WITHOUT ANY
  WARRANTY; without even the implied warranty of MERCHANTABILITY or
  FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
  License for more details.  You should have received a copy of the
  GNU Lesser General Public License along with this program.  If not,
  see <http://www.gnu.org/licenses/>.
"""

import argparse
import logging
import time
import random
import json
from pprint import pprint

from doubledecker.clientSafe import ClientSafe
from jsonrpcclient.request import Notification, Request


class SecureCli(ClientSafe):

    def __init__(self, name, dealerurl, keyfile):
        super().__init__(name=name, dealerurl=dealerurl, keyfile=keyfile)

    # callback called automatically everytime a point to point is sent at
    # destination to the current client
    def on_data(self, src, msg):
        print("DATA from %s: %s" % (str(src), str(msg)))
        jsonobj = json.loads(msg.decode())
        pprint(jsonobj)

    # callback called upon registration of the client with its broker
    def on_reg(self):
        print("The client is now connected")

        # this function notifies the broker that the client is interested

        MeasureString = """ measurements {
          m1 = throughput.rx(interface = veth3un);
          m2 = throughput.tx(interface = veth4un);
        }
        zones {
          z1 = (AVG(val = m1, max_age = \"5 minute\") < 0.5);
          z2 = (AVG(val = m2, max_age = \"5 minute\") > 0.5);
        }
        actions {
          z1->z2 = Publish(topic = \"alarms\", message = \"z1 to z2\"); Notify(target = \"alarms\", message = \"z1 to z2\");
          z2->z1 = Publish(topic = \"alarms\", message = \"z2 to z\");
          ->z1 = Publish(topic = \"alarms\", message = \"entered z1\");
          z1-> = Publish(topic = \"alarms\", message = \"left z1\");
          z1 = Publish(topic = \"alarms\", message = \"in z1\");
        z2 = Publish(topic = \"alarms\", message = \"in z2\");
        }"""

        scale_out_nffg = {"measure":MeasureString,"VNFs":[{"id":"00000001","name":"2_ctrl","ports":[{"id":1,"name":"2_ctrl_1.lxc"}]},{"id":"00000003","name":"2_ovs2","ports":[{"id":1,"name":"2_ovs2_1.lxc"},{"id":2,"name":"2_ovs2_2.lxc"},{"id":3,"name":"2_ovs2_3.lxc"},{"id":4,"name":"2_ovs2_4.lxc"},{"id":5,"name":"2_ovs2_5.lxc"}]},{"id":"00000004","name":"nostalgic_engelbart","ports":[{"id":1,"name":"2_ovs3_1.lxc"},{"id":2,"name":"2_ovs3_2.lxc"},{"id":3,"name":"2_ovs3_3.lxc"},{"id":4,"name":"2_ovs3_4.lxc"},{"id":5,"name":"2_ovs3_5.lxc"}]},{"id":"00000005","name":"2_ovs4","ports":[{"id":1,"name":"2_ovs4_1.lxc"},{"id":2,"name":"2_ovs4_2.lxc"},{"id":3,"name":"2_ovs4_3.lxc"},{"id":4,"name":"2_ovs4_4.lxc"},{"id":5,"name":"2_ovs4_5.lxc"}]},{"id":"00000006","name":"2_ovs5","ports":[{"id":1,"name":"2_ovs5_1.lxc"},{"id":2,"name":"2_ovs5_2.lxc"},{"id":3,"name":"2_ovs5_3.lxc"},{"id":4,"name":"2_ovs5_4.lxc"},{"id":5,"name":"2_ovs5_5.lxc"}]},{"id":"00000002","name":"2_ovs1","ports":[{"id":1,"name":"2_ovs1_1.lxc"},{"id":2,"name":"2_ovs1_2.lxc"},{"id":3,"name":"2_ovs1_3.lxc"},{"id":4,"name":"2_ovs1_4.lxc"},{"id":5,"name":"2_ovs1_5.lxc"}]}]}
        stop_nffg  = {}
        scale_in_nffg = { "measure":MeasureString,"VNFs":[{"id":"00000001","name":"2_ctrl","ports":[{"id":1,"name":"2_ctrl_1.lxc"}]},{"id":"00000002","name":"2_ovs1","ports":[{"id":1,"name":"2_ovs1_1.lxc"},{"id":2,"name":"2_ovs1_2.lxc"},{"id":3,"name":"2_ovs1_3.lxc"},{"id":4,"name":"2_ovs1_4.lxc"},{"id":5,"name":"2_ovs1_5.lxc"}]}]}
        new_nffg = {
            'sap': [
                {'interface': 'veth3un', 'name': 'virtual-sap4'},
                {'interface': 'veth0un', 'name': 'virtual-sap1'},
                {'interface': 'veth2un', 'name': 'virtual-sap3'},
                {'interface': 'veth1un', 'name': 'virtual-sap2'}],
            'VNFs': [
                {'id': '1', 'ports': [{'id': 1, 'name': '2_ctrl_1.lxc'}], 'name': '2_ctrl'},
                {'id': '2', 'ports': [{'id': 1, 'name': '2_ovs1_1.lxc'},
                                      {'id': 2, 'name': '2_ovs1_2.lxc'},
                                      {'id': 3, 'name': '2_ovs1_3.lxc'},
                                      {'id': 4, 'name': '2_ovs1_4.lxc'},
                                      {'id': 5, 'name': '2_ovs1_5.lxc'}], 'name': '2_ovs1'}],
            'measure': 'measurements {m1 = throughput.rx(interface = veth3un);m2 = throughput.tx(interface = veth4un);}zones {z1 = (AVG(val = m1, max_age = "5 minute") < 0.5);z2 = (AVG(val = m2, max_age = "5 minute") > 0.5);}actions {z1->z2 = Publish(topic = "alarms", message = "z1 to z2"); Notify(target = "alarms", message = "z1 to z2");z2->z1 = Publish(topic = "alarms", message = "z2 to z");->z1 = Publish(topic = "alarms", message = "entered z1");z1-> = Publish(topic = "alarms", message = "left z1");z1 = Publish(topic = "alarms", message = "in z1");z2 = Publish(topic = "alarms", message = "in z2");}'
        }



        print("Testing stopNFFG command ..")
        self.publish(topic="unify:mmp", message=str(Request("stopNFFG", nffg=stop_nffg)))
        
        print("Testing startNFFG command, scale-out")
        self.publish(topic="unify:mmp", message=str(Request("startNFFG", nffg=new_nffg)))
#        print("Testing stopNFFG command ..")
#        self.publish(topic="unify:mmp", message=str(Request("stopNFFG", nffg=stop_nffg)))
        #pprint("Adding perioding measurement result publication..")
        #self._IOLoop.add_timeout(time.time() + 1, self.send_measurement, "apeman")


    def send_measurement(self, args):
        result = {
            "version": 0,
            "label": "ratemon",
            "parameters": {"interface": "veth0"},
            "results": {
                "rate.rx": random.uniform(0, 1),
                "rate.tx": random.uniform(0, 1),
                "overload.risk.rx": random.uniform(0, 1),
                "overload.risk.tx": random.uniform(0, 1)
            }
        }
        self.publish(topic="measurement", message=str(Notification("measurement", result=result)))
        self._IOLoop.add_timeout(time.time() + 1, self.send_measurement, "apeman")


        # callback called when the client detects that the heartbeating with
        # its broker has failed, it can happen if the broker is terminated/crash
        # or if the link is broken


    def on_discon(self):
        print("The client got disconnected")

        # this function shuts down the client in a clean way
        # in this example it exists as soon as the client is disconnected
        # fron its broker
        self.shutdown()

        # callback called when the client receives an error message


    def on_error(self, code, msg):
        print("ERROR n#%d : %s" % (code, msg))

        # callback called when the client receives a message on a topic he
        # subscribed to previously


    def on_pub(self, src, topic, msg):
        print("PUB %s from %s: %s" % (str(topic), str(src), str(msg)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Generic message client")
    parser.add_argument('name', help="Identity of this client", default="test-mmp")
    parser.add_argument('customer', help="Name of the customer to get the keys (i.e. 'a' for the customer-a.json file)", default = "public")
    parser.add_argument(
        '-d',
        "--dealer",
        help='URL to connect DEALER socket to, "tcp://1.2.3.4:5555"',
        nargs='?',
        default='tcp://127.0.0.1:5555')
    parser.add_argument(
        '-f',
        "--logfile",
        help='File to write logs to',
        nargs='?',
        default=None)
    parser.add_argument(
        '-l',
        "--loglevel",
        help='Set loglevel (DEBUG, INFO, WARNING, ERROR, CRITICAL)',
        nargs='?',
        default="INFO")
    parser.add_argument(
        '-k',
        "--keyfile",
        help='File containing the encryption/authentication keys)',
        nargs='?',
        default='/etc/doubledecker/public-keys.json')

    args = parser.parse_args()

    numeric_level = getattr(logging, args.loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % args.loglevel)

    logging.basicConfig(format='%(levelname)s:%(message)s', filename=args.logfile, level=numeric_level)

    logging.info("Safe client")
    genclient = SecureCli(name=args.name,
                          dealerurl=args.dealer,
                          keyfile=args.keyfile)

    logging.info("Starting DoubleDecker example client")
    logging.info("See ddclient.py for how to send/recive and publish/subscribe")
    genclient.start()
