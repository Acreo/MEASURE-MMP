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

from doubledecker.clientSafe import ClientSafe
from jsonrpcclient.request import Request, Notification

import time
import random
import json
from pprint import pprint
import sys










class SecureCli(ClientSafe):
    def __init__(self, name, dealerurl, customer, keyfile):
        super().__init__(name, dealerurl, customer, keyfile)

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

        data = dict()
        data['MEASURE'] = "measurestring"
        data['VNFs'] = [{"id": 1,
                         "name": "docker-983249873294",
                         "ports": [
                             {"id": 1, "name": "veth0"},
                             {"id": 2, "name": "veth1"}
                         ]
                         },
                        {"id": 2,
                         "name": "docker-1545145",
                         "ports": [
                             {"id": 1, "name": "veth33"},
                             {"id": 2, "name": "veth121"}
                         ]
                         },
                        ]
        print("Testing updateNFFG command...")
        self.publish(topic="unify:mmp", message=str(Notification("updateNFFG", nffg=data)))
        print("Testing testNFFG command ..")
        self.publish(topic="unify:mmp", message=str(Notification("testNFFG")))
        pprint("Adding perioding measurement result publication..")
        self._IOLoop.add_timeout(time.time()+1,self.send_measurement,"apeman")




    def send_measurement(self, args):
        result = {
         "version":0,
         "label":"ratemon",
         "parameters":{"interface":"veth0"},
         "results": {
           "rate.rx":random.uniform(0,1),
           "rate.tx":random.uniform(0,1),
           "overload.risk.rx":random.uniform(0,1),
           "overload.risk.tx":random.uniform(0,1)
         }
        }
        self.publish(topic="measurement", message=str(Notification("measurement", result=result)))
        self._IOLoop.add_timeout(time.time()+1,self.send_measurement,"apeman")


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
    parser.add_argument('name', help="Identity of this client")
    parser.add_argument('customer', help="Name of the customer to get the keys (i.e. 'a' for the customer-a.json file)")
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
        default='')

    args = parser.parse_args()

    numeric_level = getattr(logging, args.loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % args.loglevel)

    logging.basicConfig(format='%(levelname)s:%(message)s', filename=args.logfile, level=numeric_level)

    logging.info("Safe client")
    genclient = SecureCli(name=args.name,
                          dealerurl=args.dealer,
                          customer=args.customer,
                          keyfile=args.keyfile)

    logging.info("Starting DoubleDecker example client")
    logging.info("See ddclient.py for how to send/recive and publish/subscribe")
    genclient.start()
