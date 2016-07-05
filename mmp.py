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
import time
import json
import logging
import signal
import sys

from doubledecker.clientSafe import ClientSafe
import docker
import docker.errors
from jsonrpcserver import dispatch, Methods
import jsonrpcserver.exceptions
from jsonrpcclient.request import Request, Notification
from measure import MEASUREParser
import pyparsing
from papbackend import PAPMeasureBackend
from pprint import pformat
from  concurrent.futures import ThreadPoolExecutor
restart = False
Request.notification_errors = True


class SecureCli(ClientSafe):
    def __init__(self, name, dealerurl, customer, keyfile):
        super().__init__(name, dealerurl, keyfile)
        # pyjsonrpc.JsonRpc.__init__()
        self.docker = docker.Client(version='auto',base_url='unix://var/run/docker.sock')
        self.MEASURE = None

        self.cmds = dict()
        with open('mfib.json') as json_file:
            mfib = json.load(json_file)
            self.cmds = mfib['docker']

        # Log the JSON-RPC messages, can be skipped
        logging.getLogger('jsonrpcserver').setLevel(logging.INFO)

        self.logger = logging.getLogger("MMP")

        # Initialize the RPC-Server dispatcher
        self.methods = Methods()
        self.methods.add_method(self.startNFFG)
        self.methods.add_method(self.stopNFFG)
        self.methods.add_method(self.docker_information_request)
        self.methods.add_method(self.ping)
        self.methods.add_method(self.hello)

        self.running_mfs = {}
        self.executor = ThreadPoolExecutor(max_workers=1)
        # TODO: Add aggregator to this
        # Start the default containers (Pipeline, OpenTSDB, OpenTSDB-DD, and Aggregator)
        # self.initialize_containers()

    # RPC server
    def hello(self,ddsrc, **kwargs):
        self.logger.info("HELLO from %s"%str(ddsrc))
        for n in self.running_mfs:
            if self.running_mfs[n]['name'] == ddsrc:
                self.logger.info("Found monitoring function")
                self.logger.debug(pformat(self.running_mfs[n]))
                if self.running_mfs[n]['state'] == 'docker_start':
                    for runargs in self.running_mfs[n]['config']['dd_start']:
                        message = str(Request(**runargs))
                        self.logger.info("sending message: %s"%(str(message)))
                        self.sendmsg(ddsrc,msg=message)
                    self.running_mfs[n]['state'] = 'dd_start'
        if ddsrc == "agg":
            self.logger.info("Aggregator said hello, setting cutoff and alarm level")
            self.sendmsg(ddsrc, msg=str(Notification("set_alarm_level", alarm_level=25.0, cutoff_level=0.9)))

    def docker_information_request(self, ddsrc, name):
        self.logger.info("Retrieving information about container %s" % name)
        try:
            data = self.docker.inspect_container(name)
        except docker.errors.APIError as e:
            response = "%s not found"%name
            self.logger.error("docker_information_request %s"%response)
            return {"error": response}
                    
        return data

    def kill_container(self, container):
        self.logger.info("Trying to kill container: " + container)
        try:
            self.docker.kill(container)
        except docker.errors.NotFound as e:
            self.logger.warning("NotFound when killing container: " + str(e))
        except docker.errors.APIError as e :
            self.logger.warning("APIError when killing container: " + str(e))

    def remove_container(self, container):
        self.logger.info("Trying to remove container: " + container)
        try:
            self.docker.remove_container(container=container, force=True)
        except docker.errors.NotFound as e:
            self.logger.warning("NotFound when removing container: " + str(e))
        except docker.errors.APIError as e :
            self.logger.warning("APIError when removing container: " + str(e))

    def sighandler(self,signum,frame):
        self.logger.warning("Caught SIGTERM")
        self.logger.info("Stopping containers")
        self.stopNFFG(None,None)
        self.logger.info("Unregistring from broker")
        self.shutdown()
        self.logger.info("Exiting..")
        sys.exit(1)

    def stopNFFG(self, ddsrc, nffg):
        self.logger.info("stopNFFG called by %s"%ddsrc)
        self.vnfmapping = {}
        i = 0
        self.logger.info("Will try to remove %d monitors"%len(self.running_mfs))
        self.logger.debug(pformat(self.running_mfs))
        for n in self.running_mfs:
            if 'singleton' != self.running_mfs[n]['state']:
                for stopargs in self.running_mfs[n]['config']['dd_stop']:
                    message = str(Request(**stopargs))
                    self.logger.info("sending message: %s"%(str(message)))
                    self.sendmsg(n,msg=message)

        for n in self.running_mfs:
            if 'singleton' != self.running_mfs[n]['state']:
                self.kill_container(n)
        for n in self.running_mfs:
            if 'singleton' != self.running_mfs[n]['state']:
                self.remove_container(n)
                i += 1
        self.running_mfs = {}
        if i > 0:
            self.publish(topic="monitoring_status", message=str(Notification("monitoring", status="off")))

        return "Stopped & removed %d monitors"%(i)

    def startNFFG(self, ddsrc, nffg):
        self.logger.info("startNFFG called from %s" % (ddsrc))
        self.MEASURE = nffg['measure']
        if len(self.MEASURE) < 2:
            self.logger.info("MEASURE string empty, removing running monitors!") 
            retval = self.stopNFFG(ddsrc,nffg)
            return retval
           
        self.vnfmapping = {}
        for vnf in nffg['VNFs']:
            self.vnfmapping[int(vnf['id'])] = vnf

        self.sapmapping = {}
        if 'sap' in nffg:
            for n in nffg['sap']:
                self.sapmapping[n['name']] = n['interface']

        parser = MEASUREParser()
        #parser.debug_all()

        self.logger.info("Parsing MEASURE ..")
        try: 
            measure = parser.parseToDict(self.MEASURE)
        except pyparsing.ParseException as e: 
            self.logger.error("Could not parse MEASURE string!")
            self.logger.error(str(e))
            return "Could not parse measure!"
                    
        pap = PAPMeasureBackend()
        self.logger.info("Generate PAP config..")
        result = pap.generate_config(measure)
        tools = self.resolve_tools(result['tools'])
        self.logger.info("Resolved tools")
        self.logger.debug(pformat(tools))
        self.start_tools(tools)
        self.logger.debug("results")
        self.logger.debug(pformat(result))
        self.publish(topic="monitoring_status", message=str(Notification("monitoring", status="on")))
        
        return "OK"

    def fill_params(self,data,config, indent=0):
        if isinstance(config,dict):
            for n in config:
                config[n] = self.fill_params(data,config[n],indent+1)
        if isinstance(config,list):
            for i in range(0,len(config)):
                config[i] = self.fill_params(data,config[i],indent+1)
        if isinstance(config,str):
            match = self._p.findall(config)
            for m in match:
                if m in data:
                    config = config.replace("$(%s)"%m,data[m])
        return config

    # how to know what is provided at startup and what through DD configuration
    def start_tools(self, tools):
        import re
        self._p = re.compile('\$\(([^\)\(]+)\)')
        toolist = []
        for tool in tools:
            # get the startup / create / dd_start / dd_stop info about the particular tool
            self.cmds = dict()
            with open('mfib.json') as json_file:
                mfib = json.load(json_file)
                self.cmds = mfib['docker']
            mfib_data = self.cmds[tool['label']]


            if "vnf" in tool['params']:
                # resolve container_id
                try:
                    container_id = self.docker.inspect_container(tool['params']['vnf'])['Id']
                    tool['params']['container_id'] = container_id
                except docker.errors.APIError as e:
                    self.logger.error("Could not resolv container id for %s"%tool['params']['vnf'])
                    return "ERROR"
            tool['params']['name'] = tool['name']
            tool['params']['label'] = tool['label']
            mfib_data['name'] = tool['name']
            if 'docker_create' in mfib_data:
                mfib_data['docker_create'] = self.fill_params(tool['params'],mfib_data['docker_create'])
            if 'docker_start' in mfib_data:
                mfib_data['docker_start'] = self.fill_params(tool['params'],mfib_data['docker_start'])
            if 'dd_start' in mfib_data:
                mfib_data['dd_start'] = [self.fill_params(tool['params'],mfib_data['dd_start'])]
            if 'dd_stop' in mfib_data:
                mfib_data['dd_stop'] = [self.fill_params(tool['params'],mfib_data['dd_stop'])]

            binds = {}
            ports = {}
            link = []
            if 'volumes' in mfib_data['docker_create']:
                vol = mfib_data['docker_create']['volumes']
                self.logger.debug("start_tools1, volumes: %s "%str(vol))
                del mfib_data['docker_create']['volumes']
                mfib_data['docker_create']['volumes'] = []
                self.logger.debug("start_tools2, volumes: %s"%str(vol))
                for n in vol:
                    self.logger.debug("splitting %s"%str(n))
                    src,dst,mode = n.split(':')
                    mfib_data['docker_create']['volumes'].append(dst)
                    binds[src] = {'bind':dst, 'mode':mode}
            if 'ports' in mfib_data['docker_create']:
                vol = mfib_data['docker_create']['ports']
                self.logger.debug("start_tools3, ports: %s"%str(vol))
                del mfib_data['docker_create']['ports']
                mfib_data['docker_create']['ports'] = []
                self.logger.debug("start_tools4, ports: %s"%str(vol))
                for n in vol:
                    src,dst = n.split(':')
                    mfib_data['docker_create']['ports'].append(dst)
                    ports[dst] = src
            if 'links' in mfib_data['docker_create']:
                links = mfib_data['docker_create']['links']
                self.logger.debug("start_tools5, links: %s"%str(links))
                del mfib_data['docker_create']['links']
                for n in links:
                    self.logger.debug("splitting link - %s"%str(n))
                    src,dst = n.split(':')
                    link.append((src,dst))

            mfib_data['docker_create']['host_config'] = self.docker.create_host_config(
                binds=binds, port_bindings=ports, links=link)
            toolist.append(mfib_data)


        for tool in toolist:
            if 'singleton' in tool and tool['singleton']:
                self.logger.debug("this tool is a singleton")
                if 'docker_create' in tool and 'image' in tool['docker_create']:
                    mfimage = tool['docker_create']['image']
                    for tool2 in toolist:
                        if tool == tool2:
                            continue
                        if 'singleton' in tool2 and tool2['singleton'] and tool2['docker_create']['image'] == mfimage:
                            del tool2['docker_create']
                            del tool2['docker_start']
                            tool2['singleton_name'] = tool['docker_create']['name']
                            tool['dd_start'] += tool2['dd_start']
                            tool['dd_stop'] += tool2['dd_stop']

        self.logger.debug("tools after checking singletons")
        self.logger.debug(pformat(toolist))

        for mfib_data in toolist:
            if 'docker_create' in mfib_data:
                try:
                    self.logger.info("creating container: %s"%mfib_data['docker_create']['name'])
                    cont = self.docker.create_container(**mfib_data['docker_create'] )
                    self.logger.debug("\tContainer: %s"%str(cont))
                    self.logger.info("starting container")

                    response = self.docker.start(container=cont.get('Id'))
                    self.logger.debug("\tResult: %s"%str(response))
                    self.running_mfs[mfib_data['docker_create']['name']] =  {
                        "state": "docker_start",
                        "config" : mfib_data,
                        "name" : mfib_data['name']
                    }
                except docker.errors.APIError as e:
                    self.logger.error("Error %s while trying to create %s"%(str(e),mfib_data['docker_create']['name']))
            else:
                self.running_mfs[mfib_data['name']] = {
                    "state":"singleton",
                    "config": mfib_data,
                    "name" : mfib_data['singleton_name']
                }
        self.logger.debug("Running MFs")
        self.logger.debug(pformat(self.running_mfs))
    def resolve_tools(self, unres_tools):
        tools = list()
        for tool in unres_tools:
            label = tool['label']
            name = tool['name']
            params = tool['params']
            if 'interface' in params and 'vnf' in params:
                real_interface = self.port_to_name(params['vnf'], params['interface'])
                real_vnf = self.vnfid_to_name(params['vnf'])
                if real_interface and real_vnf:
                    tool['params']['interface'] = real_interface
                    tool['params']['vnf'] = real_vnf
                else:
                    self.logger.error("Could not resolve vnf: %s interface: %s"%(params['vnf'], params['interface']))
                    self.logger.error(pformat(self.vnfmapping))
                    return "ERROR"
            elif 'vnf' in params:
                real_vnf = self.vnfid_to_name(params['vnf'])
                if real_vnf:
                    tool['params']['vnf'] = real_vnf
                else:
                    self.logger.error("Could not resolve %s "%params['vnf'])
                    return "ERROR"
            elif 'interface' in params:
                real_interface = self.sap_to_name(params['interface'])
                if real_interface:
                    tool['params']['interface'] = real_interface
                else:
                    self.logger.error("Could not resolve %s "%params['interface'])
                    return "ERROR"
            tools.append(tool)
        return tools

    def port_to_name(self, vnf_id, portid):
        if vnf_id in self.vnfmapping:
            for p in self.vnfmapping[vnf_id]['ports']:
                if p['id'] == portid:
                    return p['name']
        return None
    # SAP to name, eg. virtual-sap3 -> veth3un
    def sap_to_name(self, sapid):
        if sapid in self.sapmapping:
            return self.sapmapping[sapid]
        return None

    # name to sap, eg. veth3un -> virtual-sap3
    def name_to_sap(self, portname):
        for n in self.sapmapping:
            if portname == self.sapmapping[n]:
                return n
        return None

    # Mapping from NF-FG IDs to real names
    def vnfid_to_name(self, vnf_id):
        if vnf_id in self.vnfmapping:
            return self.vnfmapping[vnf_id]['name']
        return None

    def vnfname_to_id(self, name):
        for n in self.vnfmapping:
            if self.vnfmapping[n]['name'] == name:
                return self.vnfmapping[n]['id']
        return None

    def name_to_port(self, port):
        for n in self.vnfmapping:
            vnfid = n['id']
            for p in n['ports']:
                if p['name'] == port:
                    return (vnfid, p['id'])
        return None

    def ping(self, ddsrc):
        return "OK"

    # Docker stuff
    def initialize_containers(self):
        containers = self.docker.containers(all=True)
        idlist = list()
        for c in containers:
            if any(ext in c['Names'][0] for ext in self.cmds.keys()):
                idlist.append(c['Names'][0])

        images = list()
        for img in self.docker.images():
            images.append(img['RepoTags'][0])


        # Pull opentsdb if not available
        # if self.cmds['opentsdb']['image'] not in images:
        #    for line in self.docker.pull(repository=self.cmds['opentsdb']['image'], stream=True):
        #        print("\r",json.dumps(json.loads(line.decode()), indent=4))
        # Pull piplinedb if not available
        # if self.cmds['pipelinedb']['image'] not in images:
        #    for line in self.docker.pull(repository=self.cmds['pipelinedb']['image'], stream=True):
        #        print("\r",json.dumps(json.loads(line.decode()), indent=4))


        # stop pipeline
        if restart:
            try:
                self.docker.stop(self.cmds['pipelinedb']['name'])
            except docker.errors.APIError as e:
                self.logger.error("Error %s while trying to stop PipelineDB"%str(e))

                # stop OpenTSDB
            try:
                self.docker.stop(self.cmds['opentsdb']['name'])
            except docker.errors.APIError as e:
                self.logger.error("Error %s while trying to stop OpenTSDB"%str(e) )

                # remove pipeline
            try:
                self.docker.remove_container(self.cmds['pipelinedb']['name'])
            except docker.errors.APIError as e:
                self.logger.error("Error %s while trying to remove PipelineDB"%(str(e)))

            # remove OpenTSDB
            try:
                self.docker.remove_container(self.cmds['opentsdb']['name'])
            except docker.errors.APIError as e:
                self.logger.error("Error %s while trying to remove OpenTSDB"%(str(e)))

        pipeline_ip = None
        # start pipeline
        if 'pipelinedb' not in idlist:
            try:
                self.logger.info("Creating PipelineDB")
                cont = self.docker.create_container(**self.cmds['pipelinedb'])
                response = self.docker.start(container=cont.get('Id'))
                self.logger.info("Result: %s"%(str(response)))

            except docker.errors.APIError as e:
                self.logger.info("Error %s while trying to create PipelineDB"%(str(e)))
        try:
            pipeline_ip = self.docker.inspect_container('pipelinedb')['NetworkSettings']['IPAddress']
        except docker.errors.APIError as e:
            self.logger.info("Error %s while trying to create PipelineDB"%str(e))

        opentsdb_ip = None
        # start OpenTSDB
        # try:
        #    print("Creating OpenTSDB")
        #    cont = self.docker.create_container(**self.cmds['opentsdb'])
        #    response = self.docker.start(container=cont.get('Id'))
        #    print("Result: ",response )
        #    opentsdb_ip = self.docker.inspect_container(cont['Id'])['NetworkSettings']['IPAddress']

        #        except docker.errors.APIError as e:
        #            print("Error ", e , " while trying to create OpenTSDB")

        # temp!
        opentsdb_up = True

        wait_time = 100
        while wait_time > 0:
            pipeline_up = self.check_server(pipeline_ip, 5432)
            #     opentsdb_up = self.check_server(opentsdb_ip,4242)
            if pipeline_up and opentsdb_up:
                self.logger.info("PipelineDB and OpenTSDB running!")
                return
            else:
                status_str = "Waiting %d for" % wait_time
                if not pipeline_up:
                    status_str += " PipelineDB "
                if not opentsdb_up:
                    status_str += " OpenTSDB"
                self.logger.info(status_str)
                time.sleep(1)
            wait_time -= 1

    def check_server(self, address, port):
        import socket
        # Create a TCP socket
        s = socket.socket()
        self.logger.info("Attempting to connect to %s on port %s" % (address, port))
        try:
            s.connect((address, port))
            self.logger.info("Connected to %s on port %s" % (address, port))
            s.close()
            return True
        except socket.error as e:
            self.logger.info("Connection to %s on port %s failed: %s" % (address, port, e))
            return False

    def handle_jsonrpc(self, src, msg, topic=None):
        self.logger.debug("handling JSON-RPC")
        request = json.loads(msg.decode('UTF-8'))
        if 'error' in request:
            self.logger.error("Got error response from: %s" % src)
            self.logger.error(str(request['error']))
            return

        if 'result' in request:
            self.logger.info("Got response from %s : %s" %(src,str(request['result'])))
            return

        # include the 'ddsrc' parameter so the
        # dispatched method knows where the message came from
      
        if 'params' not in request:
            request['params'] = {}

        if isinstance(request['params'], str):
            if len(request['params']) < 1:
                request['params'] = {}

        request['params']['ddsrc'] = src.decode()
        response = dispatch(self.methods, request)
        self.logger.debug("dispatch() returned '%s'"%(str(response)))
        # if the http_status is 200, its request/response, otherwise notification
        if response.http_status == 200:
            self.logger.info("Replying to '%s' with '%s'" % (str(src), str(response)))
            self.sendmsg(src, str(response))
        # notification, correctly formatted
        elif response.http_status == 204:
            pass
        # if 400, some kind of error
        # return a message to the sender, even if it was a notification
        elif response.http_status == 400:
            self.logger.info("sending response to '%s' message: '%s'"%(str(str), str(response)))
            self.sendmsg(src, str(response))
            self.logger.error("Recived bad JSON-RPC from '%s', error '%s'" % (str(src), str(response)))
        else:
            self.logger.error(
                "Recived bad JSON-RPC from '%s'\nRequest: '%s'\nResponose: '%s'" % (str(src), msg.decode(), str(response)))



    # callback called automatically everytime a point to point is sent at
    # destination to the current client
    def on_data(self, src, msg):
        future = self.executor.submit(self.handle_jsonrpc, src, msg, None)

    # callback called when the client receives a message on a topic h
    # subscribed to previously
    def on_pub(self, src, topic, msg):
        future = self.executor.submit(self.handle_jsonrpc,src,msg,topic)

    # callback called upon registration of the client with its broker
    def on_reg(self):
        self.logger.info("The client is now connected")
        topic = 'unify:mmp'
        scope = 'all'
        # this function notifies the broker that the client is interested
        # in the topic 'monitoring' and the scope should be 'all'
        self.logger.info("Subscribing to topic '%s', scope '%s'" % (topic, scope))
        self.subscribe(topic, scope)
        # self.logger.info("Subscribing to topic 'measurement', scope 'node'")
        # self.subscribe('measurement','node')

    # callback called when the client detects that the heartbeating with
    # its broker has failed, it can happen if the broker is terminated/crash
    # or if the link is broken
    def on_discon(self):
        self.logger.error("The client got disconnected")

        # this function shuts down the client in a clean way
        # in this example it exists as soon as the client is disconnected
        # fron its broker

    # callback called when the client receives an error message
    def on_error(self, code, msg):
        self.logger.info("ERROR n#%d : %s" % (code, msg))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Generic message client")
    parser.add_argument(
        '-d',
        "--dealer",
        help='URL to connect DEALER socket to, "tcp://1.2.3.4:5555"',
        nargs='?')
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
        default='/keys/public-keys.json')

    args = parser.parse_args()

    numeric_level = getattr(logging, args.loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % args.loglevel)

    logging.basicConfig(format='%(levelname)s:%(message)s', filename=args.logfile, level=numeric_level)

    logo = r"""
   _____                .__  __               .__
  /     \   ____   ____ |__|/  |_  ___________|__| ____    ____
 /  \ /  \ /  _ \ /    \|  \   __\/  _ \_  __ \  |/    \  / ___\
/    Y    (  <_> )   |  \  ||  | (  <_> )  | \/  |   |  \/ /_/  >
\____|__  /\____/|___|  /__||__|  \____/|__|  |__|___|  /\___  /
        \/            \/                              \//_____/
   _____                                                             __
  /     \ _____    ____ _____     ____   ____   _____   ____   _____/  |_
 /  \ /  \\__  \  /    \\__  \   / ___\_/ __ \ /     \_/ __ \ /    \   __\
/    Y    \/ __ \|   |  \/ __ \_/ /_/  >  ___/|  Y Y  \  ___/|   |  \  |
\____|__  (____  /___|  (____  /\___  / \___  >__|_|  /\___  >___|  /__|
        \/     \/     \/     \//_____/      \/      \/     \/     \/
__________.__               .__
\______   \  |  __ __  ____ |__| ____
 |     ___/  | |  |  \/ ___\|  |/    \
 |    |   |  |_|  |  / /_/  >  |   |  \
 |____|   |____/____/\___  /|__|___|  /
                    /_____/         \/   """
                  
    logging.info(logo)
    name = "mmp"
    customer = "public"
    dealer = args.dealer
    import os
    if not dealer and 'DEALER_PORT' in os.environ:
        dealer = os.environ['DEALER_PORT']  
    if not dealer and 'BROKER_PORT' in os.environ:
        dealer = os.environ['BROKER_PORT']
        
    logging.info("starting securecli with key: %s dealer: %s name %s customer: %s"%(args.keyfile,dealer,name,customer))
    genclient = SecureCli(name=name,
                          dealerurl=dealer,
                          customer=customer,
                          keyfile=args.keyfile)
    signal.signal(signal.SIGTERM,genclient.sighandler)
    genclient.start()
