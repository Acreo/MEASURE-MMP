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

from doubledecker.clientSafe import ClientSafe
import docker
import docker.errors
from jsonrpcserver import dispatch, Methods
import jsonrpcserver.exceptions
from jsonrpcclient.request import Request
from measure import MEASUREParser
import pyparsing
from papbackend import PAPMeasureBackend
from pprint import pprint
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
        self.logger.info("got HELLO from ", ddsrc)
        for n in self.running_mfs:
            if self.running_mfs[n]['name'] == ddsrc:
                self.logger.info("tool is running, configured?")
                pprint(self.running_mfs[n])
                if self.running_mfs[n]['state'] == 'docker_start':
                    message = str(Request(**self.running_mfs[n]['config']['dd_start']))
                    self.logger.info("sending message: %s"%(str(message))
                    self.sendmsg(ddsrc,msg=message)
                    self.running_mfs[n]['state'] = 'dd_start'

    def docker_information_request(self, ddsrc, name):
        self.logger.info("Retrieving information about container %s" % name)
        try:
            data = self.docker.inspect_container(name)
        except docker.errors.APIError as e:
            response = "%s not found"%name
            self.logger.error("docker_information_request %s"%response)
            return {"error": response}
                    
        return data


    def stopNFFG(self, ddsrc, nffg):
        self.logger.info("StopNFFG called!")
        self.logger.warning("TODO: ")
        self.logger.warning(" - stop any running monitors")
        self.vnfmapping = {}
        i = 0
        for n in self.running_mfs:
            self.docker.stop(n)
            self.docker.remove_container(n)
            i += 1
        return "Stopped & removed %d monitors"%(i)

    def startNFFG(self, ddsrc, nffg):

        # TODO:
        # - parse the MEASURE string
        # - translate ports from MEASURE string to real ports
        # - generate PAP-MEASURE backend code
        # - start and configure monitoring tools


        vnfs = {}
        ports = {}
        self.logger.info("startNFFG called from %s" % (ddsrc))
        self.MEASURE = nffg['measure']
        self.vnfmapping = {}
        for vnf in nffg['VNFs']:
            self.vnfmapping[int(vnf['id'])] = vnf

      #  for vnf_id in self.vnfmapping.keys():
       #     print("VNF with id: %s has name %s" % (vnf_id, self.vnfid_to_name(int(vnf_id))))

       # print("VNF with name %s has id %s" % ('2_ovs5', self.vnfname_to_id('2_ovs5')))

      #  for vnf_id in self.vnfmapping.keys():
      #      for port_id in range(1, 10):
      #          port_name = self.port_to_name(int(vnf_id), int(port_id))
      #          if port_name:
      #              print("VNF %s, port %d has name %s" % (vnf_id, port_id, port_name))

        parser = MEASUREParser()
        self.logger.info("Parsing MEASURE ..")
        try: 
            measure = parser.parseToDict(self.MEASURE)
        except pyparsing.ParseException as e: 
            self.logger.error("Could not parse MEASURE string!")
            return "Could not parse measure!"
                    
        pap = PAPMeasureBackend()
        self.logger.info("Generate PAP config..")
        result = pap.generate_config(measure)
        tools = self.resolve_tools(result['tools'])
        self.start_tools(tools)
        self.logger.info("######################")
        self.logger.info("results")
        pprint(result)
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


            #if config[n].startswith("$"):
                #    print("\t it's a variable: ", config[n][1:])
                #    if config[n][1:] in data:
                #        config[n] = data[config[n][1:]]

        return config

    # how to know what is provided at startup and what through DD configuration
    def start_tools(self, tools):
        import re
        self._p = re.compile('\$\(([^\)\(]+)\)')
        for tool in tools:
            # get the startup / create / dd_start / dd_stop info about the particular tool
            mfib_data = self.cmds[tool['label']]

            #print("########## starting tool ########## ")
            #print("incoming data: ")
            #pprint(tool)
            #print("mfib data: ")
            #pprint(mfib_data)

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

            #print("Known variables")
            #pprint(tool['params'])
            if 'docker_create' in mfib_data:
                mfib_data['docker_create'] = self.fill_params(tool['params'],mfib_data['docker_create'])
            if 'docker_start' in mfib_data:
                mfib_data['docker_start'] = self.fill_params(tool['params'],mfib_data['docker_start'])
            if 'dd_start' in mfib_data:
                mfib_data['dd_start'] = self.fill_params(tool['params'],mfib_data['dd_start'])
            if 'dd_start' in mfib_data:
                mfib_data['dd_stop'] = self.fill_params(tool['params'],mfib_data['dd_stop'])

            #print("config after variable assignment")
            #print("##########################################")

            binds = {}
            ports = {}
            if 'volumes' in mfib_data['docker_create']:
                vol = mfib_data['docker_create']['volumes']
                del mfib_data['docker_create']['volumes']
                mfib_data['docker_create']['volumes'] = []

                for n in vol:
                    self.logger.info("splitting ",n)
                    src,dst,mode = n.split(':')
                    mfib_data['docker_create']['volumes'].append(dst)
            #        print("Volume src: ",src, " dst: ", dst, " mode:", mode)
                    binds[src] = {'bind':dst, 'mode':mode}
            if 'ports' in mfib_data['docker_create']:
                vol = mfib_data['docker_create']['ports']
                del mfib_data['docker_create']['ports']
                mfib_data['docker_create']['ports'] = []

                for n in vol:
                    src,dst = n.split(':')
                    mfib_data['docker_create']['ports'].append(dst)
            #        print("port src: ",src, " dst: ", dst)
                    ports[dst] = src


            mfib_data['docker_create']['host_config'] = self.docker.create_host_config(
                binds=binds, port_bindings=ports)
            pprint(mfib_data)
            try:
                self.logger.info("creating container:")
                cont = self.docker.create_container(**mfib_data['docker_create'] )
                print("\tContainer: ", cont)
                self.logger.info("starting container")
                response = self.docker.start(container=cont.get('Id'))
                self.logger.info("\tResult: ", response)
                self.running_mfs[mfib_data['docker_create']['name']] =  {
                    "state": "docker_start",
                    "config" : mfib_data,
                    "name" : tool['name']
                }
            except docker.errors.APIError as e:
                self.logger.error("Error %s while trying to create %s"%(str(e),tool['label']))

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
                    pprint(self.vnfmapping)
                    return "ERROR"
            elif 'vnf' in params:
                real_vnf = self.vnfid_to_name(params['vnf'])
                if real_vnf:
                    tool['params']['vnf'] = real_vnf
                else:
                    self.logger.error("Could not resolve %s "%params['vnf'])
                    return
            tools.append(tool)
        return tools

    # TODO
    # Nice method to dynamically translate tool arguments to better arguments
    def nffgname_to_real(self, map):
        if 'interface' in map and 'vnf' in map:
            pass

    def port_to_name(self, vnf_id, portid):
        if vnf_id in self.vnfmapping:
            for p in self.vnfmapping[vnf_id]['ports']:
                if p['id'] == portid:
                    return p['name']
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
        self.logger.info("handling JSON-RPC")
        request = json.loads(msg.decode('UTF-8'))
        self.logger.info("got request %s "%str(request))
        if 'error' in request:
            logging.error("Got error response from: %s" % src)
            logging.error(str(request['error']))
            return

        if 'result' in request:
            logging.info("Got response from %s" % src)
            logging.info(str(request['result']))
            return

        # include the 'ddsrc' parameter so the
        # dispatched method knows where the message came from
      
        if 'params' not in request:
            request['params'] = {}

        if isinstance(request['params'], str):
            if len(request['params']) < 1:
                request['params'] = {}

        # print("request: ", request)
        # print("Src: ", src.decode())
        request['params']['ddsrc'] = src.decode()
        response = 1
        response = dispatch(self.methods, request)
        self.logger.info("handle_json, got response %s"%(str(response)))
        # if the http_status is 200, its request/response, otherwise notification
        if response.http_status == 200:
            logging.info("Replying to %s with %s" % (str(src), str(response)))
            self.sendmsg(src, str(response))
        # notification, correctly formatted
        elif response.http_status == 204:
            pass
        # if 400, some kind of error
        # return a message to the sender, even if it was a notification
        elif response.http_status == 400:
            self.logger.info("sending response to %s  message: "%(str(str), str(response)))
            self.sendmsg(src, str(response))
            logging.error("Recived bad JSON-RPC from %s, error %s" % (str(src), str(response)))
        else:
            logging.error(
                "Recived bad JSON-RPC from %s \nRequest: %s\nResponose: %s" % (str(src), msg.decode(), str(response)))



    # callback called automatically everytime a point to point is sent at
    # destination to the current client
    def on_data(self, src, msg):
        self.logger.info("Queueing future")
        future = self.executor.submit(self.handle_jsonrpc, src, msg, None)

    # callback called when the client receives a message on a topic h
    # subscribed to previously
    def on_pub(self, src, topic, msg):
        self.logger.info("Queueing future")
        #future = self.executor.submit(self.handle_jsonrpc,src,msg,topic)
        self.handle_jsonrpc(src=src, topic=topic, msg=msg)

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
        self.logger.warning("The client got disconnected")

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
    genclient = SecureCli(name="mmp",
                          dealerurl=args.dealer,
                          customer="public",
                          keyfile=args.keyfile)

    genclient.start()




# to be handled later
#
#
# def configure():
#     from pprint import pprint
#     monitorconfig = {}
#     monitorconfig['prepare'] = None
#     monitorconfig['evaluate'] = [{'select':'select risk from view_all where risk > 0.7;',
#                                   'action':'Publish(topic="alarm", message="Overload")'},
#                                  {'select':'select throughput from view_all where throughput > 0.1;',
#                                   'action':'Publish(topic="alarm", message="overflow ...")'}]
#     monitorconfig['MFs'] = {'m1': {'prepare':'CREATE STREAM stream_m1 (lm float, lsd float); '
#                    'CREATE CONTINOUS VIEW view_m1 as select AVG(lm) as lm, AVG(lsd) as lsd from stream_m1; ',
#                                    'insert': 'insert into stream_m1 (lm, lsd) VALUES (%s,%s)%result[]',
#                                    'evaluate': [{'select':'select risk from view_m1 where risk > 0.7;',
#                                   'action':'Publish(topic="alarm", message="Overload")'},
#                                  {'select':'select throughput from view_m1 where throughput > 0.1;',
#                                   'action':'Publish(topic="alarm", message="overflow ...")'}]
#                                    },
#                             'm2': {'prepare':'CREATE STREAM stream_m2 (lm float, lsd float); '
#                             'CREATE CONTINOUS VIEW view_m2 as select AVG(lm) as lm, AVG(lsd) as lsd from stream_m2; ',
#                                    'insert': 'insert into stream_m2 (lm, lsd) VALUES (%s,%s)%result[]',
#                                    'evaluate': [{'select':'select risk from view_m2 where risk > 0.7;',
#                                   'action':'Publish(topic="alarm", message="Overload")'},
#                                  {'select':'select throughput from view_m2 where throughput > 0.1;',
#                                   'action':'Publish(topic="alarm", message="overflow ...")'}]
#                                    }
#                             }
#     monitorconfig['postpare'] = 'CREATE CONTINOUS VIEW view_all as SELECT AVG(m1,m2,m3,m4) from view_m1, view_m2..);'
