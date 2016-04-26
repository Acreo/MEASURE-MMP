__author__ = 'eponsko'
import json
from pprint import pprint
from jsonrpcclient.request import Request
import logging
class DictDiffer(object):
    """
    Calculate the difference between two dictionaries as:
    (1) items added
    (2) items removed
    (3) keys same in both but changed values
    (4) keys same in both and unchanged values
    """
    def __init__(self, current_dict, past_dict):
        self.current_dict, self.past_dict = current_dict, past_dict
        self.set_current, self.set_past = set(current_dict.keys()), set(past_dict.keys())
        self.intersect = self.set_current.intersection(self.set_past)
    def added(self):
        return self.set_current - self.intersect
    def removed(self):
        return self.set_past - self.intersect
    def changed(self):
        return set(o for o in self.intersect if self.past_dict[o] != self.current_dict[o])
    def unchanged(self):
        return set(o for o in self.intersect if self.past_dict[o] == self.current_dict[o])



class PAPMeasureBackend():
    def __init__(self, repositoryfile='repository.json'):
        self.mfib = None
        self.prepare_strings = dict()
        self.jsonrpc_start = dict()
        self.tools_to_start = list()
        self.mvar_to_stream = dict()
        self.stream_to_mvar = dict()
        self.action_list = list()
        self.mvar_to_metric = dict()
        self.mvar_to_type = dict()
        self.zone_commands = dict()
        self.zdeps = dict()

        with open(repositoryfile) as json_file:
            self.mfib = json.load(json_file)


    def generate_config(self, measure):
        #Reset internal state except MFIB

        self.prepare_strings = dict()
        self.jsonrpc_start = dict()
        self.tools_to_start = list()
        self.mvar_to_stream = dict()
        self.stream_to_mvar = dict()
        self.action_list = list()
        self.mvar_to_metric = dict()
        self.mvar_to_type = dict()
        self.zone_commands = dict()
        self.zdeps = dict()


        for meas in measure['measurements']:
            self.check_tool(meas)

        self.start_tools(self.tools_to_start)

        for action in measure['actions']:
            self.action_list.append(self.action_to_dict(action))

        for zone in measure['zones']:
            self.update_zone_deps(zone)

        for zone in measure['zones']:
            self.zone_to_view(zone)


        pprint(["Toools to start", self.tools_to_start])
        pprint(["Streams - mvars", self.stream_to_mvar])
        pprint(["Mvars - streams", self.mvar_to_stream])
        pprint(["Zone dependencies", self.zdeps])
        pprint(["Actions",self.action_list])
        pprint(["Zone commands: ", self.zone_commands], width=200)

        result = dict()
        result['tools'] = self.tools_to_start
        result['zonedeps'] = self.zdeps
        result['actions'] = self.action_list
        result['zonecmds'] = self.zone_commands

        return result



    def find_tool(self,metric):
        for tool in self.mfib['tools']:
            for v in self.mfib['tools'][tool]['results']:
                if v == metric:
                    return tool
        return False



# {'mvar': 'm1', 'function': {'fname': 'overload.risk.rx', 'params': [{'pvar': 'eth0', 'pname': 'interface'}]}}

    def toollist_add(self,tool):
       if tool['name'] in self.mvar_to_stream.keys():
            raise Exception("Variable %s declared twice"%(tool['name']))

        # check if mvar is busy
       for n in self.tools_to_start:
           if n['tool'] == tool['tool']:
               d = DictDiffer(n['params'],tool['params'])
               if len(d.added()) == 0 and len(d.changed()) ==  0 and len(d.removed()) == 0:
                   self.stream_to_mvar["stream_%s"%n['name']].append(tool['name'])
                   self.mvar_to_stream[tool['name']] = "stream_%s"%n['name']
                   return

       self.tools_to_start.append(tool)
       self.mvar_to_stream[tool['name']] = "stream_%s"%tool['name']
       self.stream_to_mvar["stream_%s"%tool['name']] = [tool['name']]


    def check_tool(self,desc):
        name = desc['mvar']
        function = desc['function']
        metric = function['fname']
        tool = self.find_tool(metric)
        label = self.mfib['tools'][tool]['label']
        param = dict()
        tparam = self.mfib['tools'][tool]['parameters']
        self.mvar_to_metric[name] = metric
        self.mvar_to_type[name] = self.mfib['tools'][tool]['results'][metric]
        for req in tparam:
            for p in function['params']:
                if p['pname'] == req:
        #            logging.debug("required type " + tparam[req] +  "found type "+  str(type(p['pvar'])))
                    # TODO: check if types match
                    param[req] = p['pvar']
                    function['params'].remove(p)

        if len(function['params']) > 0:
            raise Exception("Too many parameters, did not expect "  + str(function['params']))

        # print("paramters: ", param)
        # TODO Should do a lookup for parameters here, to resolve e.g. interface to port

        self.toollist_add({'tool':tool,'label':label,'params':param , 'name':name,
                           'provides':self.mfib['tools'][tool]['results']})


    def action_to_dict(self,action):
        fdesc = action['functions']
        state = action['state']
        print("action functions: ", fdesc)
        print("action state: ", state)
        retval = dict()
        retval['state'] = state
        funs = dict()
        for n in fdesc:
            arguments = dict()
            for p in n['params']:
                if 'pname' not in p or 'pstr' not in p:
                    raise Exception("Action functions arguments must be strings!")
                arguments[p['pname']] = p['pstr']
            funs[n['fname']] = arguments
        retval['calls'] = funs
        return retval


    def update_zone_req(self,zone):
        deps = list()
        if 'l' in zone:
            deps = deps + (self.update_zone_req(zone['l']))
        if 'r' in zone:
            deps = deps + (self.update_zone_req(zone['r']))
        if 'function' in zone:
            for p in zone['function']['params']:
                if 'pvar' in p:
                    deps = deps + [p['pvar']]

        return deps

    # Find which zones depend on which variable
    def update_zone_deps(self,zone):
        zname = list(zone)[0]
        deps =  self.update_zone_req(zone[zname])
        self.zdeps[zname] = deps

    def exp_to_view(self,zname, exp):
        pprint(["exp_to_view", zname, exp])

    def exp_to_select(self,zname, operand, exp):
        pprint(["exp_to_select", zname, operand, exp])


    def zone_to_view(self,zone):
        zname = list(zone)[0]
        exp = zone[zname]

        if 'function' in exp['l'] and 'pval' in exp['r']:
            funs = dict()
            fdesc = exp['l']['function']
            fname = fdesc['fname']
            params = fdesc['params']
            for p in params:
                pks = list(p.keys())
                pks.remove('pname')
                funs[p['pname']] = p[pks[0]]
                    #arguments[p['pname']] = p['pstr']
            select_str = "SELECT \"%s\" FROM view_%s WHERE \"%s\" %s %s"%(self.mvar_to_metric[funs['val']], zname,
                                                                      self.mvar_to_metric[funs['val']],exp['op'], exp['r']['pval'])

            create_streams = list()

            for n in self.zdeps[zname]:
               create_streams.append("CREATE STREAM %s (data json);"%self.mvar_to_stream[n])


            if 'max_age' in funs:
                with_str = "WITH (max_age = '%s')"%funs['max_age']
            else:
                with_str = ""

            c_str =  "CREATE CONTINUOUS VIEW view_%s %s "%(zname,with_str)
            c_str2 = "AS SELECT %s(CAST(data->>'%s' as %s)) as \"%s\" "%(fname,self.mvar_to_metric[funs['val']],
                                                                         self.mvar_to_type[funs['val']],
                                                                         self.mvar_to_metric[funs['val']])
            c_str3 = "FROM %s;"%(self.mvar_to_stream[funs['val']])
            create_str = c_str + c_str2 + c_str3
            self.zone_commands[zname] = {'select':select_str,'create':create_str, 'streams':create_streams}
            print(create_str)
            print(select_str)
        else:
            print("multi-level zone, cant handle it!")

    def start_tools(self,tools):
        for n in tools:
            self.prepare_strings[n['name']] = "CREATE STREAM stream_%s (data json)"%(n['name'])
            self.jsonrpc_start[n['name']] = str(Request("start",**n['params']))

        pprint(self.prepare_strings)
        pprint(self.jsonrpc_start, width=140)



