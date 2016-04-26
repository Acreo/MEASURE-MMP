Monitor management plugin (MMP)
===================

The Monitor Management Plugin is a DoubleDecker client responsible for starting and configuring monitoring components. It communicates using DoubleDecker with the Local Orchestrator (to retrieve the NFFG to 'real' mapping, and MEASURE string). It also communicates with the local Docker daemon to start and stop monitoring functions and monitoring infrastructure. 

Dependencies
-------------------
* Requires Python version of the DoubleDecker library (git clone from https://github.com/Acreo/DoubleDecker)
* pip3 install jsonrpcsserver
* pip3 install jsonrpcclient


> **Contact:** ponsko@acreo.se
