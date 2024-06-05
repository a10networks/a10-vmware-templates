### Server Load Balancer (SLB)
Server Load Balancing is a networking method used to distribute incoming network traffic across a group of servers or devices to improve the performance, reliability, and availability of applications or services.

This configuration script will help to configure the SLB on Thunder.

**Files**

    1. SLB_CONFIG_PARAM.json this file contains the SLB related default configuration values. 
    2. SLB_CONFIG.py Python script to configure SLB on Thunder instances.
    3. HTTP_TEMPLATE.py this script will get executed internally by SLB_CONFIG.py, If "templateHTTP" is configured (templateHTTP=1) in SLB_CONFIG_PARAM.json file. 
    4. PERSIST_COOKIE.py this script will get executed internally by SLB_CONFIG.py, If "templatePersistCookie" is configured (templatePersistCookie=1) in SLB_CONFIG_PARAM.json file. 

**Requirements**

    1. Python version Python 3.8.10
    2. VMware VSphere with required permissions and configurations
    3. Install all dependancies using following command. 
        pip install -r requirements.txt
    4. vThunder instances in running state. 
   
**Execution Steps**

    1. Install requirements.txt file if not already done.
            pip install -r requirements.txt
    2. Update SLB_CONFIG_PARAM.json based of deployed template. 
    3. Execute SLB_CONFIG.py
	    From the Start menu, open cmd and navigate to the A10-vThunder-ADC-CONFIGURATION folder.	
	    Run the following command from the command prompt:
            python SLB_CONFIG.py
             

**Additional Files**
	1. logger.py:
		This file is used to log the error and information messages to log file which will generate on execution of SLB_CONFIG.py
    2. requirements.txt
     	This is list of additional packages list need to install to run configuration script.

	
			