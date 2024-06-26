### High Availability (HA)
High availability is a quality of computing infrastructure that allows it to continue functioning, even when some of its components fail.

This configuration script will help to configure the HA on Thunder's. 

**Files**

    1. HA_CONFIG_PARAM.json This file contains the HA related default configuration values.
    2. HA_CONFIG.py python script to configure HA on Thunder.


**Requirements**

    1. Python version Python 3.8.10
    2. VMware VSphere with required permissions
    3. Install all dependancies using following command. 
        pip install -r requirements.txt

**Execution Step**

    1. Install requirements.txt file if not already done.
            pip install -r requirements.txt
    2. Update HA_CONFIG_PARAM.json
    3. Execute HA_CONFIG.py
	    From the Start menu, open cmd and navigate to the A10-vThunder-ADC-CONFIGURATION folder.	
	    Run the following command from the command prompt:
            python HA_CONFIG.py

**Execution Step**

	1. logger.py:
		This file is used to log the error and information messages to log file which will generate on execution of HA_CONFIG.py
	2. requirements.txt
     		This is list of additional packages list need to install to run configuration script.
	
			