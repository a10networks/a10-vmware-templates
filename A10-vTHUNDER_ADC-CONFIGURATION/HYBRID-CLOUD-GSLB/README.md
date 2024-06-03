### Global Server Load Balancing (GSLB)
GSLB is a DNS based system that manipulates the DNS response based on the availability of the Thunder. Run two Thunders setup in an Active-Passive architecture so that if one Thunder setup fails, traffic will be sent to the other.
This configuration script will help to configure the GSLB on cross availability zone.

**Files**

    1. HYBRID_CLOUD_CONFIG_GSLB_PARAM.json This file contains the HA related default configuration values.
    2. HYBRID_CLOUD_CONFIG_GSLB.py python script to configure HA on Thunder.


**Requirements**

    1. Python version Python 3.8.10
    2. VMware VSphere with required permissions
    3. Install all dependancies using following command. 
        pip install -r requirements.txt

**Execution Step**

    1. Install requirements.txt file if not already done.
        pip install -r requirements.txt
    2. Update HYBRID_CLOUD_CONFIG_GSLB_PARAM.json
    3. Execute HYBRID_CLOUD_CONFIG_GSLB.py
        From the Start menu, open cmd and navigate to the A10-vThunder-ADC-CONFIGURATION folder.	
        Run the following command from the command prompt:
            python HYBRID_CLOUD_CONFIG_GSLB.py


**Execution Step**

	1. logger.py:
		This file is used to log the error and information messages to log file which will generate on execution of HYBRID_CLOUD_CONFIG_GSLB.py
	2. requirements.txt
     	This is list of additional packages list need to install to run configuration script.