### SSL certificate
An SSL certificate is a digital certificate that authenticates a website's identity and enables an encrypted connection.

**Files**

    1. SSL_CONFIG_PARAM.json Parameter file for SSL file path and Thunder details.
    2. SSL_CONFIG.py Python script to configure SSL certificate in Thunder.

**Requirements**

    1. Python version Python 3.8.10
    2. VMware VSphere with required permissions
    3. Install all dependancies using following command. 
        pip install -r requirements.txt
    4. vThunder instances in running state.
    5. SSL certificate in .pem format.
	 
**Execution Step**

    1. Install requirements.txt file if not already done.
            pip install -r requirements.txt
    2. Update SSL_CONFIG_PARAM.json
    3. Execute SSL_CONFIG.py
	    From the Start menu, open cmd and navigate to the A10-vThunder-ADC-CONFIGURATION folder.	
	    Run the following command from the command prompt:
            python SSL_CONFIG.py

**Addtional Files**


	1. logger.py:
		This file is used to log the error and information messages to log file which will generate on execution of SSL_CONFIG.py
	2. server.pem:
		This is sample SSL certificate file. User can replace this certificate with his onw certificate. 
	3. requirements.txt
    		 This is list of additional packages list need to install to run configuration script. 
