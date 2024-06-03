### Change Password
This configuration script will help to change password of Thunder.

**File**

    1. CHANGE_PASSWORD_CONFIG.py is a python script to configure new password on Thunder instances.
    2. CHANGE_PASSWORD_CONFIG_PARAM.json is a parameter file that contains publicIpList to change passwords.

**Requirements**

    1. Python version Python 3.8.10
    2. VMware VSphere with required permissions
    3. Install all dependancies using following command. 
        pip install -r requirements.txt
    4. vThunder instances in running state.
   

**Execution Step**

    1. Install requirements.txt file if not already done.
            pip install -r requirements.txt
    2. Update CHANGE_PASSWORD_CONFIG_PARAM.json
    3. Execute CHANGE_PASSWORD_CONFIG.py
	    From the Start menu, open cmd and navigate to the A10-vThunder-ADC-CONFIGURATION folder.	
	    Run the following command from the command prompt:
            python CHANGE_PASSWORD_CONFIG.py

**Additional Files**

	1. logger.py:
		This file is used to log the error and information messages to log file which will generate on execution of PASSWORD_CHANGE.py
	2. CHANGE_PASSWORD_UTILS.py:
		This file is used to change the password of deployed vThunder.
	3. requirements.txt
     		This is list of additional packages list need to install to run configuration script. 
	
			