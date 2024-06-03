# Prerequisites
    1. Python3

# Steps
    1. Update vCenter Configuration present at 
        a10_vcenter_backauto_plugin/vcenter.ini
    2. Setup a source server
        refer to User Guide to Create And Setup Server VM.
    3. Create a vcenter customization specification
        refer to User Guide Create Customization Specification.
    4. Update a10_vcenter_backauto_plugin/apps/app1/config.ini
    5. Update already in use ip address from server_subnet into a10_vcenter_backauto_plugin/apps/app1/app_servers.ini
    6. Add new network adaptor in vCenter VM and same port group as source VM
        refer to User Guide Setup vCenter VM
    7. Install requirements.txt
        pip install -r requirements.txt
    8. Execute setup.py file
        python setup.py

# Alerts
    1. For each app create a vcenter inventory folder.
        refer to User Guide Create Inventory Folder
    2. Setup scale out and scale in alarm in created inventory folder.
        refer to User Guide Create Alarm for Scale out and Scale In.

# Setup addition apps
Refer to User Guide Creating a new app.
