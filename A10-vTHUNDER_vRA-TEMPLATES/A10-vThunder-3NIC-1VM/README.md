# A10 Networks VMware Templates Release v1.1.0
Welcome to VMware Templates 1.1.0 Latest Version.

Thunder® ADCs (Application Delivery Controllers) are high-performance solutions to accelerate and optimize critical applications to ensure delivery and reliability.

VMware Templates is a custom template to create using Templates[.yaml].

This template contains several configurations of Thunder which can be applied via box examples provided.VMware Templates will install Thunder in the VMware cloud environment and configure the Thunder via AXAPI.


**Files**
    
    1. VMWARE_TMPL_3NIC_1VM.yaml
       VMware template to deploy 1 vThunder having 2 interfaces in VMware vSphere vCenter.

**Requirements**

     1. Access of the VMware vSphere client.
     2. Access of the ESXI host.
     3. Access of vRealize Automation
     4. Access ACOS ova file in local machine. 
        Download image from this link - https://support.a10networks.com/support/axseries


**Execution Step**
    Navigate to the VMware template directory which needs to be applied and follow the below steps.

    1. Navigate to the VMware vRealize automation -> Cloud Assembly  
    2. Go to the Design tab. Click New form and upload existing template.
    3. Enter a name, select a project, and click Create. Upload yaml file.
    4. Click on the created template, go to the editor, then test and deploy.  


