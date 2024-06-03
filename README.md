# A10 Networks VMware Templates Release v1.1.0
Welcome to VMware Templates 1.1.0 Latest Version.

Thunder® ADCs (Application Delivery Controllers) are high-performance solutions to accelerate and optimize critical applications to ensure delivery and reliability.

VMware Templates is a custom template to create and configure Thunder using Templates[.yaml] and Python[.py] scripts.

This template contains several configurations of Thunder which can be applied via box examples provided. VMware Templates will install Thunder in the VMware cloud environment and configure the Thunder via AXAPI.

## A10’s vThunder Support Information
Below listed A10’s vThunder vADC (Application Delivery Controller) are tested and supported.


|        ACOS ADC         | VMWARE 1.0.0 | VMWARE 1.1.0 |
|:-----------------------:|:-------------------------------------------------------------------------------------------------------:|:------------------------------------------------------------------------------------------:|
`ACOS version 6.0.3-p1`|                    `Yes`|                                          `Yes`| 
`ACOS version 6.0.3`|                    `Yes`|                                          `Yes`| 
`ACOS version 6.0.2`|                      `Yes`|                                           `Yes`| 
`ACOS version 6.0.1`|                    `Yes`|                                          `Yes`| 
`ACOS version 6.0.0`|                    `Yes`|                                          `Yes`| 
`ACOS version 5.2.1-p9` |      `Yes`|                                           `Yes`| 
`ACOS version 5.2.1-p8` |      `Yes`|                                           `Yes`| 
`ACOS version 5.2.1-p6`|                      `Yes`|                                           `Yes`| 
`ACOS version 5.2.1-p5`|                      `Yes`|                                           `Yes`| 
`ACOS version 5.1.0-p7`|                      `Yes`|                                           `Yes`| 



## Release Logs
## VMware Templates-1.1.0
- All template deployment and configuration parameters are separate.
- Added SLB HTTP and Persist Cookie templates. 
- Added BACKEND-AUTOSCALE support which applies an SLB configuration automatically whenever backend app/web servers are autoscaled. 
- Added the following new templates:
  1. A10-vThunder-3NIC-1VM
  2. A10-vThunder-3NIC-2VM
  3. A10-vThunder-3NIC-3VM


- Added the following configurations for each of the templates:
  1. BASIC-SLB 
  2. CHANGE-PASSWORD 
  3. GLM-LICENSE 
  4. HIGH-AVAILABILITY 
  5. HYBRID-CLOUD-GSLB 
  6. SSL-CERTIFICATE
  7. CONFIG-SLB_ON_BACKEND-AUTOSCALE

For more information on using this option please refer to VMware documentation:https://documentation.a10networks.com/docs/IaC/vmware-esxi/1-1-0/

## VMware Templates-1.0.0

-   The VMware Template release v1.0.0 includes the vROps and vRLI dashboard configuration.
 
- **VMware VSphere**<br>
The pre-requisite to using this option is to download the scripts first by the user, upload script to VMware VSphere cloud assembly and select parameters. <br>
For more information on using this option please refer to VMware documentation:https://documentation.a10networks.com/IaC/VMware/1_0_0/html/VMware_TEMP_Responsive_HTML5/Default.htm#vmwareTOC

## How to download the A10 vThunder image

  1. Log in to the A10 Support Portal and go to Software and Documentation > Thunder & AX Series > vThunder Installation - ADC/SLB > X.X.X Release > vThunder Appliance for VMware or vThunder Appliance for KVM.

  2. Select the vThunder OVA <ACOS_vThunder_xxx.ova> or ISO image <ACOS_vThunder_xxx.iso>.

## VMware ESXi

  To install VMware ESXi on your Bare Metal instance, see [VMware ESXi Installation and Setup](https://docs.vmware.com/en/VMware-vSphere/7.0/com.vmware.esxi.install.doc/GUID-93D0227B-E5ED-40B0-B8E2-71141A32EB00.html).

## VMware Monitoring

  1. VMware vRealize Operations (vROps) - To install vROps on the ESXi host, see vROps installation.

  2. VMware vRealize Log Insight (vRLI) - To install vRLI on the ESXi host, see vRLI installation.

## How to deploy vThunder instance using an VMware template on VSphere console

Navigate to the VMware template directory which needs to be applied and follow the below steps.

1. Navigate to the VMware vRealize automation -> Cloud Assembly
2. Go to the Design tab. Click New form and upload existing template.
3. Enter a name, select a project, and click Create. Upload yaml file.
4. Click on the created template, go to the editor, then test and deploy.

## How to verify configuration on Thunder

To verify the applied configuration, follow the below steps:

  1. SSH into the Thunder device using your username and password.
  2. Once connected, enter the following commands:

     $ `enable`

     $ `show running-config`

  You will see the following configurations:
    !

    interface management

      ip address X.X.X.X 255.255.255.0

      ip default-gateway X.X.X.X

    !

    interface ethernet 1

    !

    interface ethernet 2




## How to contribute

If you have created a new example, please save the VMware Templates/Python file with a resource-specific name, such as "VMware-3NIC-1VM.yaml"

1. Clone the repository.
2. Copy the newly created file and place it under the /examples/resource directory.
3. Create an MR against the master branch.


## Documentation

VMware template documentation is available below location,
- VMware: https://documentation.a10networks.com -> Infrastructure as Code (IAC) -> VMware



## Report an Issue

Please raise the issue in the GitHub repository.
Please include the VMware templates script that demonstrates the bug and the command output and stack traces will be helpful.


## Support

Please reach out at support@a10networks.com with "a10-vmware-templates" in the subject line.
