iThis Authenticate sample code demonstrates the usage of the startAuthentication API call of PingID

prerequisites: 
a. Existing organization with properties file 
   (can be download from the Admin Web-Portal->Setup->PingID->Client Integration->Settings Applications File->Download)
b. An existing user with at least one paired device.
   the flow of the startAuthentication depends on the number of devices paired for the user and the organization's configuration 
   (multiple devices, selectiveMode, offline devices types (SMS, Voice, Email, Yubikey or Desktop) and which device is the primary)

@input path to path properties file (String)
@input an existing userName to authenticate

This is a simple main application that assumes that the inputs are correct and does no validation

