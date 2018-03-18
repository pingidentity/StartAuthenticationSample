This authentication sample code demonstrates the usage of the StartAuthentication API call of PingID.

**Prerequisites:**
<br/>
   * Existing organization with properties file <br/>
   (can be download from the Admin Web-Portal -> Setup -> PingID -> Client Integration)
   * An existing user with at least one paired device.<br/>
   the flow of the authentication depends on the number of devices paired for the user and the organization's configuration 
   (e.g. multiple devices, selection mode)

**How to run this sample:**
<br/>
  1. *mvn install*
  2. *java -jar target/authentication-0.0.1-SNAPSHOT-jar-with-dependencies.jar /env/props/pingid.properties jdoe*

<br/>

**DISCLAIMER:** This is a simple, non-official, unsupported, main application that assumes that the inputs are correct and does no validation.

