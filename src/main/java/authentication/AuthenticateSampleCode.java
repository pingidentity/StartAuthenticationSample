package authentication;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Properties;
import java.util.Scanner;
import java.util.TimeZone;


import org.apache.commons.io.IOUtils;
import org.jose4j.base64url.Base64;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.keys.HmacKey;
import org.jose4j.lang.JoseException;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

/**
 * This Authenticate sample code demonstrates the usage of the startAuthentication API call of PingID
 * 
 * prerequisites: 
 * a. Existing organization with properties file 
 *    (can be download from the Admin Web-Portal->Setup->PingID->Client Integration->Settings Applications File->Download)
 * b. An existing user with at least one paired device.
 *    the flow of the startAuthentication depends on the number of devices paired for the user and the organization's configuration 
 *    (multiple devices, selectiveMode, offline devices types (SMS, Voice, Email, Yubikey or Desktop) and which device is the primary)
 * 
 * @input path to path properties file (String)
 * @input an existing userName to authenticate
 * 
 * This is a simple main application that assumes that the inputs are correct and does no validation
 */
public class AuthenticateSampleCode {

	private String orgAlias;
	private String token;
	private String base64Key;
	private String baesUrl;
	private String userName;
	
	/**
	 * constructor
	 *  @input path to path properties file (String)
	 *  @input an existing userName to authenticate
	 * */
	public AuthenticateSampleCode(String path, String userName) {
		Properties props = new Properties();
		InputStream input = null;
		try {
			input = new FileInputStream(path);
			props.load(input);
		} catch (IOException e) {
			e.printStackTrace();
		}
		this.orgAlias = props.getProperty("org_alias");
		this.token = props.getProperty("token");
		this.base64Key = props.getProperty("use_base64_key");
		this.baesUrl = props.getProperty("idp_url");
		this.userName = userName;
	}

	/**
	 * this method demonstrates the only mandatory fields that need to be sent in the http-request's body
	 * in the simple case when there is no information about the user's devices
	 **/
	@SuppressWarnings("unchecked")
	private JSONObject startAuthentication() {
		String endpoint = "/rest/4/startauthentication/do";
		
		JSONObject reqBody = new JSONObject();
		//"web" is the most common but there are other option like "sso" and more
		reqBody.put("spAlias", "web");
		reqBody.put("userName", this.userName);
		String requestToken = buildRequestToken(reqBody);

		String responseToken = sendRequest(this.baesUrl + endpoint, requestToken);
		JSONObject response = parseResponse(responseToken);
		return response;
	}
	
	/**
	 * this method demonstrates the second use of startAuthentication - when the first call returns 30008
	 * this means that the org's configurations are multiple devices allowed and selection mode is on (doesn't send to default device) 
	 * and the user has more then one device
	 * in that case the response of the first API call will include the information on the user devices and a sessionId 
	 * it still doesn't make the authentication. it will give back which flow to choose for this device (online, offline, sms, offline, voice etc)
	 * @input deviceId - one that we chose from multiple 
	 * @input sessionId 
	 **/
	@SuppressWarnings("unchecked")
	private JSONObject startAuthentication(String sessionId, Long deviceId) {
		String endpoint = "/rest/4/startauthentication/do";
		
		JSONObject reqBody = new JSONObject();
		reqBody.put("spAlias", "web");
		reqBody.put("userName", this.userName);
		reqBody.put("sessionId", sessionId);
		reqBody.put("deviceId", deviceId);
		String requestToken = buildRequestToken(reqBody);

		String responseToken = sendRequest(this.baesUrl + endpoint, requestToken);
		JSONObject response = parseResponse(responseToken);
		return response;
	}

	/**
	 * this method demonstrates how to call AuthOnline API. this call makes an online authentication to a given device
	 * the deviceId and sessionId are accepted from the response of StartAuthentication API call 
	 * see also @link https://developer.pingidentity.com/en/api/pingid-api/authentication-api.html#online_authentication_workflow
	 * */
	@SuppressWarnings("unchecked")
	private JSONObject authOnLine(String sessionId, Long deviceId) {
		String endpoint = "/rest/4/authonline/do";
		JSONObject reqBody = new JSONObject();
		reqBody.put("spAlias", "web");
		reqBody.put("userName", this.userName);
		reqBody.put("authType", "CONFIRM");
		reqBody.put("deviceId", deviceId);
		reqBody.put("sessionId", sessionId);
		String requestToken = buildRequestToken(reqBody);

		String responseToken = sendRequest(this.baesUrl + endpoint, requestToken);
		JSONObject response = parseResponse(responseToken);
		return response;
	}
	
	/**
	 * this method demonstrates how to call AuthOffline API. this method authenticates the user with an offline "device" (sms, voice, yubikey, swipe-disable mobile app). 
	 * the @input otp is accepted from sms/voice/yubikey/mail according to device configuration
	 * the deviceId and sessionId are accepted from the response of StartAuthentication API call 
	 * see also @link https://developer.pingidentity.com/en/api/pingid-api/authentication-api.html#online_authentication_workflow
	 * */
	@SuppressWarnings("unchecked")
	private JSONObject authOffLine(String sessionId, Long deviceUuid, Long otp) {
		String endpoint = "/rest/4/authoffline/do";
		JSONObject reqBody = new JSONObject();
		JSONObject formParams = new JSONObject();
		formParams.put("sp_name", "gmail");
		reqBody.put("spAlias", "web");
		reqBody.put("userName", this.userName);
		reqBody.put("authType", "CONFIRM");
		reqBody.put("deviceId", deviceUuid);
		reqBody.put("sessionId", sessionId);
		reqBody.put("otp", otp);
		reqBody.put("formParameters", formParams);
		String requestToken = buildRequestToken(reqBody);

		String responseToken = sendRequest(this.baesUrl + endpoint, requestToken);
		JSONObject response = parseResponse(responseToken);
		return response;
	}

	/**
	 * Yubikey scenario 
	 * 
	 * */
	@SuppressWarnings("unchecked")
	private JSONObject authOffLine(String sessionId, Long deviceUuid, String otp) {
		String endpoint = "/rest/4/authoffline/do";
		JSONObject reqBody = new JSONObject();
		JSONObject formParams = new JSONObject();
		formParams.put("sp_name", "gmail");
		reqBody.put("spAlias", "web");
		reqBody.put("userName", this.userName);
		reqBody.put("authType", "CONFIRM");
		reqBody.put("deviceId", deviceUuid);
		reqBody.put("sessionId", sessionId);
		reqBody.put("otp", otp);
		reqBody.put("formParameters", formParams);
		String requestToken = buildRequestToken(reqBody);

		String responseToken = sendRequest(this.baesUrl + endpoint, requestToken);
		JSONObject response = parseResponse(responseToken);
		return response;
	}
	
	/**
	 * Helper method to send and get the http-request/response. 
	 * Other ways to are also possible
	 * */
	private String sendRequest(String url, String requestToke) {

		String responseToken;
		try {
			URL restUrl = new URL(url);
			HttpURLConnection urlConnection = (HttpURLConnection) restUrl.openConnection();
			urlConnection.setRequestMethod("POST");
			urlConnection.addRequestProperty("Content-Type", "application/json");
			urlConnection.addRequestProperty("Accept", "*/*");

			urlConnection.setDoOutput(true);
			OutputStreamWriter outputStreamWriter = new OutputStreamWriter(urlConnection.getOutputStream(), "UTF-8");
			outputStreamWriter.write(requestToke);
			outputStreamWriter.flush();
			outputStreamWriter.close();

			int responseCode = urlConnection.getResponseCode();

			if (responseCode == 200) {

				String encoding = urlConnection.getContentEncoding();
				InputStream is = urlConnection.getInputStream();
				String stringJWS = IOUtils.toString(is, encoding);
				responseToken = stringJWS;
				urlConnection.disconnect();
			} else {
				String encoding = urlConnection.getContentEncoding();
				InputStream is = urlConnection.getErrorStream();
				String stringJWS = IOUtils.toString(is, encoding);
				responseToken = stringJWS;
				urlConnection.disconnect();
			}
		} catch (Exception ex) {
			return null;
		}
		return responseToken;
	}

	/**
	 * Helper method to verify the response and get the response's body
	 * @return JSONObject the represent the response's body
	 * */
	private JSONObject parseResponse(String responseToken) {

		JSONParser parser = new JSONParser();
		JSONObject responsePayloadJSON = null;

		try {

			JsonWebSignature responseJWS = new JsonWebSignature();
			responseJWS.setCompactSerialization(responseToken);
			HmacKey key = new HmacKey(Base64.decode(this.base64Key));
			responseJWS.setKey(key);
			responsePayloadJSON = (JSONObject) parser.parse(responseJWS.getPayload());

			if (responsePayloadJSON.containsKey("responseBody")) {
				responsePayloadJSON = (JSONObject) responsePayloadJSON.get("responseBody");
			}

		} catch (Exception e) {
			e.printStackTrace();
		}

		return responsePayloadJSON;
	}

	/**
	 * this method demonstrates how to build the request and sign it. 
	 * as explained in @link https://developer.pingidentity.com/en/api/pingid-api.html 
	 * */
	@SuppressWarnings("unchecked")
	private String buildRequestToken(JSONObject requestBody) {

		JSONObject requestHeader = buildRequestHeader();

		JSONObject payload = new JSONObject();
		payload.put("reqHeader", requestHeader);
		payload.put("reqBody", requestBody);

		JsonWebSignature jws = new JsonWebSignature();

		jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.HMAC_SHA256);
		jws.setHeader("org_alias", this.orgAlias);
		jws.setHeader("token", this.token);

		jws.setPayload(payload.toJSONString());

		// Set the verification key
		HmacKey key = new HmacKey(Base64.decode(this.base64Key));
		jws.setKey(key);

		String jwsCompactSerialization = null;
		try {
			jwsCompactSerialization = jws.getCompactSerialization();
		} catch (JoseException e) {
			e.printStackTrace();
		}

		return jwsCompactSerialization;
	}

	/**
	 *  Helper method - self explained 
	 * */
	@SuppressWarnings("unchecked")
	private JSONObject buildRequestHeader() {

		JSONObject reqHeader = new JSONObject();
		reqHeader.put("locale", "en");
		reqHeader.put("orgAlias", this.orgAlias);
		reqHeader.put("secretKey", this.token);
		reqHeader.put("timestamp", getCurrentTimeStamp());
		reqHeader.put("version", "4.9");

		return reqHeader;
	}

	/**
	 * Helper method - self explained 
	 * */
	static String getCurrentTimeStamp() {

		Date currentDate = new Date();
		SimpleDateFormat PingIDDateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
		PingIDDateFormat.setTimeZone(TimeZone.getTimeZone("America/Denver"));

		return PingIDDateFormat.format(currentDate);
	}

	public static void main(String[] args) {
		
		String propertiesPath;
		String userName;
		
		if (args.length<2){
			System.out.println(String.format("Usage: %s <full-path-of-properties-file> <username>", AuthenticateSampleCode.class.getSimpleName()));
			return;
		}else{
			propertiesPath = args[0];
			userName = args[1];
		}
		
		AuthenticateSampleCode authenticator = new AuthenticateSampleCode(propertiesPath, userName);
		
		JSONObject response = authenticator.startAuthentication();
		if (response.containsKey("responseBody")) {
			response = (JSONObject)response.get("responseBody");
		}

		if (response == null) {
			System.out.println("something went wrong- maybe user doesnt exist or wrong properties");
			System.exit(1);
		}
		
		long errorId = (Long)(response.get("errorId"));
		
		
		/**
		*  30001 - Offline authentication (SMS) (OTP was sent, collect the OTP and call offline authentication)
		*  30002 - Offline authentication (Voice)(OTP was sent, collect the OTP and call offline authentication)
		*  30003 - Offline authentication (Application)(OTP was sent, collect the OTP and call offline authentication)
		*  30004 - Offline authentication (YubiKey)(collect the OTP and call offline authentication)
		*  30005 - Offline authentication (Email)(OTP was sent, collect the OTP and call offline authentication)
		*  30007 - Online authentication (Application) (call OnlineAuthentication)
		*  30008 - Device selection prompt (ask for a user to select a device and call startAuthentication again with the sessionID from the current request and the device ID for the selected device).
		* */
		JSONArray devices = (JSONArray) response.get("userDevices");
		Long deviceId = (Long)((JSONObject)devices.get(0)).get("deviceId");
		String sessionId = (String)(response.get("sessionId"));
		Long otp = null;
		
		System.out.println(response.get("errorMsg"));
		
		//
		// Handle the response of StartAuthentication
		//
		switch((int)errorId){
			case 30001: // this will happen when primary device's authentication type is sms - see above
			case 30002: // this will happen when primary device's authentication type is voice - see above
			case 30005: // this will happen when primary device's authentication type is Email - see above
				otp = new Scanner(System.in).nextLong();
				response = authenticator.authOffLine(sessionId, deviceId, otp);
				break;
			case 30004: // this will happen when primary device's authentication type is yubiKey - see above
				String yubikeyCode = new Scanner(System.in).nextLine();
				response = authenticator.authOffLine(sessionId, deviceId, yubikeyCode);
				break;
			case 30007: //the selective mode is disable and the primary device authentication type is Mobile
				response = authenticator.authOnLine(sessionId, deviceId);
				errorId = (Long)response.get("errorId");

				//you should get a push to your phone...
				//unless the phone has disabled notifications and then you'll get prompt to enter OTP from device
				
				if (errorId == 30003) {
					// this will happen when primary device's authentication type is application and notifications are disabled  
					System.out.println(response.get("errorMsg")+". Please enter otp from App");
					otp = new Scanner(System.in).nextLong();
					response = authenticator.authOffLine(sessionId, deviceId, otp);
				}
				break;
			case 30008:
				// this will happen when selection mode is enabled and there is more then one device
				devices = (JSONArray) response.get("userDevices");
				
				// user selects the device (in this example, the 2nd device)
				int indexOfSelectedDevice = 1;
				
				deviceId = (Long)((JSONObject)devices.get(indexOfSelectedDevice)).get("deviceId");
				sessionId = (String)(response.get("sessionId"));
				response = authenticator.startAuthentication(sessionId, deviceId);
				long flow = (Long)response.get("errorId");
				
				// handle the flow according to the returned status code (as done above):
				// 30001, 30002, 30003, 30005 authOffline with long otp
				// 30004 - authOffline with String otp (yubikey)
				// 30007 - authOnline

				break;
			default:
				break;
		}
		

		errorId = (Long)response.get("errorId");
		String msg = (String)response.get("errorMsg");
		if (errorId == 200) {
			msg = "SUCCESS";
		}
		System.out.println(String.format("msg=%s (%s)", msg, errorId));
	}
}
