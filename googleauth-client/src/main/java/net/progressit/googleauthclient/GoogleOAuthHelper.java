package net.progressit.googleauthclient;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;

import lombok.Builder;
import lombok.Data;
import lombok.Getter;

public class GoogleOAuthHelper {
	
	private static final String GOOGLE_OAUTH_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
	private static final String GOOGLE_OAUTH_TOKEN_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/token";
	
	public enum GoogleOAuthAuthUrlError{
		admin_policy_enforced("Sign-in in not allowed because your organization's Google Workspace policy does not allow this feature currently."),
		disallowed_useragent("Sign-in is not allowed via this browser."),
		org_internal("You cannot sign-in because this application is only for Google Workspace users of this organization."),
		redirect_uri_mismatch("Unable to sign-in because the request is initiated from suspicious source.");
		
		@Getter
		private String message;
		GoogleOAuthAuthUrlError(String message) {
			this.message = message;
		}
	}
	
	@Data
	@Builder
	public static class GoogleOAuthAuthRequestData{
		private String clientId;
		private String redirectUri;
		private List<String> scopes;
		private String stateJson;
		
	}
	
	@Data
	@Builder
	public static class GoogleOAuthTokenRequestData{
		private String clientId;
		private String clientSecret;
		private String code;
		private String redirectUri;
		
	}
	
	@Data
	@Builder
	public static class GoogleOAuthTokenResponseData{
		@SerializedName("access_token")
		private String accessToken;
		@SerializedName("expires_in")
		private long expiresIn;
	}
	
	/**
	 * This method builds the whole URL, and takes care of URL encoding of the parameter values.  
	 * <ul>
	 * <li>Starts with: https://accounts.google.com/o/oauth2/v2/auth</li> 
	 * <li>Query parameters: client_id, redirect_uri, response_type (code), scope, access_type (online), state</li>
	 * </ul>
	 * 
	 * @param requestData
	 * @return
	 */
	public String buildAuthUrl(GoogleOAuthAuthRequestData requestData) {
		StringBuilder sb = new StringBuilder(500);
		
		String scopesSsv = requestData.getScopes().stream().collect(Collectors.joining(" "));
		
		sb.append(GOOGLE_OAUTH_AUTH_ENDPOINT);
		sb.append("?").append("client_id=").append( encode(requestData.getClientId()) );
		sb.append("&").append("redirect_uri=").append( encode(requestData.getRedirectUri()) );
		sb.append("&").append("response_type=").append("code");
		sb.append("&").append("scope=").append( encode(scopesSsv) );
		sb.append("&").append("access_type=").append("online");
		sb.append("&").append("state=").append( encode(requestData.getStateJson()) );
		
		return sb.toString();
	}

	public String getAuthResponseErrorKey() {
		return "error";
	}
	
	public String getAuthResponseCodeKey() {
		return "code";
	}
	
	public GoogleOAuthAuthUrlError asAuthUrlError(String errorCode) {
		return GoogleOAuthAuthUrlError.valueOf(errorCode);
	}
	
	/**
	 * This method builds the whole URL, and takes care of URL encoding of the parameter values.  
	 * <ul>
	 * <li>Starts with: https://accounts.google.com/o/oauth2/v2/token</li> 
	 * <li>Query parameters: client_id, client_secret, code, grant_type (authorization_code), redirect_uri</li>
	 * </ul>
	 * 
	 * @param requestData
	 * @return
	 */
	public String buildTokenUrl(GoogleOAuthTokenRequestData requestData) {
		StringBuilder sb = new StringBuilder(500);
		
		sb.append(GOOGLE_OAUTH_TOKEN_ENDPOINT);
		sb.append("?").append("client_id=").append( encode(requestData.getClientId()) );
		sb.append("&").append("client_secret=").append( encode(requestData.getClientSecret()) );
		sb.append("&").append("code=").append( encode(requestData.getCode()) );
		sb.append("&").append("grant_type=").append( "authorization_code" );
		sb.append("&").append("redirect_uri=").append( encode(requestData.getRedirectUri()) );
		
		return sb.toString();
	}
	
	public GoogleOAuthTokenResponseData parseOAuthTokenResponse(String tokenResponseJson) {
		return new Gson().fromJson(tokenResponseJson, GoogleOAuthTokenResponseData.class);
	}
	
	public String getAccessTokenHeaderKey() {
		return "Authorization";
	}
	
	public String getAccessTokenHeaderValue(String onlyAccessToken) {
		return "Bearer " + onlyAccessToken;
	}
	
	//PRIVATE
	
	private String encode(String value) {
		return URLEncoder.encode(value, StandardCharsets.UTF_8);
	}
}
