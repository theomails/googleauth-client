package net.progressit.googleauthclient;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import net.progressit.googleauthclient.GoogleOAuthHelper.GoogleOAuthAuthRequestData;
import net.progressit.googleauthclient.GoogleOAuthHelper.GoogleOAuthAuthUrlError;
import net.progressit.googleauthclient.GoogleOAuthHelper.GoogleOAuthTokenRequestData;
import net.progressit.googleauthclient.GoogleOAuthHelper.GoogleOAuthTokenResponseData;

public class GoogleAuthHelperTest {
	
	private GoogleOAuthHelper googleAuthHelper = new GoogleOAuthHelper(); 

	@Test
	public void shouldBuildAuthUrl() {
		GoogleOAuthAuthRequestData requestData = GoogleOAuthAuthRequestData.builder()
				.clientId("09283402384-lscjroceuoco9wcs9ejp93nxlmo5uosl.apps.googleusercontent.com")
				.redirectUri("http://localhost:8080")
				.scopes(List.of("https://www.googleapis.com/auth/userinfo.profile"))
				.stateJson("{\"process\":\"signup\", \"original_request_path\":\"https://sessionz.progressit.net/\"}")
				.build();
		String authUrl = googleAuthHelper.buildAuthUrl(requestData);
		String expectedAuthUrl = "https://accounts.google.com/o/oauth2/v2/auth?client_id=09283402384-lscjroceuoco9wcs9ejp93nxlmo5uosl.apps.googleusercontent.com&redirect_uri=http%3A%2F%2Flocalhost%3A8080&response_type=code&scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.profile&access_type=online&state=%7B%22process%22%3A%22signup%22%2C+%22original_request_path%22%3A%22https%3A%2F%2Fsessionz.progressit.net%2F%22%7D";
		Assertions.assertEquals(expectedAuthUrl, authUrl);
	}

	@Test
	public void shouldGetAuthResponseErrorKey() {
		String errorKey = googleAuthHelper.getAuthResponseErrorKey();
		String expectedErrorKey = "error";
		Assertions.assertEquals(expectedErrorKey, errorKey);
	}
	
	@Test
	public void shouldGetAuthResponseCodeKey() {
		String codeKey = googleAuthHelper.getAuthResponseCodeKey();
		String expectedCodeKey = "code";
		Assertions.assertEquals(expectedCodeKey, codeKey);
	}
	
	@Test
	public void shouldConvertAuthUrlError() {
		GoogleOAuthAuthUrlError errorEnum = googleAuthHelper.asAuthUrlError("disallowed_useragent");
		GoogleOAuthAuthUrlError expectedEnum = GoogleOAuthAuthUrlError.disallowed_useragent;
		Assertions.assertEquals(expectedEnum, errorEnum);
	}
	
	@Test
	public void shouldBuildTokenUrl() {
		GoogleOAuthTokenRequestData requestData = GoogleOAuthTokenRequestData.builder()
				.clientId("09283402384-lscjroceuoco9wcs9ejp93nxlmo5uosl.apps.googleusercontent.com")
				.clientSecret("asdlkfjaskd")
				.code("4/P7q7W91a-oMsCeLvIaQm6bTrgtp7")
				.redirectUri("http://localhost:8080")
				.build();
		String tokenUrl = googleAuthHelper.buildTokenUrl(requestData);
		String expectedTokenUrl = "https://accounts.google.com/o/oauth2/v2/token?client_id=09283402384-lscjroceuoco9wcs9ejp93nxlmo5uosl.apps.googleusercontent.com&client_secret=asdlkfjaskd&code=4%2FP7q7W91a-oMsCeLvIaQm6bTrgtp7&grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%3A8080";
		Assertions.assertEquals(expectedTokenUrl, tokenUrl);
	}
	
	@Test
	public void shouldParseOAuthTokenResponse() {
		GoogleOAuthTokenResponseData responseObj = googleAuthHelper.parseOAuthTokenResponse("{\n"
				+ "  \"access_token\": \"1/fFAGRNJru1FTz70BzhT3Zg\",\n"
				+ "  \"expires_in\": 3920,\n"
				+ "  \"token_type\": \"Bearer\",\n"
				+ "  \"scope\": \"https://www.googleapis.com/auth/drive.metadata.readonly\",\n"
				+ "  \"refresh_token\": \"1//xEoDL4iW3cxlI7yDbSRFYNG01kVKM2C-259HOF2aQbI\"\n"
				+ "}");
		
		assertEquals("1/fFAGRNJru1FTz70BzhT3Zg", responseObj.getAccessToken());
		assertEquals(3920L, responseObj.getExpiresIn());
	}
	
	@Test
	public void shouldGetAccessTokenHeaderKey() {
		String headerKey = googleAuthHelper.getAccessTokenHeaderKey();
		String expectedHeaderKey = "Authorization";
		Assertions.assertEquals(expectedHeaderKey, headerKey);
	}
	
	@Test
	public void shouldGetAccessTokenHeaderValue() {
		String headerValue = googleAuthHelper.getAccessTokenHeaderValue("1/fFAGRNJru1FTz70BzhT3Zg");
		String expectedHeaderValue = "Bearer 1/fFAGRNJru1FTz70BzhT3Zg";
		Assertions.assertEquals(expectedHeaderValue, headerValue);
	}
	
}
