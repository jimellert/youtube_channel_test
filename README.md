youtube_channel_test
====================

Test area for youtube api usage.


1. Build youtube-channel-auth and youtube-channel-refresh.
2. Navigate to https://console.developers.google.com.  Create a project and create a Client ID for a "web application".  You need a client ID and a client secret.
3. Create file "client_secrets.json" in the top youtube_channel_test directory.
   Example client_secrets.jason:
{
    "client_id": "686507845681-h7chjgtkjau13b3gaqkgvl9cp9hji91k.apps.googleusercontent.com",
    "client_secret": "gu8ZSL57QaqkpQxmtEdmz5bE",
    "redirect_uri": "http://localhost:8080",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://accounts.google.com/o/oauth2/token"
}
4. Run youtube-channel-auth and accept the access request.  This will create another file in the top youtube_channel_test directory called accessTokens.json.  This file is used to re-auth when necessary on youtube api requests.
5. Run youtube-channel-refresh.  This will get a list of channels using the access tokens previously created and refresh those tokens as needed.

