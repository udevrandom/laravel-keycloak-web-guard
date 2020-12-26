<?php

namespace Vizir\KeycloakWebGuard\Controllers;

use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Vizir\KeycloakWebGuard\Exceptions\KeycloakCallbackException;
use Vizir\KeycloakWebGuard\Facades\KeycloakWeb;

class AuthController extends Controller
{
    /**
     * Redirect to login
     *
     * @return view
     */
    public function login()
    {
        $url = KeycloakWeb::getLoginUrl();
        KeycloakWeb::saveState();

        return redirect($url);
    }

    /**
     * Redirect to logout
     *
     * @return view
     */
    public function logout()
    {
        KeycloakWeb::forgetToken();

        $url = KeycloakWeb::getLogoutUrl();
        return redirect($url);
    }

    /**
     * Redirect to register
     *
     * @return view
     */
    public function register()
    {
        $url = KeycloakWeb::getRegisterUrl();
        return redirect($url);
    }

    public function invalidPermissions(){

        $errorURL = \Config::get('keycloak-web.invalid_permissions_url','');
        if ($errorURL == ''){
            return "
<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv=\"Content-type\" content=\"text/html; charset=utf-8\">
    <meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; base-uri 'self'; connect-src 'self'; form-action 'self'; img-src 'self' data:; script-src 'self'; style-src 'unsafe-inline'\">
    <meta content=\"origin\" name=\"referrer\">
    <title>Invalid Permissions</title>
    <style type=\"text/css\" media=\"screen\">
      body {
        background-color: #f1f1f1;
        margin: 0;
      }
      body,
      input,
      button {
        font-family: \"Helvetica Neue\", Helvetica, Arial, sans-serif;
      }

      .container { margin: 50px auto 40px auto; width: 600px; text-align: center; }

      a { color: #4183c4; text-decoration: none; }
      a:hover { text-decoration: underline; }

      h1 { letter-spacing: -1px; line-height: 60px; font-size: 60px; font-weight: 100; margin: 0px; text-shadow: 0 1px 0 #fff; }
      p { color: rgba(0, 0, 0, 0.5); margin: 10px 0 10px; font-size: 18px; font-weight: 200; line-height: 1.6em;}

      ul { margin: 25px 0; padding: 0; }
      li { font-weight: bold;  }

      .logo { display: inline-block; margin-top: 35px; }
      .logo-img-2x { display: none; }
      @media
      only screen and (-webkit-min-device-pixel-ratio: 2),
      only screen and (   min--moz-device-pixel-ratio: 2),
      only screen and (     -o-min-device-pixel-ratio: 2/1),
      only screen and (        min-device-pixel-ratio: 2),
      only screen and (                min-resolution: 192dpi),
      only screen and (                min-resolution: 2dppx) {
        .logo-img-1x { display: none; }
        .logo-img-2x { display: inline-block; }
      }

      #suggestions {
        margin-top: 35px;
        color: #ccc;
        text-align: left;
      }
      #suggestions a {
        color: #666666;
        font-weight: 200;
        font-size: 14px;
        margin: 0 10px;
      }

    </style>
  </head>
  <body>


    <div class=\"container\">
      <p><strong>You are logged in, but do not have permission for this application.</strong></p>

      <p>While you are logged in, you do not have permission to access this application. So, we cannot let you in.</p>


    <p style='text-align:left'>Some suggestions:</p>
    <ol style='text-align: left'>
    <li>If you have multiple logins, you can <a href='/logout'>Log Out</a> and login using the correct username.</li><li>You can <a href='mailto:itsupport@miraclemethod.com'>Contact itsupport@miraclemethod.com</a> for assistance.</li>


</ol>

    </div>
  </body>
</html>
";
        }else{
            return redirect($errorURL);
        }


    }

    /**
     * Keycloak callback page
     *
     * @throws KeycloakCallbackException
     *
     * @return view
     */
    public function callback(Request $request)
    {
        // Check for errors from Keycloak
        if (! empty($request->input('error'))) {
            $error = $request->input('error_description');
            $error = ($error) ?: $request->input('error');

            throw new KeycloakCallbackException($error);
        }

        // Check given state to mitigate CSRF attack
        $state = $request->input('state');
        if (empty($state) || ! KeycloakWeb::validateState($state)) {
            KeycloakWeb::forgetState();

            throw new KeycloakCallbackException('Invalid state');
        }

        // Change code for token
        $code = $request->input('code');
        if (! empty($code)) {
            $token = KeycloakWeb::getAccessToken($code);

            if (Auth::validate($token)) {
                $url = config('keycloak-web.redirect_url', '/admin');
                return redirect()->intended($url);
            }
        }

        return redirect(route('keycloak.login'));
    }
}
