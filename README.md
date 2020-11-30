# LumenOauth2

## Introduction

Lumen Oauth2 provides a simple API to authenticate your Lumen api with an Openid/Oauth2 server.

## Installation

### Via composer
Run `composer require ecmxperts/lumenoauth2 0.*`

## Usage

In your `.env` add the following Environment Variable
```
IDENTITY_URL=openid/oauth2 server address
```

In your `app\Providers\AuthServiceProvider.php` inside the boot method add the following lines
```
$this->app['auth']->viaRequest('api', function ($request) {
    if (($token = $request->bearerToken()) != null) {
        try {
            return LumenOauth2::setProviderUrl(env('IDENTITY_URL'))
                ->setAudience('expected audience')
                ->authenticate($token);
        } catch (LumenOauth2Exception $e) {
            Log::error($e, ['exception' => $e]);
        }
    }
});
```

See [Lumen Authentication](https://lumen.laravel.com/docs/6.x/authentication) for the rest on Authentication

The following methods can be used to access the authenticated user properties:
* The global identifier for the user.
```
    $userGuid = Auth::user()->guid();

    $userGuid = $request->user()->guid();
```
* The firstname for the user.
```
    $firstname = Auth::user()->firstname();

    $firstname = $request->user()->firstname();
```
* The surname for the user.
```
    $surname = Auth::user()->surname();

    $surname = $request->user()->surname();
```
* The fullname for the user.
```
    $fullname = Auth::user()->fullname();

    $fullname = $request->user()->fullname();
```
* The tenant global identifier for the user.
```
    $tenant = Auth::user()->tenant();

    $tenant = $request->user()->tenant();
```
