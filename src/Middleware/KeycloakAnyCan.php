<?php

namespace Vizir\KeycloakWebGuard\Middleware;

use Closure;
use Illuminate\Support\Facades\Auth;
use Vizir\KeycloakWebGuard\Exceptions\KeycloakCanException;

class KeycloakAnyCan extends KeycloakAuthenticated
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string|null  $guard
     * @return mixed
     */
    public function handle($request, Closure $next, ...$guards)
    {
        if (empty($guards) && Auth::check()) {
            return $next($request);
        }

        $guards = explode('|', ($guards[0] ?? ''));
        if (Auth::hasAnyRole($guards)) {
            return $next($request);
        }

        if (Auth::check()){
            throw new KeycloakCanException(
                'Not enough permissions to access this application.', $guards, $this->redirectNotEnoughPermissions($request)
            );
        }else {
            throw new KeycloakCanException(
                'Unauthenticated.', $guards, $this->redirectTo($request)
            );
        }
    }
}
