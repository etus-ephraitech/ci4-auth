<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Tests\Feature;

use CodeIgniter\HTTP\RedirectResponse;
use CodeIgniter\HTTP\ResponseInterface;
use Ephraitech\Auth\Filters\PermissionFilter;
use Ephraitech\Auth\Filters\RoleFilter;
use Ephraitech\Auth\Tests\Support\AuthTestCase;

/**
 * 'can:' and 'role:' imply sign-in, so routes need no separate 'auth'
 * filter; a leading 'session'/'token' argument pins the guard.
 */
final class PermissionFilterSignInTest extends AuthTestCase
{
    public function testCanAloneRedirectsAGuestToSignIn(): void
    {
        $this->useRequest();

        $result = (new PermissionFilter())->before(service('request'), ['users.view']);

        $this->assertInstanceOf(RedirectResponse::class, $result);
        $this->assertStringEndsWith('/login', $result->getHeaderLine('Location'));
    }

    public function testRoleAloneReturns401ForApiGuests(): void
    {
        $this->useRequest(['Accept' => 'application/json']);

        $result = (new RoleFilter())->before(service('request'), ['admin']);

        $this->assertInstanceOf(ResponseInterface::class, $result);
        $this->assertSame(401, $result->getStatusCode());
    }

    public function testPipeArgumentMeansAny(): void
    {
        $user = $this->createUser('a@example.com', ['admin']);
        $new  = service('authTokens')->issueSessionToken((int) $user->id, 'Test device');

        $this->useRequest(['Authorization' => 'Bearer ' . $new->plaintext]);

        $this->assertNull((new PermissionFilter())->before(service('request'), ['reports.view|users.view']));
    }

    public function testSessionPinRejectsABearerToken(): void
    {
        $user = $this->createUser('a@example.com', ['admin']);
        $new  = service('authTokens')->issueSessionToken((int) $user->id, 'Test device');

        $this->useRequest(['Authorization' => 'Bearer ' . $new->plaintext]);

        $pinned = (new PermissionFilter())->before(service('request'), ['session', 'users.view']);

        $this->assertInstanceOf(ResponseInterface::class, $pinned, 'a bearer token must not pass a session-pinned route');
        $this->assertSame(401, $pinned->getStatusCode());
    }

    public function testTokenPinAcceptsABearerToken(): void
    {
        $user = $this->createUser('a@example.com', ['admin']);
        $new  = service('authTokens')->issueSessionToken((int) $user->id, 'Test device');

        $this->useRequest(['Authorization' => 'Bearer ' . $new->plaintext]);

        $this->assertNull((new RoleFilter())->before(service('request'), ['token', 'admin']));
    }
}
