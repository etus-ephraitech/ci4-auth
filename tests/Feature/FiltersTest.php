<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Tests\Feature;

use CodeIgniter\HTTP\ResponseInterface;
use Ephraitech\Auth\Filters\AuthFilter;
use Ephraitech\Auth\Filters\PermissionFilter;
use Ephraitech\Auth\Filters\TenantFilter;
use Ephraitech\Auth\Tests\Support\AuthTestCase;

final class FiltersTest extends AuthTestCase
{
    public function testAuthFilterReturnsJson401WithoutAToken(): void
    {
        $this->useRequest(['Accept' => 'application/json']);

        $result = (new AuthFilter())->before(service('request'), ['token']);

        $this->assertInstanceOf(ResponseInterface::class, $result);
        $this->assertSame(401, $result->getStatusCode());
        $this->assertSame('Bearer', $result->getHeaderLine('WWW-Authenticate'));
    }

    public function testAuthFilterPassesWithAValidToken(): void
    {
        $user = $this->createUser();
        $new  = service('authTokens')->issueSessionToken((int) $user->id, 'Test device');

        $this->useRequest(['Authorization' => 'Bearer ' . $new->plaintext]);

        $this->assertNull((new AuthFilter())->before(service('request'), ['token']));
        $this->assertSame($user->id, service('auth')->id());
    }

    public function testRevokedTokenIsRejectedByTheFilter(): void
    {
        $user = $this->createUser();
        $new  = service('authTokens')->issueSessionToken((int) $user->id, 'Test device');

        service('authTokens')->revokePlaintext($new->plaintext);

        $this->useRequest(['Authorization' => 'Bearer ' . $new->plaintext]);

        $result = (new AuthFilter())->before(service('request'), ['token']);

        $this->assertInstanceOf(ResponseInterface::class, $result);
        $this->assertSame(401, $result->getStatusCode());
    }

    public function testPermissionFilterReturns403WithoutThePermission(): void
    {
        $user = $this->createUser('jane@example.com', ['user']);
        $new  = service('authTokens')->issueSessionToken((int) $user->id, 'Test device');

        $this->useRequest(['Authorization' => 'Bearer ' . $new->plaintext]);

        $result = (new PermissionFilter())->before(service('request'), ['users.view']);

        $this->assertInstanceOf(ResponseInterface::class, $result);
        $this->assertSame(403, $result->getStatusCode());
    }

    public function testPermissionFilterAnyMode(): void
    {
        $user = $this->createUser('jane@example.com', ['admin']);
        $new  = service('authTokens')->issueSessionToken((int) $user->id, 'Test device');

        $this->useRequest(['Authorization' => 'Bearer ' . $new->plaintext]);

        $this->assertNull(
            (new PermissionFilter())->before(service('request'), ['any', 'tokens.manage', 'users.view'])
        );
    }

    public function testTenantFilterRejectsATokenBoundToAnotherTenant(): void
    {
        $this->authConfig->tenancy = 'multi';

        $user = $this->createUser();
        service('authAuthorizer')->assignRole($user, 'admin', 'school-a');

        $new = service('authTokens')->issueSessionToken((int) $user->id, 'Test device', null, 'school-a');

        $this->useRequest([
            'Authorization' => 'Bearer ' . $new->plaintext,
            'X-Tenant-ID'   => 'school-b',
        ]);

        $result = (new TenantFilter())->before(service('request'));

        $this->assertInstanceOf(ResponseInterface::class, $result);
        $this->assertSame(403, $result->getStatusCode());
    }

    public function testTenantFilterRejectsUsersWithoutMembership(): void
    {
        $this->authConfig->tenancy = 'multi';

        $user = $this->createUser('jane@example.com', []);
        service('authAuthorizer')->assignRole($user, 'admin', 'school-a');

        $new = service('authTokens')->issueSessionToken((int) $user->id, 'Test device');

        $this->useRequest([
            'Authorization' => 'Bearer ' . $new->plaintext,
            'X-Tenant-ID'   => 'school-b',
        ]);

        $result = (new TenantFilter())->before(service('request'));

        $this->assertInstanceOf(ResponseInterface::class, $result);
        $this->assertSame(403, $result->getStatusCode());
    }
}
