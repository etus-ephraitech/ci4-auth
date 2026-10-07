<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Api;

use DateTimeInterface;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Entities\AccessToken;
use Ephraitech\Auth\Entities\User;
use stdClass;

/**
 * Default API representation of a user.
 *
 * Permissions are filtered through the token's abilities, so a client
 * sees exactly what this token can do, not everything the user can.
 */
final class UserTransformer implements UserTransformerInterface
{
    public function __construct(private readonly Auth $config) {}

    public function transform(User $user, ?AccessToken $token = null): array
    {
        $authorizer = service('authAuthorizer');
        $tenant     = $token?->tenant();

        $identifiers = [];

        foreach ($user->getIdentities() as $type => $identity) {
            $identifiers[$type] = [
                'value'    => $identity->identifier,
                'verified' => $identity->isVerified(),
            ];
        }

        $profile = [];

        foreach ($this->config->userAllowedFields as $field) {
            $profile[$field] = $this->scalar($user->{$field});
        }

        $permissions = $authorizer->permissionsFor($user, $tenant);

        if ($token !== null) {
            $permissions = array_values(array_filter(
                $permissions,
                static fn(string $permission): bool => $token->allows($permission)
            ));
        }

        return [
            'id'            => $user->id,
            'uuid'          => $user->uuid,
            'status'        => $user->status,
            'identifiers'   => $identifiers === [] ? new stdClass() : $identifiers,
            'profile'       => $profile === [] ? new stdClass() : $profile,
            'roles'         => $authorizer->rolesFor($user, $tenant),
            'permissions'   => $permissions,
            'last_login_at' => $this->scalar($user->last_login_at),
            'created_at'    => $this->scalar($user->created_at),
        ];
    }

    private function scalar(mixed $value): mixed
    {
        return $value instanceof DateTimeInterface ? $value->format(DATE_ATOM) : $value;
    }
}
