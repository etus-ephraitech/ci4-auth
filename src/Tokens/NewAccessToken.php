<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Tokens;

use Ephraitech\Auth\Entities\AccessToken;

/**
 * Returned once, at issue time. This is the ONLY moment the plaintext
 * token exists; hand it to the client and discard it.
 */
final class NewAccessToken
{
    public function __construct(
        public readonly AccessToken $token,
        public readonly string $plaintext,
    ) {}

    /**
     * Shape suitable for an API login/issue response.
     *
     * @return array{token: string, token_type: string, type: string|null, name: string|null, abilities: list<string>, expires_at: string|null}
     */
    public function toArray(): array
    {
        return [
            'token'      => $this->plaintext,
            'token_type' => 'Bearer',
            'type'       => $this->token->type,
            'name'       => $this->token->name,
            'abilities'  => $this->token->abilityList(),
            'expires_at' => $this->token->expires_at?->toDateTimeString(),
        ];
    }
}
