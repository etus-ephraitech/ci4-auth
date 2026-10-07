<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Commands;

use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\CLI;
use Ephraitech\Auth\Commands\Concerns\InteractsWithAuth;
use Ephraitech\Auth\Exceptions\AuthException;

class AuthToken extends BaseCommand
{
    use InteractsWithAuth;

    private const ACTIONS = ['issue', 'list', 'revoke', 'revoke-all'];

    protected $group       = 'Ephraitech Auth';
    protected $name        = 'auth:token';
    protected $description = 'Issues, lists and revokes API keys and session tokens.';
    protected $usage       = "auth:token issue <user> <name> [--abilities=a,b] [--days=N] [--tenant=]\n"
        . "    auth:token list <user> [--type=session|api_key]\n"
        . "    auth:token revoke <token-id>\n"
        . '    auth:token revoke-all <user> [--type=session|api_key]';
    protected $options = [
        '--abilities' => 'Comma-separated abilities, e.g. reports.view,orders.* (default: Config\Auth).',
        '--days'      => 'API key lifetime in days (default: Config\Auth::$apiKeyLifetime).',
        '--tenant'    => 'Bind the key to a tenant (multi-tenant mode).',
        '--type'      => 'Filter by token type: session or api_key.',
    ];

    /**
     * @param array<int|string, string|null> $params
     */
    public function run(array $params)
    {
        $action = $params[0] ?? null;

        if (! in_array($action, self::ACTIONS, true)) {
            CLI::error('Action must be one of: ' . implode(', ', self::ACTIONS) . '.');
            CLI::write('Usage: ' . $this->usage);

            return EXIT_ERROR;
        }

        try {
            return match ($action) {
                'issue'      => $this->issue($params),
                'list'       => $this->list($params),
                'revoke'     => $this->revoke($params),
                'revoke-all' => $this->revokeAll($params),
            };
        } catch (AuthException $e) {
            CLI::error($e->getMessage());

            return EXIT_ERROR;
        }
    }

    /**
     * @param array<int|string, string|null> $params
     */
    private function issue(array $params): int
    {
        $user = $this->resolveUser($params[1] ?? null);
        $name = trim((string) ($params[2] ?? ''));

        if ($user === null || $name === '') {
            CLI::error('Usage: auth:token issue <user> <name> [--abilities=] [--days=] [--tenant=]');

            return EXIT_ERROR;
        }

        $lifetime = null;
        $days     = $this->option($params, 'days');

        if ($days !== null) {
            if (! ctype_digit($days) || (int) $days < 1) {
                CLI::error('--days must be a positive whole number.');

                return EXIT_ERROR;
            }

            $lifetime = (int) $days * 86400;
        }

        $new = service('authTokens')->issueApiKey(
            (int) $user->id,
            $name,
            $this->listOption($params, 'abilities'),
            $this->tenantOption($params),
            $lifetime
        );

        CLI::write('API key issued for ' . $this->describeUser($user) . " (token #{$new->token->id}).", 'green');
        CLI::write('Abilities: ' . implode(', ', $new->token->abilityList()));
        CLI::write('Expires:   ' . ($new->token->expires_at?->toDateTimeString() ?? 'never'));
        CLI::newLine();
        CLI::write('Key (shown once, store it now):', 'yellow');
        CLI::write($new->plaintext, 'light_green');

        return EXIT_SUCCESS;
    }

    /**
     * @param array<int|string, string|null> $params
     */
    private function list(array $params): int
    {
        $user = $this->resolveUser($params[1] ?? null);

        if ($user === null) {
            CLI::error('User not found: ' . ($params[1] ?? '(none given)'));

            return EXIT_ERROR;
        }

        $tokens = service('authTokens')->listForUser((int) $user->id, $this->option($params, 'type'));

        if ($tokens === []) {
            CLI::write('No active tokens for ' . $this->describeUser($user) . '.');

            return EXIT_SUCCESS;
        }

        $rows = [];

        foreach ($tokens as $token) {
            $rows[] = [
                (string) $token->id,
                (string) $token->type,
                (string) $token->name,
                implode(',', $token->abilityList()),
                $token->last_used_at?->toDateTimeString() ?? 'never',
                $token->expires_at?->toDateTimeString() ?? 'never',
                $token->created_at?->toDateTimeString() ?? '-',
            ];
        }

        CLI::table($rows, ['ID', 'Type', 'Name', 'Abilities', 'Last used', 'Expires', 'Created']);

        return EXIT_SUCCESS;
    }

    /**
     * @param array<int|string, string|null> $params
     */
    private function revoke(array $params): int
    {
        $id = (string) ($params[1] ?? '');

        if (! ctype_digit($id)) {
            CLI::error('Usage: auth:token revoke <token-id>');

            return EXIT_ERROR;
        }

        if (! service('authTokens')->revoke((int) $id)) {
            CLI::error("Token #{$id} not found or already revoked.");

            return EXIT_ERROR;
        }

        CLI::write("Token #{$id} revoked.", 'green');

        return EXIT_SUCCESS;
    }

    /**
     * @param array<int|string, string|null> $params
     */
    private function revokeAll(array $params): int
    {
        $user = $this->resolveUser($params[1] ?? null);

        if ($user === null) {
            CLI::error('User not found: ' . ($params[1] ?? '(none given)'));

            return EXIT_ERROR;
        }

        $revoked = service('authTokens')->revokeAllForUser((int) $user->id, $this->option($params, 'type'));

        CLI::write('Revoked ' . count($revoked) . ' token(s) for ' . $this->describeUser($user) . '.', 'green');

        return EXIT_SUCCESS;
    }
}
