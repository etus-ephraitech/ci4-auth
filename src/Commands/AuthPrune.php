<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Commands;

use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\CLI;
use Ephraitech\Auth\Commands\Concerns\InteractsWithAuth;
use Throwable;

class AuthPrune extends BaseCommand
{
    use InteractsWithAuth;

    protected $group       = 'Ephraitech Auth';
    protected $name        = 'auth:prune';
    protected $description = 'Deletes stale tokens, old login attempts and expired one-time codes. Safe to run daily from cron.';
    protected $usage       = 'auth:prune [--tokens-days=7]';
    protected $options     = [
        '--tokens-days' => 'Delete tokens revoked/expired more than N days ago (default 7).',
    ];

    /**
     * @param array<int|string, string|null> $params
     */
    public function run(array $params)
    {
        $days = $this->option($params, 'tokens-days') ?? '7';

        if (! ctype_digit($days)) {
            CLI::error('--tokens-days must be a whole number.');

            return EXIT_ERROR;
        }

        // try {
        //     $tokens   = service('authTokens')->pruneStale((int) $days);
        //     $attempts = service('authThrottle')->prune();
        // } catch (Throwable $e) {
        //     CLI::error('Prune failed: ' . $e->getMessage());

        //     return EXIT_ERROR;
        // }

        // CLI::write("Deleted {$tokens} stale token(s) and {$attempts} old login attempt(s).", 'green');


        try {
            $tokens   = service('authTokens')->pruneStale((int) $days);
            $attempts = service('authThrottle')->prune();
            $codes    = service('authOneTimeCodes')->prune();
        } catch (Throwable $e) {
            CLI::error('Prune failed: ' . $e->getMessage());

            return EXIT_ERROR;
        }

        CLI::write(
            "Deleted {$tokens} stale token(s), {$attempts} old login attempt(s) and {$codes} expired code(s).",
            'green'
        );
        return EXIT_SUCCESS;
    }
}
