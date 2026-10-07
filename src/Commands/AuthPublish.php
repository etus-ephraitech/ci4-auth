<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Commands;

use CodeIgniter\CLI\BaseCommand;
use CodeIgniter\CLI\CLI;
use Ephraitech\Auth\Commands\Concerns\InteractsWithAuth;
use Ephraitech\Auth\Config\Auth as BaseAuth;

class AuthPublish extends BaseCommand
{
    use InteractsWithAuth;

    /**
     * Properties most projects customise, written with current defaults.
     *
     * @var array<string, string> property => declared type
     */
    private const PUBLISHED = [
        'identifiers'             => 'array',
        'loginIdentifiers'        => 'array',
        'requiredIdentifiers'     => 'array',
        'requireVerifiedToLogin'  => 'array',
        'userAllowedFields'       => 'array',
        'phoneDefaultCountryCode' => 'string',
        'tenancy'                 => 'string',
        'defaultRoles'            => 'array',
        'roles'                   => 'array',
        'permissions'             => 'array',
        'matrix'                  => 'array',
        'redirects'               => 'array',
    ];

    protected $group       = 'Ephraitech Auth';
    protected $name        = 'auth:publish';
    protected $description = 'Creates app/Config/Auth.php to customise Ephraitech Auth.';
    protected $usage       = 'auth:publish [--force]';
    protected $options     = [
        '--force' => 'Overwrite an existing app/Config/Auth.php.',
    ];

    /**
     * @param array<int|string, string|null> $params
     */
    public function run(array $params)
    {
        $path = APPPATH . 'Config' . DIRECTORY_SEPARATOR . 'Auth.php';

        if (is_file($path) && ! $this->hasOption($params, 'force')) {
            CLI::error('app/Config/Auth.php already exists. Use --force to overwrite it.');

            return EXIT_ERROR;
        }

        if (file_put_contents($path, $this->render(new BaseAuth())) === false) {
            CLI::error("Could not write {$path}. Check directory permissions.");

            return EXIT_ERROR;
        }

        CLI::write('Created app/Config/Auth.php', 'green');
        CLI::write('Next: adjust it, run "php spark migrate -n Ephraitech\\\\Auth", then "php spark auth:sync".');

        return EXIT_SUCCESS;
    }

    private function render(BaseAuth $defaults): string
    {
        $properties = [];

        foreach (self::PUBLISHED as $name => $type) {
            $properties[] = "    public {$type} \${$name} = " . $this->export($defaults->{$name}) . ';';
        }

        $body = implode("\n\n", $properties);

        return <<<PHP
            <?php

            namespace Config;

            use Ephraitech\\Auth\\Config\\Auth as BaseAuth;

            /**
             * Ephraitech Auth settings for this application.
             *
             * Only properties declared here override the package defaults.
             * Every option is documented in vendor/ephraitech/ci4-auth/src/Config/Auth.php;
             * copy any other property here to change it.
             *
             * After changing \$roles, \$permissions or \$matrix, run: php spark auth:sync
             */
            class Auth extends BaseAuth
            {
            {$body}
            }

            PHP;
    }

    private function export(mixed $value, int $depth = 1): string
    {
        if ($value === null) {
            return 'null';
        }

        if (! is_array($value)) {
            return var_export($value, true);
        }

        if ($value === []) {
            return '[]';
        }

        $pad   = str_repeat('    ', $depth + 1);
        $close = str_repeat('    ', $depth);
        $list  = array_is_list($value);
        $lines = [];

        foreach ($value as $key => $item) {
            $lines[] = $pad . ($list ? '' : var_export($key, true) . ' => ') . $this->export($item, $depth + 1) . ',';
        }

        return "[\n" . implode("\n", $lines) . "\n" . $close . ']';
    }
}
