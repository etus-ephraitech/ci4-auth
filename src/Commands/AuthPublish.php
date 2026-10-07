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
    protected $usage   = 'auth:publish [--views] [--force]';
    protected $options = [
        '--views' => 'Copy the auth page views into app/Views/auth/ instead of publishing config.',
        '--force' => 'Overwrite existing files.',
    ];

    /**
     * @param array<int|string, string|null> $params
     */
    public function run(array $params)
    {
        $path = APPPATH . 'Config' . DIRECTORY_SEPARATOR . 'Auth.php';

        if ($this->hasOption($params, 'views')) {
            return $this->publishViews($this->hasOption($params, 'force'));
        }

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

    private function publishViews(bool $force): int
    {
        $source      = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'Views';
        $destination = APPPATH . 'Views' . DIRECTORY_SEPARATOR . 'auth';

        if (! is_dir($destination) && ! mkdir($destination, 0755, true) && ! is_dir($destination)) {
            CLI::error("Could not create {$destination}.");

            return EXIT_ERROR;
        }

        $files = glob($source . DIRECTORY_SEPARATOR . '*.php') ?: [];

        foreach ($files as $file) {
            $target = $destination . DIRECTORY_SEPARATOR . basename($file);

            if (is_file($target) && ! $force) {
                CLI::write('Skipped (exists): app/Views/auth/' . basename($file), 'yellow');

                continue;
            }

            if (! copy($file, $target)) {
                CLI::error('Could not copy ' . basename($file) . '.');

                return EXIT_ERROR;
            }

            CLI::write('Copied: app/Views/auth/' . basename($file), 'green');
        }

        CLI::newLine();
        CLI::write('Now point Config\Auth at the copies:', 'yellow');
        CLI::write("    public string \$viewLayout = 'auth/layout';   // or your own layout");
        CLI::write('    public array $views = [');

        foreach (BaseAuth::viewKeys() as $key) {
            $file = $key === 'messages' ? '_messages' : $key;
            CLI::write("        '{$key}' => 'auth/{$file}',");
        }

        CLI::write('    ];');

        return EXIT_SUCCESS;
    }
}
