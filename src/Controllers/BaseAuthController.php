<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Controllers;

use Closure;
use CodeIgniter\Config\Factories;
use CodeIgniter\Controller;
use CodeIgniter\HTTP\IncomingRequest;
use CodeIgniter\HTTP\RedirectResponse;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use Ephraitech\Auth\Authentication\Guards\SessionGuard;
use Ephraitech\Auth\Config\Auth;
use Ephraitech\Auth\Entities\User;
use Ephraitech\Auth\Exceptions\AuthException;
use Ephraitech\Auth\Exceptions\NotificationException;
use Ephraitech\Auth\Exceptions\ResendTooSoonException;
use Ephraitech\Auth\Models\UserModel;
use Ephraitech\Auth\Support\Mask;
use Ephraitech\Auth\Support\PendingVerification;
use Psr\Log\LoggerInterface;

/**
 * Shared plumbing for the auth pages.
 *
 * Re-displayed values travel in a flash 'old' array containing only safe
 * fields, never CodeIgniter's withInput(), which would copy the submitted
 * password into the session.
 *
 * @property IncomingRequest $request
 */
abstract class BaseAuthController extends Controller
{
    protected $helpers = ['form', 'url'];

    protected Auth $authConfig;

    public function initController(RequestInterface $request, ResponseInterface $response, LoggerInterface $logger): void
    {
        parent::initController($request, $response, $logger);

        $auth = service('auth');
        $auth->shouldUse(SessionGuard::NAME);

        $this->authConfig = $auth->config();
    }

    /**
     * @param array<string, mixed> $data
     */
    protected function render(string $view, string $pageTitle, array $data = []): string
    {
        $views = [];

        foreach (Auth::viewKeys() as $key) {
            $views[$key] = $this->authConfig->view($key);
        }

        return view($this->authConfig->view($view), array_merge([
            'authLayout'  => $this->authConfig->viewLayout,
            'authSection' => $this->authConfig->viewSection,
            'authViews'   => $views,
            'authConfig'  => $this->authConfig,
            'pageTitle'   => $pageTitle,
            'canRegister' => $this->authConfig->allowRegistration && $this->routeExists('auth.register'),
            'canReset'    => $this->routeExists('auth.forgot'),
            'old'         => session('old') ?? [],
            'errors'      => session('errors') ?? [],
        ], $data));
    }

    protected function sessionGuard(): SessionGuard
    {
        return service('auth')->session();
    }

    protected function users(): UserModel
    {
        /** @var UserModel $users */
        $users = Factories::models($this->authConfig->userModel, ['preferApp' => false]);

        return $users;
    }

    protected function post(string $key): string
    {
        $value = $this->request->getPost($key);

        return is_string($value) ? $value : '';
    }

    protected function query(string $key): string
    {
        $value = $this->request->getGet($key);

        return is_string($value) ? $value : '';
    }

    protected function ip(): string
    {
        return $this->request->getIPAddress();
    }

    protected function routeExists(string $name): bool
    {
        return route_to($name) !== false;
    }

    /**
     * @param array<string, string> $errors field => message
     * @param array<string, string> $old    safe values to re-display
     */
    protected function backWithErrors(array $errors, array $old = []): RedirectResponse
    {
        return redirect()->back()->with('errors', $errors)->with('old', $old);
    }

    /**
     * @param array<string, string> $old
     */
    protected function backWithError(string $message, array $old = []): RedirectResponse
    {
        return redirect()->back()->with('error', $message)->with('old', $old);
    }

    /**
     * @param array<string, array{label: string, rules: string}> $rules
     */
    protected function validatePost(array $rules): bool
    {
        return $this->validateData((array) $this->request->getPost(), $rules);
    }

    /**
     * @return array<string, string>
     */
    protected function validationErrors(): array
    {
        return $this->validator?->getErrors() ?? [];
    }

    protected function resetLinkBuilder(): Closure
    {
        return static fn(string $selector, string $code): string
        => url_to('auth.reset') . '?' . http_build_query(['s' => $selector, 'c' => $code]);
    }

    protected function verifyLinkBuilder(): ?Closure
    {
        if (! $this->routeExists('auth.verify.link')) {
            return null;
        }

        return static fn(string $selector, string $code): string
        => url_to('auth.verify.link') . '?' . http_build_query(['s' => $selector, 'c' => $code]);
    }

    /**
     * Park the user as pending verification, send a code, and go to the
     * verification page. Used after login and after registration.
     */
    protected function startVerification(int $userId, string $type): RedirectResponse
    {
        PendingVerification::put($userId, $type);

        $user = $this->users()->find($userId);

        if (! $user instanceof User) {
            PendingVerification::clear();

            return redirect()->route('auth.login')->with('error', 'Please sign in again.');
        }

        try {
            service('authVerification')->send($user, $type, $this->ip(), $this->verifyLinkBuilder());

            $identity = $user->refreshIdentities()->getIdentity($type);
            $message  = 'We sent a verification code to '
                . Mask::identifier($type, (string) $identity?->identifier) . '.';
        } catch (ResendTooSoonException) {
            $message = 'Enter the verification code we sent you.';
        } catch (NotificationException $e) {
            log_message('error', 'Ephraitech Auth: verification code not sent: {message}', ['message' => $e->getMessage()]);

            return redirect()->route('auth.verify')
                ->with('error', 'We could not send a verification code right now. Please try again shortly.');
        } catch (AuthException $e) {
            return redirect()->route('auth.verify')->with('error', $e->getMessage());
        }

        return redirect()->route('auth.verify')->with('message', $message);
    }

    /**
     * "Email", "Email or phone number", "Email, username or phone number".
     */
    protected function loginLabel(): string
    {
        $labels = [
            Auth::IDENTIFIER_EMAIL    => 'email',
            Auth::IDENTIFIER_USERNAME => 'username',
            Auth::IDENTIFIER_PHONE    => 'phone number',
        ];

        $parts = array_map(
            static fn(string $type): string => $labels[$type] ?? $type,
            $this->authConfig->loginIdentifiers
        );

        $text = count($parts) === 1
            ? $parts[0]
            : implode(', ', array_slice($parts, 0, -1)) . ' or ' . end($parts);

        return ucfirst($text);
    }
}
