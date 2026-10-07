<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Filters\Concerns;

use CodeIgniter\HTTP\IncomingRequest;
use CodeIgniter\HTTP\RequestInterface;
use CodeIgniter\HTTP\ResponseInterface;
use Ephraitech\Auth\Authentication\AuthManager;
use Ephraitech\Auth\Authentication\Guards\TokenGuard;
use Ephraitech\Auth\Support\IntendedUrl;

/**
 * Consistent failure responses for every auth filter:
 * JSON (401/403/400) for API and AJAX clients, redirects with a flash
 * message for browsers.
 */
trait HandlesAuthFailures
{
    protected function unauthenticated(RequestInterface $request, AuthManager $auth): ResponseInterface
    {
        if ($this->wantsJson($request, $auth)) {
            return service('response')
                ->setStatusCode(401)
                ->setHeader('WWW-Authenticate', 'Bearer')
                ->setJSON([
                    'status'  => 401,
                    'error'   => 'unauthenticated',
                    'message' => 'Authentication is required to access this resource.',
                ]);
        }

        if (
            $request instanceof IncomingRequest
            && strcasecmp($request->getMethod(), 'get') === 0
            && ! $request->isAJAX()
        ) {
            IntendedUrl::remember((string) $request->getUri());
        }

        return redirect()
            ->to($auth->config()->redirects['login'])
            ->with('error', 'Please sign in to continue.');
    }

    protected function forbidden(
        RequestInterface $request,
        AuthManager $auth,
        string $message = 'You do not have permission to perform this action.',
    ): ResponseInterface {
        if ($this->wantsJson($request, $auth)) {
            return service('response')
                ->setStatusCode(403)
                ->setJSON([
                    'status'  => 403,
                    'error'   => 'forbidden',
                    'message' => $message,
                ]);
        }

        return redirect()
            ->to($auth->config()->redirects['forbidden'])
            ->with('error', $message);
    }

    protected function badRequest(RequestInterface $request, AuthManager $auth, string $message): ResponseInterface
    {
        $response = service('response')->setStatusCode(400);

        if ($this->wantsJson($request, $auth)) {
            return $response->setJSON([
                'status'  => 400,
                'error'   => 'bad_request',
                'message' => $message,
            ]);
        }

        return $response->setBody(esc($message));
    }

    protected function wantsJson(RequestInterface $request, AuthManager $auth): bool
    {
        if (TokenGuard::extractFromRequest($auth->config(), $request) !== null) {
            return true;
        }

        if (! $request instanceof IncomingRequest) {
            return false;
        }

        return $request->isAJAX()
            || str_contains(strtolower($request->getHeaderLine('Accept')), 'application/json');
    }

    /**
     * @param array<int, string>|string|null $arguments
     *
     * @return list<string>
     */
    protected function normalizeArguments(array|string|null $arguments): array
    {
        return array_values(array_filter(
            array_map('trim', (array) $arguments),
            static fn(string $argument): bool => $argument !== ''
        ));
    }
}
