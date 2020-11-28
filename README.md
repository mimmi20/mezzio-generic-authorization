# mezzio-generic-authorization

[![Code Coverage](https://codecov.io/gh/mimmi20/mezzio-generic-authorization/branch/master/graph/badge.svg)](https://codecov.io/gh/mimmi20/mezzio-generic-authorization)

[![Latest Stable Version](https://poser.pugx.org/mimmi20/mezzio-generic-authorization/v/stable)](https://packagist.org/packages/mimmi20/mezzio-generic-authorization)
[![Total Downloads](https://poser.pugx.org/mimmi20/mezzio-generic-authorization/downloads)](https://packagist.org/packages/mimmi20/mezzio-generic-authorization)

# Introduction

This component provides middleware for [Mezzio](https://github.com/mezzio/mezzio)
and [PSR-7](https://www.php-fig.org/psr/psr-7/) applications for authorizing
specific routes based on [ACL](https://en.wikipedia.org/wiki/Access_control_list)
or [RBAC](https://en.wikipedia.org/wiki/Role-based_access_control) systems.

Unlike in [mezzio-authorization](https://github.com/mezzio/mezzio-authorization) this library does not require
the `ServerRequestInterface` by default. This makes it possible to use this component in combination with [mezzio-navigation](https://github.com/mimmi20/mezzio-navigation).

If you are using the provided midleware, the **route name** is used as the resource.

## Installation

You can install the mezzio-generic-authorization library with
[Composer](https://getcomposer.org):

```bash
$ composer require mimmi20/mezzio-generic-authorization
```

# Introduction

This component provides authorization middleware for [PSR-7](https://www.php-fig.org/psr/psr-7/)
and [PSR-15](https://www.php-fig.org/psr/psr-15/) applications.

An authorization system first needs authentication: to verify that an identity
has access to something (i.e., is authorized) we first need the _identity_, which
is provided during authentication.

Authentication is provided via the package
[mezzio-authentication](https://docs.mezzio.dev/mezzio-authentication/).
That library provides an `AuthenticationMiddleware` class that verify
credentials using the HTTP request, and stores the identity via a
[PSR-7 request attribute](https://docs.mezzio.dev/mezzio/v3/cookbook/passing-data-between-middleware/).

The identity generated by mezzio-authentication is stored as the
request attribute `Mezzio\Authentication\UserInterface` as a
`UserInterface` implementation. That interface looks like the following:

```php
namespace Mezzio\Authentication;

interface UserInterface
{
    /**
     * Get the unique user identity (id, username, email address or ...)
     */
    public function getIdentity() : string;

    /**
     * Get all user roles
     *
     * @return Iterable
     */
    public function getRoles() : iterable;

    /**
     * Get a detail $name if present, $default otherwise
     */
    public function getDetail(string $name, $default = null);

    /**
     * Get all the details, if any
     */
    public function getDetails() : array;
}
```

mezzio-generic-authorization consumes this identity attribute.  It checks if a
user's role (as retrieved from the `UserInterface` object) is authorized
(granted) to the perform the current HTTP request.

Authorization is performed using the `isGranted()` method of the AuthorizationInterface

```php
public function isGranted(string $role, string $resource, ?string $privilege = null, ?\Psr\Http\Message\ServerRequestInterface\ServerRequestInterface $request = null): bool;
```

Two adapters are available:

- [mezzio-generic-authorization-rbac](https://github.com/mimmi20/mezzio-generic-authorization-rbac/),
  which implements Role-Based Access Controls ([RBAC](https://en.wikipedia.org/wiki/Role-based_access_control))
- [mezzio-generic-authorization-acl](https://github.com/mimmi20/mezzio-generic-authorization-acl/),
  which implements an Access Control List ([ACL](https://en.wikipedia.org/wiki/Access_control_list)).

> If you want to know more about authentication using middleware in PHP,
> we suggest reading the blog post ["Authorize users using Middleware"](https://framework.zend.com/blog/2017-05-04-authorization-middleware.html).

# Authorization adapters

You can configure the authorization adapter to use via your service container
configuration. Specifically, you can either map the service name
`Mezzio\GenericAuthorization\AuthorizationInterface` to a factory, or alias it
to the appropriate service.

For instance, using [Mezzio container configuration](https://docs.mezzio.dev/mezzio/v3/features/container/config/),
you could select the mezzio-authorization-acl adapter in either of the
following ways:

- Using an alias:
  ```php
  use Mezzio\GenericAuthorization\AuthorizationInterface;
  use Mezzio\GenericAuthorization\Acl\LaminasAcl;
  
  return [
      'dependencies' => [
          // Using an alias:
          'aliases' => [
              AuthorizationInterface::class => LaminasAcl::class,
          ],
      ],
  ];
  ```

- Mapping to a factory:
  ```php
  use Mezzio\GenericAuthorization\AuthorizationInterface;
  use Mezzio\GenericAuthorization\Acl\LaminasAclFactory;
  
  return [
      'dependencies' => [
          // Using a factory:
          'factories' => [
              AuthorizationInterface::class => LaminasAclFactory::class,
          ],
      ],
  ];
  ```

We provide two different adapters.

- The RBAC adapter is provided by [mezzio-generic-authorization-rbac](https://github.com/mimmi20/mezzio-generic-authorization-rbac/).
- The ACL adapter is provided by [mezzio-generic-authorization-acl](https://github.com/mimmi20/mezzio-generic-authorization-acl/).

Each adapter is installable via [Composer](https://getcomposer.org):

```bash
$ composer require mimmi20/mezzio-generic-authorization-rbac
# or
$ composer require mimmi20/mezzio-generic-authorization-acl
```

## License

This package is licensed using the MIT License.

Please have a look at [`LICENSE.md`](LICENSE.md).
