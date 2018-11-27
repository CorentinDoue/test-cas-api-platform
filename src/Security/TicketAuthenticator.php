<?php
/**
 * Created by PhpStorm.
 * User: douec
 * Date: 21/11/2018
 * Time: 12:47
 */

namespace App\Security;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class TicketAuthenticator extends AbstractGuardAuthenticator
{
    private $em;
    private $logger;

    public function __construct(EntityManagerInterface $em, LoggerInterface $logger)
    {
        $this->em = $em;
        $this->logger = $logger;
    }

    /**
     * Called on every request to decide if this authenticator should be
     * used for the request. Returning false will cause this authenticator
     * to be skipped.
     * @param Request $request
     * @return bool
     */
    public function supports(Request $request)
    {
        return 'login' === $request->attributes->get('_route') && $request->isMethod('POST');
    }

    /**
     * Called on every request. Return whatever credentials you want to
     * be passed to getUser() as $credentials.
     * @param Request $request
     * @return array
     */
    public function getCredentials(Request $request)
    {
        $this->logger->info('Getting credential');
        return array(
            'service' => $request->request->get('service'),
            'ticket' => $request->request->get('ticket'),
        );
    }

    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        if(!isset($_SESSION)) session_start();
        $uid = $_SESSION['phpCAS']['attributes']['uid'];

        if (null === $uid) {
            return null;
        }

        $this->logger->info('Getting User with uid : '.$_SESSION['phpCAS']['attributes']['uid']);
        // if a User object, checkCredentials() is called
        return $this->em->getRepository(User::class)
            ->findOneBy(['login' => $uid]);
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        $this->logger->info('Checking credential');
        if(!isset($_SESSION)) session_start();
        \phpCAS::setDebug(false);
        $this->logger->info('First call to phpCAS ok');
        \phpCAS::client(CAS_VERSION_2_0, 'cas.emse.fr', 443, '');
        \phpCAS::setNoCasServerValidation();
        // check credentials - e.g. make sure the password is valid
        // no credential check is needed in this case

        // return true to cause authentication success
        $this->logger->info('Checked credential with uid : '.$_SESSION['phpCAS']['attributes']['uid']);
        return \phpCAS::isAuthenticated();
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        // on success, send back a token
        if(!isset($_SESSION)) session_start();
        $data = array(
            "bearer" => $_SESSION['phpCAS']['attributes']['uid']
        );
        $this->logger->info('AuthenticatedSuccessfully with uid : '.$_SESSION['phpCAS']['attributes']['uid']);
        return new JsonResponse($data, Response::HTTP_ACCEPTED);
}

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        $data = array(
            'message' => strtr($exception->getMessageKey(), $exception->getMessageData())

            // or to translate this message
            // $this->translator->trans($exception->getMessageKey(), $exception->getMessageData())
        );

        return new JsonResponse($data, Response::HTTP_FORBIDDEN);
    }

    /**
     * Called when authentication is needed, but it's not sent
     */
    public function start(Request $request, AuthenticationException $authException = null)
    {
        $data = array(
            // you might translate this message
            'message' => 'Authentication Required'
        );

        return new JsonResponse($data, Response::HTTP_UNAUTHORIZED);
    }

    public function supportsRememberMe()
    {
        return false;
    }
}