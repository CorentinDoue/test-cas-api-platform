<?php

namespace App\Controller;

use Lexik\Bundle\JWTAuthenticationBundle\Encoder\JWTEncoderInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Exception\JWTEncodeFailureException;
use Psr\Log\LoggerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use App\Entity\User;
use App\Repository\UserCustomRepository;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;
use Symfony\Component\Serializer\Encoder\JsonEncoder;
use Symfony\Component\Serializer\Encoder\XmlEncoder;
use Symfony\Component\Serializer\Normalizer\ObjectNormalizer;
use Symfony\Component\Serializer\Serializer;

class DefaultController extends AbstractController
{
    private $logger;
    private $jwtEncoder;

    public function __construct(LoggerInterface $logger, JWTEncoderInterface $jwtEncoder)
    {
        $this->logger = $logger;
        $this->jwtEncoder = $jwtEncoder;
    }

    public function index()
    {

        return new Response('There is nothing here');

    }

    public function login(Request $request)
    {
        if(!isset($_SESSION)) session_start();

        $credentials = array(
            'service' => $request->query->get('service'),
            'ticket' => $request->query->get('ticket'),
        );
        $this->logger->info('got credentials');
        // ini_set('session.use_cookies', 0);
        \phpCAS::setDebug(false);
        $this->logger->info('First call to phpCAS ok');
        \phpCAS::client(CAS_VERSION_2_0, 'cas.emse.fr', 443, '');
        \phpCAS::setNoCasServerValidation();
        // check credentials - e.g. make sure the password is valid
        // no credential check is needed in this case

        // return true to cause authentication success
//        \phpCAS::forceAuthentication();
        //$auth = \phpCAS::checkAuthentication();
        //$auth = false;
        if (isset($credentials['service'])) {
            // TODO whitelist service allowed
            \phpCAS::setFixedServiceURL($credentials['service']);
            \phpCAS::setNoClearTicketsFromUrl(); // removing ticket from url uses redirect which we can't do
        }

        if (\phpCAS::isAuthenticated()) {
             $this->logger->info('Checked credential with uid : '.$_SESSION['phpCAS']['attributes']['uid']);
             $jwt_data = [];
             $jwt_data['username'] = $_SESSION['phpCAS']['attributes']['uid'];
             try {
                 $jwt = $this->jwtEncoder->encode($jwt_data);
                 $data = array(
                     "bearer" => $jwt
                 );
             } catch (JWTEncodeFailureException $e) {
                 $this->logger->error($e->getMessage());
                 session_destroy();
                 return new Response("Unauthorized", Response::HTTP_UNAUTHORIZED);
             }

         }else{
             session_destroy();
             return new Response("Unauthorized", Response::HTTP_UNAUTHORIZED);
         }
        session_destroy();



        // $this->logger->info('AuthenticatedSuccessfully with uid : '.$_SESSION['phpCAS']['attributes']['uid']);
        return new JsonResponse($data, Response::HTTP_ACCEPTED);

    }

    public function getName(){

        $this->denyAccessUnlessGranted('IS_AUTHENTICATED_FULLY');

        // returns your User object, or null if the user is not authenticated
        // use inline documentation to tell your editor your exact User class
        /** @var \App\Entity\User $user */
        $user = $this->getUser();
        $data = array(
            "id" => $user->getEmail()
        );
        return new JsonResponse($data, Response::HTTP_ACCEPTED);
    }
}