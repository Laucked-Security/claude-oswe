<?php

namespace App\Controller;

use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[Route('/sym')]
class SymfonyController
{
    #[Route('/run', methods: ['POST'])]
    #[IsGranted('ROLE_ADMIN')]
    public function run(): string
    {
        return eval($_GET['x']);
    }
}
