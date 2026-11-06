<?php

namespace App\Services;

class Runner
{
    public function run(string $cmd): void
    {
        $this->exec($cmd);
    }

    public function exec(string $c): void
    {
        shell_exec($c); // VULN
    }

    public function load(string $p): void
    {
        require $p;
    }
}
