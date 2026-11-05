<?php

namespace App\Http\Controllers;

use App\Services\Runner;
use Illuminate\Http\Request;

class RunController
{
    public function __construct(private Runner $runner)
    {
    }

    public function run(Request $request)
    {
        $this->runner->run($request->input('cmd'));
        return 'ok';
    }
}
