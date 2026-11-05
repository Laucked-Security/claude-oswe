<?php

use App\Http\Controllers\RunController;
use Illuminate\Support\Facades\Route;

Route::middleware(['auth'])->group(function () {
    Route::post('/run', [RunController::class, 'run']);
});

Route::get('/health', fn () => 'ok');

require __DIR__ . '/extra.php';

function helper(callable $cb)
{
    $cb();
}
