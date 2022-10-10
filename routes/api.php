<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Controller;
use App\Http\Controllers\AuthController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy bprotected function unauthenticated(uilding your API!
|
*/
//Public Routes
Route::post('/varify/phone-number', [AuthController::class,'varifyPhoneNumber']);
Route::post('/varify/otp', [AuthController::class,'varifyOtp']);
Route::post('/login', [AuthController::class,'login']);


//Protected Routes
Route::middleware('auth:sanctum')->group(function () {
    Route::post('/register', [AuthController::class,'register']);
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::get('/protected_route', function(){
        return 'protected route';
    });

});

