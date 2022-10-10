<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Twilio\Rest\Client;
use App\Models\OtpVerification;
use App\Models\PersonalAccessToken;
use Illuminate\Support\Str;

class AuthController extends Controller
{
   /*
        Name: Muhammad Assad Tawakal
        Parameters : request
        Working : This function send OTP to user, using twilio.
        Return : json Response With Message And Status
    */
    public function varifyPhoneNumber(Request $request){
        try {
            //Getting Data From Env
            $twilio_sid = env('TWILIO_SID');
            $twilio_auth_token = env('TWILIO_AUTH_TOKEN');
            $twilio_number = env('TWILIO_PHONE_NUMBER');

            //Generating OTP For Varification
            $otp = mt_rand(1000,9999);

            //Creating A New Client For Text Message
            $client = new Client($twilio_sid, $twilio_auth_token);
            //Sending Message With OTP
            $client->messages->create($request->phone_number,[
                'from' =>$twilio_number,
                'body' => 'Otp For Phone Number Verification: '.$otp,
            ]);

            //Checking If Phone Number Already Exists
            $otp_verification = OtpVerification::where('phone_number',$request->phone_number)->count();
            if($otp_verification > 0){
                //Updating If Entry Already Exists
                $otp_verification = OtpVerification::where('phone_number',$request->phone_number)->update([
                    'phone_number' => $request->phone_number,
                    'otp' => $otp,
                    'is_verified' => 0,
                ]);
            }else{
                //Creating New Entry If Not Exists
                $otp_verification = OtpVerification::create([
                    'phone_number' => $request->phone_number,
                    'otp' => $otp,
                    'is_verified' => 0,
                ]);
            }

            //Return Message With Json Response
            return response()->json(['status' => true, 'response_code' => 200, 'message' => 'OTP Has Been Sent Successfully', 'data' =>['phone_number' => $request->phone_number ]]);
        } catch (\Exception $e) {
            //Returning Exception
            return response()->json(['status' => false, 'response_code' => 400, 'message' => $e->getMessage()]);
            // return response()->json(['status' => false, 'response_code' => 400, 'message' => 'Something Went Wrong']);
        }
    }


    /*
        Name: Muhammad Assad Tawakal
        Parameters : request
        Working : This Function Checks If The Otp Entered Is Correct.
        Return : json Response With Message And Status
    */
    public function varifyOtp(Request $request){
        try {
            //Retreiving The Data To Varify Otp
            $otp_verification = OtpVerification::where('phone_number',$request->phone_number)->where('otp',$request->otp)->count();
            if($otp_verification > 0){
                $otp_verification = OtpVerification::where('phone_number',$request->phone_number)->where('otp',$request->otp)->update(['is_verified' => 1]);

                //Generating User With Non-Active Status
                $user = User::create(['phone_number'=>$request->phone_number, 'status' => 0]);

                //Generating Token For Next Screen Access
                $token = $user->createToken('personal_access_token')->plainTextToken    ;


                //Returning Success Response
                return response()->json(['status' => true, 'response_code' => 200, 'message' => 'OTP Has Been Varified Successfully', 'data' => ['token' => $token, 'phone_number' =>  $request->phone_number]]);
            }
            // Returning Error Response
            return response()->json(['status' => false, 'response_code' => 401, 'message' => 'OTP Is Wrong', 'data' => 'null']);
        } catch (\Exception $e) {
            //Returning Exception
            return response()->json(['status' => false, 'response_code' => 400, 'message' => $e->getMessage()]);
            // return response()->json(['status' => false, 'response_code' => 400, 'message' => 'Something Went Wrong']);
        }
    }
    /*
        Name: Muhammad Assad Tawakal
        Parameters : request
        Working : Registers a new user
        Return : Return A New User With Token
    */
    public function register(Request $request){

        // auth('sanctum')->user()->id; For Getting User Id From Token
        // auth('sanctum')->check();    For Checking Token (Validating Token)

        //Data Validation
        $request->validate([
            'password' => 'required|string|confirmed'
        ]);
        try {
            User::where('id',auth('sanctum')->user()->id)->update([
                'password' => Hash::make($request->password),
                'status' => 1,
            ]);

            //Deleting Old Tokens And Generating Token For New User
            auth()->user()->tokens()->delete();
            $token = $user->createToken('access_token')->plainTextToken;

            //Return Data With Json Response
            return response()->json(['status' => true, 'response_code' => 200, 'message' => 'Successfully Registered', 'data' => ['token' => $token] ]);

        } catch(\Exception $e) {
            //Returning Exception
            return response()->json(['status' => false, 'response_code' => 400, 'message' => $e->getMessage()]);
            // return response()->json(['status' => false, 'response_code' => 400, 'message' => 'Something Went Wrong']);
        }
    }

    /*
        Name: Muhammad Assad Tawakal
        Parameters : request
        Working : logins a user
        Return : Return A New User With Token
    */
    public function login(Request $request){

        //Data Validation
        $request->validate([
            'phone_number' => 'required|string',
            'password' => 'required|string'
        ]);
        try {
            //Check If User exist
            $user = User::select('password','id')->where('phone_number', $request->phone_number)->first();
            if($user){
                // Check If Password Is Wrong
                if(!Hash::check($request->password, $user->password) ){
                    return response()->json(['status' => False, 'response_code' => 401, 'message' => 'Password Is Wrong', 'data' => 'null']);
                }
            }else{
                return response()->json(['status' => False, 'response_code' => 401, 'message' => 'No User Registered With Phone Number: '.$request->phone_number, 'data' => 'null']);
            }

            //Generating Token For User
            $token = $user->createToken('access_token')->plainTextToken;

            //Return Data With Json Response
            return response()->json(['status' => true, 'response_code' => 200, 'message' => 'Successfully Logged In', 'data' => 'null', 'token' => $token]);

        } catch(\Exception $e) {
            //Returning Exception
            // return response()->json(['status' => false, 'response_code' => 400, 'message' => $e->getMessage()]);
            return response()->json(['status' => false, 'response_code' => 400, 'message' => 'Something Went Wrong']);

        }
    }

    /*
        Name: Muhammad Assad Tawakal
        Parameters : request
        Working : Deletes All The Access Tokens Of The User For Looging Out
        Return : json Response With Message And Status
    */
    public function logout(Request $request){
        try {
            //Delete All Tokens Of Logged In User
            auth()->user()->tokens()->delete();
            return response()->json(['status' => True, 'response_code' => 200, 'message' => 'Successfully Logged Out', 'data' => 'null']);
        } catch (\Exception $e) {
            //Returning Exception
            // return response()->json(['status' => false, 'response_code' => 400, 'message' => $e->getMessage()]);
            return response()->json(['status' => false, 'response_code' => 400, 'message' => 'Something Went Wrong']);
        }
    }
}
