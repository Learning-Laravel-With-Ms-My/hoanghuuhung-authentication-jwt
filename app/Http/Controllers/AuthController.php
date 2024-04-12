<?php

namespace App\Http\Controllers;

use App\Http\Controllers\Controller;
use Exception;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login']]);
    }
    public function login()
    {
        $credentials = request(['email', 'password']);

        if (!$token = auth()->attempt($credentials)) {
            return response()->json(['error' => 'Không được phép truy cập'], 401);
        }

        $refreshToken = $this->createRefreshToken();
        return $this->respondWithToken($token, $refreshToken);
    }

    public function me()
    {
        echo "sj";
        try {
            return response()->json(auth('api')->user());
        } catch (JWTException $exception) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
    }
    public function logout()
    {
        auth('api')->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }
    public function refresh()
    {
        $refreshToken = request()->refresh_token;
        try {
            $decoded = JWTAuth::getJWTProvider()->decode($refreshToken);
            $user = User::find($decoded['user_id']);
            if (!$user) {
                return response()->json(['error' => 'User not found'], 404);
            }
            JWTAuth::invalidate();
            $token = auth('api')->login($user);
            $refreshToken =  $this->createRefreshToken();
            // xử lý cấp lại token mới
            return $this->respondWithToken($token, $refreshToken);
        } catch (JWTException $exception) {
            return response()->json(['error' => 'Refresh Token Invalid'], 500);
        }
    }

    private function respondWithToken($token, $refreshToken)
    {
        return response()->json([
            'access_token' => $token,
            'refresh_token' => $refreshToken,
            'token_type' => 'bearer',
            'expires_in' => Auth::factory()->getTTL() * 60
        ]);
    }
    private function createRefreshToken()
    {
        $data = [
            'user_id' => auth('api')->user()->id,
            'random' => rand() . time(),
            'exp' => time() + config('jwt.refresh_ttl')
        ];

        $refreshToken = JWTAuth::getJWTProvider()->encode($data);
        return $refreshToken;
    }
    // public function createUser(Request $request){
    //     try{
    //         $validateUser = Validator::make($request->all(),[
    //             'name' => 'required',
    //             'email' => 'required|email|unique:users,email',
    //             'password' => 'required'
    //         ]);
    //         if($validateUser->fails()){
    //             return response()->json([
    //                 'status' => false,
    //                 'message' => 'validation error',
    //                 'error' =>$validateUser->errors()
    //             ],401);
    //         }
    //         $user  = User::create([
    //             'name' =>$request->name,
    //             'email' =>$request->email,
    //             'password' =>Hash::make($request->password),
    //         ]);
    //         return response()->json([
    //             'status' => true,
    //             'message' => 'User created successfully',
    //             'error' => $user->createToken("API TOKEN")->plainTextToken
    //         ],200);
    //     }catch(\Throwable $th){
    //         return response()->json([
    //             'status' => false,
    //             'message' => $th->getMessage()
    //         ],500);
    //     }

    // }
}