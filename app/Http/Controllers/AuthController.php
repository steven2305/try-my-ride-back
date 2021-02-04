<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name'      => 'required',
            'email'     => 'required|email',
            'password'  => 'required'
        ]);

        if ($validator->fails())
        {
            return response()->json([
                'message' => 'Bad Request'
            ],400);
        }
        $user = new User();
        $user->name = $request->name;
        $user->email = $request->email;
        $user->password = bcrypt($request->password);
        $user->save();
        $token = $user->createToken('my-app-token')->plainTextToken;

        return response()->json([
            'user'      =>  $user,
            'token'      =>  $token,
            'message'   =>  'User created successfully!'
        ], 201);

    }

    public function login(Request $request)
    {
        $user = User::where('email',$request->email)->first();
        if (!$user || !Hash::check($request->password, $user->password))
        {
            return response()->json([
                'message' => 'These credentials do not match our records'
            ], 404);
        }
        $token = $user->createToken('my-app-token')->plainTextToken;

        $response = [
            'user'  => $user,
            'token' => $token
        ];

        return response()->json($response, 201);
    }

    public function logout(Request $request)
    {
        $request->user()->currentAccessToken()->delete();

        return response()->json([
            'message' => 'Token deleted successfully!'
        ],201);
    }

    public function getUsers(Request $request)
    {
        $user = User::get();

        if (!$user)
        {
            return response()->json([
                'message' => 'not found'
            ],404);
        }

        return response()->json([
            'user'      =>  $user,
            'message'   =>  'User found successfully!'
        ], 201);
    }

    public function getUsersById($id)
    {
        $user = User::find($id);

        if (!$user)
        {
            return response()->json([
                'message' => 'not found'
            ],404);
        }

        return response()->json([
            'user'      =>  $user,
            'message'   =>  'User found successfully!'
        ], 201);
    }
    public function editUsersById(Request $request, $id)
    {
        $validator = Validator::make($request->all(), [
            'name'      => 'required',
            'email'     => 'required|email',
            'password'  => 'required'
        ]);

        if ($validator->fails())
        {
            return response()->json([
                'message' => 'Bad Request'
            ],400);
        }
        $user = User::find($id);
        $user->name = $request->name;
        $user->email = $request->email;
        $user->save();

        return response()->json([
            'user'      =>  $user,
            'message'   =>  'User created successfully!'
        ], 201);

    }
}
