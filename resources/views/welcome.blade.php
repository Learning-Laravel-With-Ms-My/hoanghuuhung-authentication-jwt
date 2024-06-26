<!DOCTYPE html>
<html lang="en">
   <head>
        <title>Login form</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.0/css/bootstrap.min.css">
        <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.4.0/jquery.min.js"></script>
        <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.0/js/bootstrap.min.js"></script>
        <link rel="stylesheet" href="{{asset('style.css')}}">
</head>
<body>
    <div class="login">
            <div class="account-login">
               <h1>Account Login</h1>
               <form action="/api/auth/login" class="login-form" method="POST">
                  <div class="form-group">
                     <input type="text" name="email" placeholder="User Name" class="form-control">
                  </div>
                  <div class="form-group">
                     <input type="password" name="password" placeholder="Password"  class="form-control">
                  </div>
                  <div class="remember">
                     {{-- <label class="custom-checkbox">Remember me
                     <input type="checkbox">
                     <span class="checkmark"></span>
                     </label> --}}
                     <a href="#" class="pull-right">Forgot Password?</a>
                  </div>
                  <button class="btn">Login</button>
                  <p>Are you new?<a href="#">Sign Up</a></p>
               </form>
            </div>
        </div>
   </body>
</html>