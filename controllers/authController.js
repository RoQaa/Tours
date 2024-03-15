const { promisify } = require('util');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const validator = require('validator');
const User = require('../models/userModel')
const { catchAsync } = require('../utils/catchAsync');
const AppError = require('../utils/AppError');

const signToken = (id) => {
  const token = jwt.sign({ id: id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  }); //sign(payload,secret,options=expires)
  return token;
};

const createSendToken = (user, statusCode, message, res) => {
  const token = signToken(user.id);

  const cookieOption = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ), //=> 90 days
    httpOnly: true, // be in http only
  };

  if (process.env.NODE_ENV === 'production') cookieOption.secure = true; // client cann't access it

  res.cookie('jwt', token, cookieOption); // save jwt in cookie

  //Remove password from output
  user.password = undefined;
  //user.token=token;

  res.status(statusCode).json({
    status: true,
    message,

    data: {
      name: user.name,
      // email:user.email,
      // photo: user.photo,
      //isPaid: user.isPaid,
      role: user.role,
    },
    token,
  });
};




exports.SignUp = catchAsync(async (req, res, next) => {

  const newUser = await User.create(req.body);

  if (!newUser) {
    return next(new AppError(`SomeThing Error cannot sign up`, 404));
  }



  createSendToken(newUser, 201, "sign up successfully", res);



});

exports.login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;

  //1) check email && password exist,
  if (!email || !password) {
    return next(new AppError('please provide email & password', 400));
  }
  const validEmail = validator.isEmail(email);
  if (!validEmail) {

    return next(new AppError(`Please provide a correct email`, 400));
  }
  //2)check user exists && password is correct

  const user = await User.findOne({ email: email }).select('+password'); // hyzaod el password el m5fee aslan

  //const correct=await user.correctPassword(password,user.password);

  if (
    !user ||
    !(
      (await user.correctPassword(
        password,
        user.password
      )) /** 34an hyrun fe el correct 7ta loo ml2hoo4*/
    )
  ) {

    return next(new AppError('Incorrect email or password', 404));
  }
  //3) if everything ok send token back to the client

  createSendToken(user, 200, 'log in successfully', res);

});

exports.forgotPassword = catchAsync(async (req, res, next) => {
  const user = await User.findOne({ email: req.body.email }).select(
    'email'
  );
  if (!user) {

    return next(new AppError('There is no user with email address.', 404));
  }


  const OTP = await user.generateOtp();
  await user.save({ validateBeforeSave: false });
  try {
    await sendEmail({
      email: user.email,
      subject: 'Your Password (valid for 10 min)',
      name: user.name,
      otp: OTP,
    });

    res.status(200).json({
      status: true,
      message: 'Code sent to email!',
    });

  } catch (err) {
    user.passwordOtp = undefined;
    user.passwordOtpExpires = undefined;
    await user.save({ validateBeforeSave: false });

    return next(new AppError(err), 500);
  }
});
exports.verifyEmailOtp = catchAsync(async (req, res, next) => {
  //just email otp
  const cryptoOtp = crypto
    .createHash('sha256')
    .update(req.body.otp)
    .digest('hex');

  const user = await User.findOne({
    passwordOtp: cryptoOtp,
    passwordOtpExpires: { $gt: Date.now() },
  });

  if (!user) {


    return next(new AppError('OTP is invalid or has expired', 400));
  }
  const token = signToken(user.id);

  res.status(200).json({
    status: true,
    message: 'OTP is valid You can now reset password',
    token,
  });

});



exports.resetPassword = catchAsync(async (req, res, next) => {
  // protect handler
  const user = req.user;
  if (!user) {
    return next(new AppError('Token is invalid or has expired', 400));
  }
  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordOtp = undefined;
  user.passwordOtpExpires = undefined;

  await user.save({ validateBeforeSave: false });

  res.clearCookie('jwt');
  res.status(200).json({
    status: true,
    message: 'password reset success you can now  try agin to log in',
  });


});



exports.logOut = catchAsync(async (req, res, next) => {
  res.clearCookie('jwt');
  req.headers.authorization = undefined;
 
    res.status(200).json({
      status: true,
      message: 'You log out Successfully',
       token:""
    });
  });








//MIDDLEWARE CHECK IF USER STILL LOGGED IN
exports.protect = catchAsync(async (req, res, next) => {
  //1)Getting token and check it's there
  let token;
  if (req.headers.authorization === 'Bearer null') {
    if (req.headers.lang === 'AR') {
      return next(new AppError('برجاء تسجيل الدخول اولا', 401));
    }
    return next(new AppError("Your're not logged in please log in", 401));
  }
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith('Bearer')
  ) {
    token = req.headers.authorization.split(' ')[1];
  }

  if (!token) {

    return next(new AppError("Your're not logged in please log in", 404)); //401 => is not 'authorized
  }
  //2)Verification token
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  //3)check if user still exist in the route
  const currentUser = await User.findById(decoded.id);
  if (!currentUser) {

    return next(
      new AppError(`Your Session expires please Login again`, 401)
    );
  }
  //4)check if user changed password after the token has issued
  if (currentUser.changesPasswordAfter(decoded.iat)) {
    //iat=> issued at

    return next(
      new AppError(
        'user has changed password recently please log in again',
        401
      )
    );
  }

  //GRANT ACCESS TO PROTECTED ROUTE
  req.user = currentUser; // pyasse el data le middleware tany
  next();
});


exports.restrictTo = (...roles) => {
  //function feha paramter we 3awz a7oot feha middleware
  //roles ['admin','lead-guide']
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(
        new AppError('You do not have permission to preform this action', 403)
      );
    }
    next();
  };
};

