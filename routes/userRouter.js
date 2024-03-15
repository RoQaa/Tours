const express=require('express');
const router = express.Router();
const authController=require('../controllers/authController')


router.post('/signUp', authController.SignUp);
router.post('/login', authController.login);
router.post('/forgotPassword',authController.forgotPassword)
router.post('/verifyEmailOtp',authController.verifyEmailOtp)
// Protect all routes after this middleware
router.use(authController.protect)
router.patch('/resetPassword',authController.resetPassword)
router.post('/logout',authController.logOut)
router.post('/verifyOtp',authController.verifyEmailOtp)





// Restrict all routes after this middleware
router.use(authController.restrictTo('admin'));
//Admin Routes



module.exports=router;

